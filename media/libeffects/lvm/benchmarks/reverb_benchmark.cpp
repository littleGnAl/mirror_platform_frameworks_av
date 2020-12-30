/*
 * Copyright 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <array>
#include <climits>
#include <cstdlib>
#include <random>
#include <vector>
#include <log/log.h>
#include <benchmark/benchmark.h>
#include <hardware/audio_effect.h>
#include <system/audio.h>
#include "EffectReverb.h"

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;
constexpr effect_uuid_t kEffectUuids[] = {
        {0x172cdf00,
         0xa3bc,
         0x11df,
         0xa72f,
         {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // preset-insert mode
        {0xf29a1400,
         0xa3bb,
         0x11df,
         0x8ddc,
         {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // preset-aux mode
};

constexpr size_t kNumEffectUuids = std::size(kEffectUuids);

constexpr size_t kFrameCount = 2048;

constexpr audio_channel_mask_t kChMasks[] = {
        AUDIO_CHANNEL_OUT_MONO,    AUDIO_CHANNEL_OUT_STEREO,  AUDIO_CHANNEL_OUT_2POINT1,
        AUDIO_CHANNEL_OUT_QUAD,    AUDIO_CHANNEL_OUT_PENTA,   AUDIO_CHANNEL_OUT_5POINT1,
        AUDIO_CHANNEL_OUT_6POINT1, AUDIO_CHANNEL_OUT_7POINT1,
};

constexpr size_t kNumChMasks = std::size(kChMasks);
constexpr int kSampleRate = 44100;
// TODO(b/131240940) Remove once effects are updated to produce mono output
constexpr size_t kMinOutputChannelCount = 2;

int reverbSetConfigParam(uint32_t paramType, uint32_t paramValue, effect_handle_t effectHandle) {
    int reply = 0;
    uint32_t replySize = sizeof(reply);
    uint32_t paramData[2] = {paramType, paramValue};
    effect_param_t* effectParam = (effect_param_t*)malloc(sizeof(*effectParam) + sizeof(paramData));
    memcpy(&effectParam->data[0], &paramData[0], sizeof(paramData));
    effectParam->psize = sizeof(paramData[0]);
    effectParam->vsize = sizeof(paramData[1]);
    int status = (*effectHandle)
                         ->command(effectHandle, EFFECT_CMD_SET_PARAM,
                                   sizeof(effect_param_t) + sizeof(paramData), effectParam,
                                   &replySize, &reply);
    free(effectParam);
    if (status != 0) {
        ALOGE("Reverb set config returned an error = %d\n", status);
        return status;
    }
    return reply;
}

/*******************************************************************
 * A test result running on Pixel 3 with for comparison.
 * REVERB_PARAM_PRESET is set to 1 for the following data.
 * The first parameter indicates the number of channels.
 * The second parameter indicates the effect.
 * 0: preset-insert mode, 1: preset-aux mode
 * --------------------------------------------------------
 * Benchmark              Time             CPU   Iterations
 * --------------------------------------------------------
 * BM_REVERB/2/0     609299 ns       607661 ns         1124
 * BM_REVERB/2/1     594124 ns       592540 ns         1154
 * BM_REVERB/3/0     619022 ns       617355 ns         1087
 * BM_REVERB/3/1     594875 ns       593318 ns         1151
 * BM_REVERB/4/0     623906 ns       622232 ns         1099
 * BM_REVERB/4/1     596077 ns       594512 ns         1148
 * BM_REVERB/5/0     627297 ns       625593 ns         1093
 * BM_REVERB/5/1     594548 ns       593018 ns         1147
 * BM_REVERB/6/0     627661 ns       626016 ns         1094
 * BM_REVERB/6/1     597513 ns       595942 ns         1145
 * BM_REVERB/7/0     633000 ns       631283 ns         1084
 * BM_REVERB/7/1     598670 ns       597076 ns         1142
 * BM_REVERB/8/0     636653 ns       634935 ns         1078
 * BM_REVERB/8/1     599401 ns       597795 ns         1141
 *******************************************************************/

static void BM_REVERB(benchmark::State& state) {
    const size_t chMask = kChMasks[state.range(0) - 1];
    const effect_uuid_t uuid = kEffectUuids[state.range(1)];
    const size_t channelCount = audio_channel_count_from_out_mask(chMask);

    // Initialize input buffer with deterministic pseudo-random values
    std::minstd_rand gen(chMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    std::vector<float> input(kFrameCount * channelCount);
    for (auto& in : input) {
        in = dis(gen);
    }

    effect_handle_t effectHandle = nullptr;
    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(&uuid, 1, 1, &effectHandle);
        status != 0) {
        ALOGE("create_effect returned an error = %d\n", status);
        return;
    }

    effect_config_t config{};
    config.inputCfg.samplingRate = config.outputCfg.samplingRate = kSampleRate;
    config.inputCfg.channels = config.outputCfg.channels = chMask;
    config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_FLOAT;

    int reply = 0;
    uint32_t replySize = sizeof(reply);
    if (int status = (*effectHandle)
                             ->command(effectHandle, EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t),
                                       &config, &replySize, &reply);
        status != 0) {
        ALOGE("command returned an error = %d\n", status);
        return;
    }

    if (int status =
                (*effectHandle)
                        ->command(effectHandle, EFFECT_CMD_ENABLE, 0, nullptr, &replySize, &reply);
        status != 0) {
        ALOGE("Command enable call returned error %d\n", reply);
        return;
    }

    if (int status = reverbSetConfigParam(REVERB_PARAM_PRESET, (uint32_t)1, effectHandle);
        status != 0) {
        ALOGE("Invalid reverb preset. Error %d\n", status);
        return;
    }

    // Run the test
    for (auto _ : state) {
        std::vector<float> output(kFrameCount * std::max(channelCount, kMinOutputChannelCount));

        benchmark::DoNotOptimize(input.data());
        benchmark::DoNotOptimize(output.data());

        audio_buffer_t inBuffer = {.frameCount = kFrameCount, .f32 = input.data()};
        audio_buffer_t outBuffer = {.frameCount = kFrameCount, .f32 = output.data()};
        (*effectHandle)->process(effectHandle, &inBuffer, &outBuffer);

        benchmark::ClobberMemory();
    }

    state.SetComplexityN(state.range(0));

    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effectHandle); status != 0) {
        ALOGE("release_effect returned an error = %d\n", status);
        return;
    }
}

static void REVERBArgs(benchmark::internal::Benchmark* b) {
    // TODO(b/131240940) Test single channel once effects are updated to process mono data
    for (int i = 2; i <= kNumChMasks; i++) {
        for (int j = 0; j < kNumEffectUuids; ++j) {
            b->Args({i, j});
        }
    }
}

BENCHMARK(BM_REVERB)->Apply(REVERBArgs);

BENCHMARK_MAIN();
