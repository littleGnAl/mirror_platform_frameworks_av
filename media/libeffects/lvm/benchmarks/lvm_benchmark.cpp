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

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;
const effect_uuid_t kEffectUuids[] = {
        // NXP SW BassBoost
        {0x8631f300, 0x72e2, 0x11df, 0xb57e, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Virtualizer
        {0x1d4033c0, 0x8557, 0x11df, 0x9f2d, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Equalizer
        {0xce772f20, 0x847d, 0x11df, 0xbb17, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Volume
        {0x119341a0, 0x8469, 0x11df, 0x81f9, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
};

constexpr int kNumEffectUuids = std::size(kEffectUuids);

static constexpr size_t kFrameCount = 2048;

constexpr audio_channel_mask_t kChMasks[] = {
        AUDIO_CHANNEL_OUT_MONO,    AUDIO_CHANNEL_OUT_STEREO,  AUDIO_CHANNEL_OUT_2POINT1,
        AUDIO_CHANNEL_OUT_QUAD,    AUDIO_CHANNEL_OUT_PENTA,   AUDIO_CHANNEL_OUT_5POINT1,
        AUDIO_CHANNEL_OUT_6POINT1, AUDIO_CHANNEL_OUT_7POINT1,
};

constexpr int kNumChMasks = std::size(kChMasks);
constexpr int kSampleRate = 44100;
constexpr size_t kMinOutputChannelCount = 2;
/*******************************************************************
 * A test result running on Pixel 3 for comparison.
 * The first parameter indicates the number of channels.
 * The second parameter indicates the effect.
 * 0: Bass Boost, 1: Virtualizer, 2: Equalizer, 3: Volume
 * -----------------------------------------------------
 * Benchmark           Time             CPU   Iterations
 * -----------------------------------------------------
 * BM_LVM/2/0      26687 ns        26601 ns        26296
 * BM_LVM/2/1      26695 ns        26609 ns        26316
 * BM_LVM/2/2      26673 ns        26587 ns        26329
 * BM_LVM/2/3      26673 ns        26588 ns        26323
 * BM_LVM/3/0      26618 ns        26538 ns        26438
 * BM_LVM/3/1      27007 ns        26927 ns        26444
 * BM_LVM/3/2      27002 ns        26921 ns        26159
 * BM_LVM/3/3      26604 ns        26525 ns        26427
 * BM_LVM/4/0      37188 ns        37086 ns        18916
 * BM_LVM/4/1      37184 ns        37083 ns        18919
 * BM_LVM/4/2      37183 ns        37083 ns        18919
 * BM_LVM/4/3      37183 ns        37083 ns        18919
 * BM_LVM/5/0      46603 ns        46477 ns        15081
 * BM_LVM/5/1      46602 ns        46475 ns        15079
 * BM_LVM/5/2      46603 ns        46474 ns        14889
 * BM_LVM/5/3      46598 ns        46471 ns        14885
 * BM_LVM/6/0      55371 ns        55220 ns        12807
 * BM_LVM/6/1      55017 ns        54866 ns        12751
 * BM_LVM/6/2      54706 ns        54555 ns        12809
 * BM_LVM/6/3      54704 ns        54553 ns        12750
 * BM_LVM/7/0      64122 ns        63942 ns        11089
 * BM_LVM/7/1      63431 ns        63254 ns        11093
 * BM_LVM/7/2      63622 ns        63447 ns        11025
 * BM_LVM/7/3      63418 ns        63241 ns        11086
 * BM_LVM/8/0      73343 ns        73137 ns         9778
 * BM_LVM/8/1      73475 ns        73268 ns         9781
 * BM_LVM/8/2      72249 ns        72047 ns         9778
 * BM_LVM/8/3      73395 ns        73190 ns         9642
 *******************************************************************/

static void BM_LVM(benchmark::State& state) {
    const size_t chMask = kChMasks[state.range(0) - 1];
    const effect_uuid_t uuid = kEffectUuids[state.range(1)];
    const size_t channelCount = audio_channel_count_from_out_mask(chMask);

    // Initialize input buffer with deterministic pseudo-random values
    std::minstd_rand gen(chMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    std::vector<float> input(kFrameCount * channelCount);
    for (size_t i = 0; i < kFrameCount * channelCount; ++i) {
        input[i] = dis(gen);
    }

    effect_handle_t effectHandle = nullptr;
    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(&uuid, 1, 1, &effectHandle);
        status != 0) {
        ALOGE("create_effect returned an error = %d\n", status);
        return;
    }

    effect_config_t config;
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

    // Run the test
    for (auto _ : state) {
        std::vector<float> output(kFrameCount * std::max(channelCount, kMinOutputChannelCount));

        benchmark::DoNotOptimize(input.data());
        benchmark::DoNotOptimize(output.data());

        audio_buffer_t inBuffer;
        audio_buffer_t outBuffer;
        inBuffer.frameCount = kFrameCount;
        inBuffer.f32 = input.data();
        outBuffer.frameCount = kFrameCount;
        outBuffer.f32 = output.data();
        (*effectHandle)->process(effectHandle, &inBuffer, &outBuffer);

        benchmark::ClobberMemory();
    }

    state.SetComplexityN(state.range(0));

    if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effectHandle); status != 0) {
        ALOGE("release_effect returned an error = %d\n", status);
        return;
    }
}

static void LVMArgs(benchmark::internal::Benchmark* b) {
    for (int i = 2; i <= kNumChMasks; i++)         // channel count
        for (int j = 0; j < kNumEffectUuids; ++j)  // Effects
            b->Args({i, j});
}

BENCHMARK(BM_LVM)->Apply(LVMArgs);

BENCHMARK_MAIN();