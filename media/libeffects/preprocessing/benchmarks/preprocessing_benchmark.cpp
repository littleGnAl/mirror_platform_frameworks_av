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

/*******************************************************************
 * A test result running on Pixel 3 for comparison.
 * The first parameter indicates the channel mask index.
 * The second parameter indicates the effect index.
 * 0: Automatic Gain Control,
 * 1: Acoustic Echo Canceler,
 * 2: Noise Suppressor,
 * 3: Automatic Gain Control 2,
 * 4: Acoustic Echo Canceler Mobile Mode
 * ---------------------------------------------------------------
 * Benchmark                     Time             CPU   Iterations
 * ---------------------------------------------------------------
 * BM_PREPROCESSING/1/0      58742 ns        58570 ns        11947
 * BM_PREPROCESSING/1/1     478939 ns       477263 ns         1471
 * BM_PREPROCESSING/1/2      19964 ns        19897 ns        35090
 * BM_PREPROCESSING/1/3       4748 ns         4733 ns       147914
 * BM_PREPROCESSING/1/4      71738 ns        71517 ns         9842
 * BM_PREPROCESSING/2/0     115314 ns       114950 ns         6088
 * BM_PREPROCESSING/2/1     480979 ns       479274 ns         1464
 * BM_PREPROCESSING/2/2      38129 ns        38000 ns        18390
 * BM_PREPROCESSING/2/3       6251 ns         6231 ns       112410
 * BM_PREPROCESSING/2/4     130570 ns       130158 ns         5416
 * BM_PREPROCESSING/3/0     229191 ns       228457 ns         3065
 * BM_PREPROCESSING/3/1     482599 ns       481022 ns         1459
 * BM_PREPROCESSING/3/2      75037 ns        74834 ns         9165
 * BM_PREPROCESSING/3/3       9697 ns         9669 ns        72406
 * BM_PREPROCESSING/3/4     246486 ns       245704 ns         2862
 * BM_PREPROCESSING/4/0     286358 ns       285417 ns         2454
 * BM_PREPROCESSING/4/1     486169 ns       484454 ns         1448
 * BM_PREPROCESSING/4/2      93277 ns        93006 ns         7372
 * BM_PREPROCESSING/4/3      11449 ns        11413 ns        61297
 * BM_PREPROCESSING/4/4     304759 ns       303852 ns         2311
 * BM_PREPROCESSING/5/0     342766 ns       341712 ns         2048
 * BM_PREPROCESSING/5/1     487667 ns       485934 ns         1444
 * BM_PREPROCESSING/5/2     112063 ns       111740 ns         6114
 * BM_PREPROCESSING/5/3      13172 ns        13131 ns        53306
 * BM_PREPROCESSING/5/4     362949 ns       361785 ns         1941
 *******************************************************************/

#include <array>
#include <climits>
#include <cstdlib>
#include <random>
#include <vector>
#include <audio_effects/effect_aec.h>
#include <audio_effects/effect_agc.h>
#ifndef WEBRTC_LEGACY
#include <audio_effects/effect_agc2.h>
#endif
#include <audio_effects/effect_ns.h>
#include <benchmark/benchmark.h>
#include <hardware/audio_effect.h>
#include <log/log.h>
#include <sys/stat.h>
#include <system/audio.h>

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;

constexpr int kSampleRate = 16000;
constexpr float kTenMilliSecVal = 0.01;
constexpr unsigned int kStreamDelayMs = 0;
constexpr effect_uuid_t kEffectUuids[] = {
    // agc uuid
    {0xaa8130e0, 0x66fc, 0x11e0, 0xbad0, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
    // aec uuid
    {0xbb392ec0, 0x8d4d, 0x11e0, 0xa896, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
    // ns  uuid
    {0xc06c8400, 0x8e06, 0x11e0, 0x9cb6, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
#ifndef WEBRTC_LEGACY
    // agc2 uuid
    {0x89f38e65, 0xd4d2, 0x4d64, 0xad0e, {0x2b, 0x3e, 0x79, 0x9e, 0xa8, 0x86}},
    // aecm uuid (same as aec)
    {0xbb392ec0, 0x8d4d, 0x11e0, 0xa896, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
#endif
};
constexpr size_t kNumEffectUuids = std::size(kEffectUuids);
constexpr audio_channel_mask_t kChMasks[] = {
    AUDIO_CHANNEL_IN_MONO,
    AUDIO_CHANNEL_IN_STEREO,
    AUDIO_CHANNEL_IN_2POINT0POINT2,
    AUDIO_CHANNEL_IN_2POINT1POINT2,
    AUDIO_CHANNEL_IN_6,
};
constexpr size_t kNumChMasks = std::size(kChMasks);

// types of pre processing modules
enum PreProcId {
  PREPROC_AGC, // Automatic Gain Control
  PREPROC_AEC, // Acoustic Echo Canceler
  PREPROC_NS,  // Noise Suppressor
#ifndef WEBRTC_LEGACY
  PREPROC_AGC2, // Automatic Gain Control 2
  PREPROC_AECM, // Acoustic Echo Canceler Mobile
#endif
  PREPROC_NUM_EFFECTS
};

int preProcCreateEffect(effect_handle_t *pEffectHandle, uint32_t effectType,
                        effect_config_t *pConfig, int sessionId, int ioId) {
  if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(
          &kEffectUuids[effectType], sessionId, ioId, pEffectHandle);
      status != 0) {
    ALOGE("Audio Preprocessing create returned an error = %d\n", status);
    return EXIT_FAILURE;
  }
  int reply = 0;
  uint32_t replySize = sizeof(reply);
  if (effectType == PREPROC_AEC) {
    if (int status =
            (**pEffectHandle)
                ->command(*pEffectHandle, EFFECT_CMD_SET_CONFIG_REVERSE,
                          sizeof(effect_config_t), pConfig, &replySize, &reply);
        status != 0) {
      ALOGE("Set config reverse command returned an error = %d\n", status);
      return EXIT_FAILURE;
    }
  }
  if (int status =
          (**pEffectHandle)
              ->command(*pEffectHandle, EFFECT_CMD_SET_CONFIG,
                        sizeof(effect_config_t), pConfig, &replySize, &reply);
      status != 0) {
    ALOGE("Set config command returned an error = %d\n", status);
    return EXIT_FAILURE;
  }
  return reply;
}

int preProcSetConfigParam(effect_handle_t effectHandle, uint32_t paramType,
                          uint32_t paramValue) {
  int reply = 0;
  uint32_t replySize = sizeof(reply);
  uint32_t paramData[2] = {paramType, paramValue};
  effect_param_t *effectParam =
      (effect_param_t *)malloc(sizeof(*effectParam) + sizeof(paramData));
  memcpy(&effectParam->data[0], &paramData[0], sizeof(paramData));
  effectParam->psize = sizeof(paramData[0]);
  (*effectHandle)
      ->command(effectHandle, EFFECT_CMD_SET_PARAM, sizeof(effect_param_t),
                effectParam, &replySize, &reply);
  free(effectParam);
  return reply;
}

short preProcGetShortVal(float paramValue) {
  return static_cast<short>(paramValue * std::numeric_limits<short>::max());
}

static void BM_PREPROCESSING(benchmark::State &state) {
  const size_t chMask = kChMasks[state.range(0) - 1];
  const size_t channelCount = audio_channel_count_from_in_mask(chMask);

  PreProcId effectType = (PreProcId)state.range(1);

  int32_t sessionId = 1;
  int32_t ioId = 1;
  effect_handle_t effectHandle = nullptr;
  effect_config_t config{};
  config.inputCfg.samplingRate = config.outputCfg.samplingRate = kSampleRate;
  config.inputCfg.channels = config.outputCfg.channels = chMask;
  config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_16_BIT;

  if (int status = preProcCreateEffect(&effectHandle, state.range(1), &config,
                                       sessionId, ioId);
      status != 0) {
    ALOGE("Create effect call returned error %i", status);
    return;
  }

  int reply = 0;
  uint32_t replySize = sizeof(reply);
  if (int status = (*effectHandle)
                       ->command(effectHandle, EFFECT_CMD_ENABLE, 0, nullptr,
                                 &replySize, &reply);
      status != 0) {
    ALOGE("Command enable call returned error %d\n", reply);
    return;
  }

// Set Config Params of the effects
#ifndef WEBRTC_LEGACY
  if (PREPROC_AEC == effectType || PREPROC_AECM == effectType) {
    uint32_t aecMobileMode = (PREPROC_AECM == effectType) ? 1 : 0;
    if (int status = preProcSetConfigParam(effectHandle, AEC_PARAM_MOBILE_MODE,
                                           aecMobileMode);
        status != 0) {
      ALOGE("Invalid AEC mobile mode value %d\n", status);
      return;
    }
  }
#endif

  // Initialize input buffer with deterministic pseudo-random values
  const int frameLength = (int)(kSampleRate * kTenMilliSecVal);
  std::minstd_rand gen(chMask);
  std::uniform_real_distribution<> dis(-1.0f, 1.0f);
  std::vector<short> in(frameLength * channelCount);
  for (auto &i : in) {
    i = preProcGetShortVal(dis(gen));
  }
  std::vector<short> farIn(frameLength * channelCount);
  for (auto &i : farIn) {
    i = preProcGetShortVal(dis(gen));
  }
  std::vector<short> out(frameLength * channelCount);

  // Run the test
  for (auto _ : state) {
    benchmark::DoNotOptimize(in.data());
    benchmark::DoNotOptimize(out.data());
    benchmark::DoNotOptimize(farIn.data());

    audio_buffer_t inBuffer = {.frameCount = (size_t)frameLength,
                               .s16 = in.data()};
    audio_buffer_t outBuffer = {.frameCount = (size_t)frameLength,
                                .s16 = out.data()};
    audio_buffer_t farInBuffer = {.frameCount = (size_t)frameLength,
                                  .s16 = farIn.data()};

#ifndef WEBRTC_LEGACY
    if (PREPROC_AEC == effectType || PREPROC_AECM == effectType) {
#else
    if (PREPROC_AEC == effectType) {
#endif
      if (int status = preProcSetConfigParam(effectHandle, AEC_PARAM_ECHO_DELAY,
                                             kStreamDelayMs);
          status != 0) {
        ALOGE("preProcSetConfigParam returned Error %d\n", status);
        return;
      }
    }
    if (int status =
            (*effectHandle)->process(effectHandle, &inBuffer, &outBuffer);
        status != 0) {
      ALOGE("\nError: Process i = %d returned with error %d\n",
            (int)state.range(1), status);
      return;
    }
#ifndef WEBRTC_LEGACY
    if (PREPROC_AEC == effectType || PREPROC_AECM == effectType) {
#else
    if (PREPROC_AEC == effectType) {
#endif
      if (int status =
              (*effectHandle)
                  ->process_reverse(effectHandle, &farInBuffer, &outBuffer);
          status != 0) {
        ALOGE("\nError: Process reverse i = %d returned with error %d\n",
              (int)state.range(1), status);
        return;
      }
    }
  }
  benchmark::ClobberMemory();

  state.SetComplexityN(state.range(0));

  if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effectHandle);
      status != 0) {
    ALOGE("release_effect returned an error = %d\n", status);
    return;
  }
}

static void preprocessingArgs(benchmark::internal::Benchmark *b) {
  for (int i = 1; i <= (int)kNumChMasks; i++) {
    for (int j = 0; j < (int)kNumEffectUuids; ++j) {
      b->Args({i, j});
    }
  }
}

BENCHMARK(BM_PREPROCESSING)->Apply(preprocessingArgs);

BENCHMARK_MAIN();
