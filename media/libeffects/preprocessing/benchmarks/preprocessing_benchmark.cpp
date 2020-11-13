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
#include <sys/stat.h>
#include <benchmark/benchmark.h>
#include <hardware/audio_effect.h>
#include <system/audio.h>
#include <audio_effects/effect_aec.h>
#include <audio_effects/effect_agc.h>
#ifndef WEBRTC_LEGACY
#include <audio_effects/effect_agc2.h>
#endif
#include <audio_effects/effect_ns.h>

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;
constexpr effect_uuid_t kEffectUuids[] = {
    // agc uuid
    {0xaa8130e0, 0x66fc, 0x11e0, 0xbad0, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
#ifndef WEBRTC_LEGACY
    // agc2 uuid
    {0x89f38e65, 0xd4d2, 0x4d64, 0xad0e, {0x2b, 0x3e, 0x79, 0x9e, 0xa8, 0x86}},
#endif
    // aec uuid
    {0xbb392ec0, 0x8d4d, 0x11e0, 0xa896, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
    // ns  uuid
    {0xc06c8400, 0x8e06, 0x11e0, 0x9cb6, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
};

constexpr size_t kNumEffectUuids = std::size(kEffectUuids);

constexpr audio_channel_mask_t kChMasks[] = {
    AUDIO_CHANNEL_IN_MONO,
    AUDIO_CHANNEL_IN_STEREO,
    AUDIO_CHANNEL_IN_FRONT_BACK,
    AUDIO_CHANNEL_IN_6,
    AUDIO_CHANNEL_IN_2POINT0POINT2,
    AUDIO_CHANNEL_IN_2POINT1POINT2,
    AUDIO_CHANNEL_IN_3POINT0POINT2,
    AUDIO_CHANNEL_IN_3POINT1POINT2,
    AUDIO_CHANNEL_IN_5POINT1,
    AUDIO_CHANNEL_IN_VOICE_UPLINK_MONO,
    AUDIO_CHANNEL_IN_VOICE_DNLINK_MONO,
    AUDIO_CHANNEL_IN_VOICE_CALL_MONO,
};

constexpr size_t kNumChMasks = std::size(kChMasks);

struct preProcConfigParams_t {
  int samplingFreq = 16000;
  audio_channel_mask_t chMask = AUDIO_CHANNEL_IN_MONO;
  int nsLevel = 0;        // a value between 0-3
  int agcTargetLevel = 3; // in dB
  int agcCompLevel = 9;   // in dB
#ifndef WEBRTC_LEGACY
  float agc2Gain = 0.f;             // in dB
  float agc2SaturationMargin = 2.f; // in dB
  int agc2Level = 0;                // either kRms(0) or kPeak(1)
#endif
  int aecDelay = 0; // in ms
};

constexpr int kSampleRate = 16000;

constexpr size_t kMinOutputChannelCount = 2;

// types of pre processing modules
enum PreProcId {
  PREPROC_AGC, // Automatic Gain Control
#ifndef WEBRTC_LEGACY
  PREPROC_AGC2, // Automatic Gain Control 2
#endif
  PREPROC_AEC, // Acoustic Echo Canceler
  PREPROC_NS,  // Noise Suppressor
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
    (**pEffectHandle)
        ->command(*pEffectHandle, EFFECT_CMD_SET_CONFIG_REVERSE,
                  sizeof(effect_config_t), pConfig, &replySize, &reply);
  }
  (**pEffectHandle)
      ->command(*pEffectHandle, EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t),
                pConfig, &replySize, &reply);
  return reply;
}

int preProcSetConfigParam(uint32_t paramType, uint32_t paramValue,
                          effect_handle_t effectHandle) {
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

static void BM_LVM(benchmark::State &state) {
  constexpr float kTenMilliSecVal = 0.01;
  const size_t chMask = kChMasks[state.range(0) - 1];
  const size_t channelCount = audio_channel_count_from_in_mask(chMask);

  struct preProcConfigParams_t preProcCfgParams {};
  int effectEn[PREPROC_NUM_EFFECTS] = {0};
#ifndef WEBRTC_LEGACY
  int aecMobileMode = 0;
#endif

  switch (state.range(1)) {
  case PREPROC_AGC:
    effectEn[PREPROC_AGC] = 1;
    break;
#ifndef WEBRTC_LEGACY
  case PREPROC_AGC2:
    effectEn[PREPROC_AGC2] = 1;
    break;
#endif
  case PREPROC_AEC:
    effectEn[PREPROC_AEC] = 1;
    break;
  case PREPROC_NS:
    effectEn[PREPROC_NS] = 1;
    break;
  default:
    break;
  }

  preProcCfgParams.samplingFreq = kSampleRate;
  preProcCfgParams.chMask = chMask;

  int32_t sessionId = 1;
  int32_t ioId = 1;
  effect_handle_t effectHandle = nullptr;
  effect_config_t config{};
  config.inputCfg.samplingRate = config.outputCfg.samplingRate =
      preProcCfgParams.samplingFreq;
  config.inputCfg.channels = config.outputCfg.channels =
      preProcCfgParams.chMask;
  config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_16_BIT;

  if (int status = preProcCreateEffect(&effectHandle, state.range(1), &config,
                                       sessionId, ioId);
      status != 0) {
    ALOGE("Create effect call returned error %i", status);
    return;
  }

  if (effectEn[state.range(1)] == 1) {
    int reply = 0;
    uint32_t replySize = sizeof(reply);
    if (int status = (*effectHandle)
                         ->command(effectHandle, EFFECT_CMD_ENABLE, 0, nullptr,
                                   &replySize, &reply);
        status != 0) {
      ALOGE("Command enable call returned error %d\n", reply);
      return;
    }
  }

  // Set Config Params of the effects
  if (effectEn[PREPROC_AGC]) {
    if (int status = preProcSetConfigParam(
            AGC_PARAM_TARGET_LEVEL, (uint32_t)preProcCfgParams.agcTargetLevel,
            effectHandle);
        status != 0) {
      ALOGE("Invalid AGC Target Level. Error %d\n", status);
      return;
    }
    if (int status = preProcSetConfigParam(
            AGC_PARAM_COMP_GAIN, (uint32_t)preProcCfgParams.agcCompLevel,
            effectHandle);
        status != 0) {
      ALOGE("Invalid AGC Comp Gain. Error %d\n", status);
      return;
    }
  }
#ifndef WEBRTC_LEGACY
  if (effectEn[PREPROC_AGC2]) {
    if (int status = preProcSetConfigParam(AGC2_PARAM_FIXED_DIGITAL_GAIN,
                                           (float)preProcCfgParams.agc2Gain,
                                           effectHandle);
        status != 0) {
      ALOGE("Invalid AGC2 Fixed Digital Gain. Error %d\n", status);
      return;
    }
    if (int status = preProcSetConfigParam(
            AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR,
            (uint32_t)preProcCfgParams.agc2Level, effectHandle);
        status != 0) {
      ALOGE("Invalid AGC2 Level Estimator. Error %d\n", status);
      return;
    }
    if (int status = preProcSetConfigParam(
            AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN,
            (float)preProcCfgParams.agc2SaturationMargin, effectHandle);
        status != 0) {
      ALOGE("Invalid AGC2 Saturation Margin. Error %d\n", status);
      return;
    }
  }
#endif
  if (effectEn[PREPROC_NS]) {
    if (int status = preProcSetConfigParam(
            NS_PARAM_LEVEL, (uint32_t)preProcCfgParams.nsLevel, effectHandle);
        status != 0) {
      ALOGE("Invalid Noise Suppression level Error %d\n", status);
      return;
    }
  }
#ifndef WEBRTC_LEGACY
  if (effectEn[PREPROC_AEC]) {
    aecMobileMode = 1;
    if (int status = preProcSetConfigParam(
            AEC_PARAM_MOBILE_MODE, (uint32_t)aecMobileMode, effectHandle);
        status != 0) {
      ALOGE("Invalid AEC mobile mode value %d\n", status);
      return;
    }
  }
#endif

  // Initialize input buffer with deterministic pseudo-random values
  const int frameLength =
      (int)(preProcCfgParams.samplingFreq * kTenMilliSecVal);
  std::minstd_rand gen(chMask);
  std::minstd_rand gen1(chMask);
  std::uniform_real_distribution<> dis(-1.0f, 1.0f);
  std::vector<short> in(frameLength *
                        std::max(channelCount, kMinOutputChannelCount));
  for (auto &idx : in) {
    idx = dis(gen);
  }
  std::vector<short> farIn(frameLength *
                           std::max(channelCount, kMinOutputChannelCount));
  for (auto &idx : farIn) {
    idx = dis(gen1);
  }

  // Run the test
  for (auto _ : state) {
    std::vector<short> out(frameLength *
                           std::max(channelCount, kMinOutputChannelCount));

    benchmark::DoNotOptimize(in.data());
    benchmark::DoNotOptimize(out.data());
    benchmark::DoNotOptimize(farIn.data());

    audio_buffer_t inBuffer = {.frameCount = (size_t)frameLength,
                               .s16 = in.data()};
    audio_buffer_t outBuffer = {.frameCount = (size_t)frameLength,
                                .s16 = out.data()};
    audio_buffer_t farInBuffer = {.frameCount = (size_t)frameLength,
                                  .s16 = farIn.data()};

    if (effectEn[state.range(1)] == 1) {
      if (effectEn[PREPROC_AEC] == 1) {
        if (int status = preProcSetConfigParam(
                AEC_PARAM_ECHO_DELAY, (uint32_t)preProcCfgParams.aecDelay,
                effectHandle);
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
      if (effectEn[PREPROC_AEC] == 1) {
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
  }

  state.SetComplexityN(state.range(0));

  if (int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effectHandle);
      status != 0) {
    ALOGE("release_effect returned an error = %d\n", status);
    return;
  }
}

static void LVMArgs(benchmark::internal::Benchmark *b) {
  for (int i = 2; i <= (int)kNumChMasks; i++) {
    for (int j = 0; j < (int)kNumEffectUuids; ++j) {
      b->Args({i, j});
    }
  }
}

BENCHMARK(BM_LVM)->Apply(LVMArgs);

BENCHMARK_MAIN();
