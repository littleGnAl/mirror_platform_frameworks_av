/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <utils/Log.h>
#include <utils/Timers.h>
#include <hardware/audio_effect.h>
#include <audio_effects/effect_aec.h>
#include <audio_effects/effect_agc.h>
#include <audio_effects/effect_ns.h>
#include <module_common_types.h>
#include <audio_processing.h>

#include <audio_utils/channels.h>
#include <audio_utils/primitives.h>
#include <log/log.h>
#include <system/audio.h>

//------------------------------------------------------------------------------
// local definitions
//------------------------------------------------------------------------------

// types of pre processing modules
enum preproc_id {
  PREPROC_AGC,  // Automatic Gain Control
  PREPROC_AEC,  // Acoustic Echo Canceler
  PREPROC_NS,   // Noise Suppressor
  PREPROC_NUM_EFFECTS
};

enum preproc_params {
  ARG_SETS_EFF = 0,
  ARG_HELP,
  ARG_IN_FILE,
  ARG_OUT_FILE,
  ARG_REV_FILE,
  ARG_STREAM_FS,
  ARG_AGC_TGT_LVL,
  ARG_AGC_COMP_LVL,
  ARG_AEC_DELAY,
  ARG_NS_LVL
};

struct preProcConfigParams_t {
  int samplingFreq = 16000;
  int nsLevel = 0;        // a value between 0-3
  int agcTargetLevel = 3;   // in dB
  int agcCompLevel = 9;  // in dB
  int aecDelay = 0;     // in ms
};
// This is the only symbol that needs to be imported
extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;

const effect_uuid_t preproc_uuids[PREPROC_NUM_EFFECTS] = {
    {0xaa8130e0,
     0x66fc,
     0x11e0,
     0xbad0,
     {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // agc uuid
    {0xbb392ec0,
     0x8d4d,
     0x11e0,
     0xa896,
     {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // aec uuid
    {0xc06c8400,
     0x8e06,
     0x11e0,
     0x9cb6,
     {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // ns  uuid
};

void printUsage() {
  printf("\nUsage: ");
  printf("\n     <executable> [options] --input <input_file> --output <out_file>\n");
  printf("\nwhere, ");
  printf("\n     <inputfile>");
  printf("\n           is the input file name on which Pre Processing effects are applied");
  printf("\n     <outputfile>");
  printf("\n           processed output file");
  printf("\n     and options are mentioned below");
  printf("\n");
  printf("\n     --help (or) --h");
  printf("\n           Prints this usage information");
  printf("\n");
  printf("\n     --fs <sampling_freq>");
  printf("\n           Sampling Frequency");
  printf("\n     --far <farend_file>");
  printf("\n           Far end signal file needed for echo cancellation");
  printf("\n     --aec");
  printf("\n           Enable Echo Cancellation");
  printf("\n     --ns");
  printf("\n           Enable Noise Suppression");
  printf("\n     --agc");
  printf("\n           Enable Gain Control");
  printf("\n     --ns_lvl <ns_level>");
  printf("\n           Noise Suppression level");
  printf("\n     --agc_tgt_lvl <target_level>");
  printf("\n           AGC Target Level");
  printf("\n     --agc_comp_lvl <comp_level>");
  printf("\n           AGC Comp Level");
  printf("\n     --aec_delay <delay>");
  printf("\n           AEC delay value");
  printf("\n");
}

static const float kTenMilliSecVal = 0.01;

int preProcCreateEffect(effect_handle_t *pEffectHandle, uint32_t effectType,
                          effect_config_t *pConfig, int sessionId, int ioId) {
  int err = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(
      &preproc_uuids[effectType], sessionId, ioId, pEffectHandle);
  if (err) {
    ALOGE("Audio Preprocessing create returned an error = %d\n", err);
    return -1;
  }
  int reply = 0;
  uint32_t replySize = sizeof(reply);
  if (effectType == PREPROC_AEC) {
    (**pEffectHandle)
        ->command(*pEffectHandle, EFFECT_CMD_SET_CONFIG_REVERSE,
                  sizeof(effect_config_t), pConfig, &replySize, &reply);
  }
  (**pEffectHandle)
      ->command(*pEffectHandle, EFFECT_CMD_SET_CONFIG,
                sizeof(effect_config_t), pConfig, &replySize, &reply);
  return reply;
}

int preProcSetConfigParam(uint32_t param_type, uint32_t param_value,
                          effect_handle_t effectHandle) {
  int reply = 0;
  uint32_t replySize = sizeof(reply);
  uint32_t param_data[2] = {param_type, param_value};
  effect_param_t *effect_param =
      (effect_param_t *)malloc(sizeof(*effect_param) + sizeof(param_data));
  memcpy(&effect_param->data[0], &param_data[0], sizeof(param_data));
  effect_param->psize = sizeof(param_data[0]);
  (*effectHandle)
      ->command(effectHandle, EFFECT_CMD_SET_PARAM, sizeof(effect_param_t),
                effect_param, &replySize, &reply);
  free(effect_param);
  return reply;
}

int main(int argc, const char *argv[]) {
  if (argc == 1) {
    printUsage();
    return -1;
  }
  const char *infile = nullptr;
  const char *outfile = nullptr;
  const char *farFile = nullptr;
  int effectEn[PREPROC_NUM_EFFECTS] = {0};

  const option long_opts[] = {
      {"help", no_argument, nullptr, (int)ARG_HELP},
      {"input", required_argument, nullptr, (int)ARG_IN_FILE},
      {"output", required_argument, nullptr, (int)ARG_OUT_FILE},
      {"far", required_argument, nullptr, (int)ARG_REV_FILE},
      {"fs", required_argument, nullptr, (int)ARG_STREAM_FS},
      {"agc_tgt_lvl", required_argument, nullptr,
       (int)ARG_AGC_TGT_LVL},
      {"agc_comp_lvl", required_argument, nullptr,
       (int)ARG_AGC_COMP_LVL},
      {"aec_delay", required_argument, nullptr, (int)ARG_AEC_DELAY},
      {"ns_lvl", required_argument, nullptr, (int)ARG_NS_LVL},
      {"aec", no_argument, &effectEn[PREPROC_AEC], 1},
      {"agc", no_argument, &effectEn[PREPROC_AGC], 1},
      {"ns", no_argument, &effectEn[PREPROC_NS], 1},
      {nullptr, 0, nullptr, 0},
  };
  struct preProcConfigParams_t preProcCfgParams {};

  while (true) {
    int opt = getopt_long(argc, (char *const *)argv, "i:o:", long_opts, nullptr);
    if (opt == -1) {
      break;
    }
    switch (opt) {
      case ARG_SETS_EFF:
        break;
      case ARG_HELP:
        printUsage();
        return 0;
      case ARG_IN_FILE: {
        infile = (char *)optarg;
        break;
      }
      case ARG_OUT_FILE: {
        outfile = (char *)optarg;
        break;
      }
      case ARG_REV_FILE: {
        farFile = (char *)optarg;
        break;
      }
      case ARG_STREAM_FS: {
        preProcCfgParams.samplingFreq = atoi(optarg);
        break;
      }
      case ARG_AGC_TGT_LVL: {
        preProcCfgParams.agcTargetLevel = atoi(optarg);
        break;
      }
      case ARG_AGC_COMP_LVL: {
        preProcCfgParams.agcCompLevel = atoi(optarg);
        break;
      }
      case ARG_AEC_DELAY: {
        preProcCfgParams.aecDelay = atoi(optarg);
        break;
      }
      case ARG_NS_LVL: {
        preProcCfgParams.nsLevel = atoi(optarg);
        break;
      }
      default:
        printUsage();
        return 0;
    }
  }

  if (infile == nullptr || outfile == nullptr) {
    ALOGE("Error: missing input/output files\n");
    printUsage();
    return -1;
  }

  FILE *fInp = fopen(infile, "rb");
  if (fInp == nullptr) {
    ALOGE("Cannot open input file %s\n", infile);
    return -1;
  }

  FILE *fFar = nullptr;
  if (effectEn[PREPROC_AEC]) {
    if (farFile == nullptr) {
      ALOGE("Far end signal file requried for echo cancellation \n");
      fclose(fInp);
      return -1;
    }
    fFar = fopen(farFile, "rb");
    if (fFar == nullptr) {
      ALOGE("Cannot open far end stream file %s\n", farFile);
      fclose(fInp);
      return -1;
    }
  }

  FILE *fOut = fopen(outfile, "wb");
  if (fOut == nullptr) {
    ALOGE("Cannot open output file %s\n", outfile);
    fclose(fInp);
    if (fFar != nullptr) {
      fclose(fFar);
    }
    return -1;
  }

  int32_t sessionId = 1;
  int32_t ioId = 1;
  effect_handle_t effectHandle[PREPROC_NUM_EFFECTS] = {0};
  effect_config_t config;
  config.inputCfg.samplingRate = config.outputCfg.samplingRate =
      preProcCfgParams.samplingFreq;
  config.inputCfg.channels = config.outputCfg.channels =
      AUDIO_CHANNEL_IN_MONO;
  config.inputCfg.format = config.outputCfg.format =
          AUDIO_FORMAT_PCM_16_BIT;

  // Create all the effect handles
  for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
    preProcCreateEffect(&effectHandle[i], i,
                        &config, sessionId, ioId);
  }

  for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
    if (effectEn[i] == 1) {
      int reply;
      uint32_t replySize = sizeof(reply);
      (*effectHandle[i])
          ->command(effectHandle[i], EFFECT_CMD_ENABLE, 0, NULL, &replySize,
                    &reply);
    }
  }

  // Set Config Params of the effects
  if (effectEn[PREPROC_AGC]) {
    int err = preProcSetConfigParam(AGC_PARAM_TARGET_LEVEL,
                                    (uint32_t)preProcCfgParams.agcTargetLevel,
                                    effectHandle[PREPROC_AGC]);
    if (err) {
      ALOGE("Invalid AGC Target Level. Error %d\n", err);
      return -1;
    }
    err = preProcSetConfigParam(AGC_PARAM_COMP_GAIN,
                                (uint32_t)preProcCfgParams.agcCompLevel,
                                effectHandle[PREPROC_AGC]);
    if (err) {
      ALOGE("Invalid AGC Comp Gain. Error %d\n", err);
      return -1;
    }
  }
  if (effectEn[PREPROC_NS]) {
    int err =
        preProcSetConfigParam(NS_PARAM_LEVEL, (uint32_t)preProcCfgParams.nsLevel,
                              effectHandle[PREPROC_NS]);
    if (err) {
      ALOGE("Invalid Noise Suppression level Error %d\n", err);
      return -1;
    }
  }

  // Process Call
  int frameLength = (int)(preProcCfgParams.samplingFreq * kTenMilliSecVal);
  int ioChannelCount = 1;
  int ioFrameSize = ioChannelCount * sizeof(short);
  int frameCounter = 0;
  std::vector<short> in(frameLength * ioChannelCount);
  std::vector<short> out(frameLength * ioChannelCount);
  std::vector<short> farIn(frameLength * ioChannelCount);
  std::vector<short> farOut(frameLength * ioChannelCount);
  audio_buffer_t inputBuffer, outputBuffer, farInBuffer, farOutBuffer;
  inputBuffer.frameCount = frameLength;
  outputBuffer.frameCount = frameLength;
  farInBuffer.frameCount = frameLength;
  farOutBuffer.frameCount = frameLength;
  while (fread(in.data(), ioFrameSize, frameLength, fInp) ==
         (size_t)frameLength) {
    if (fFar != nullptr) {
      if (fread(farIn.data(), ioFrameSize, frameLength, fFar) !=
          (size_t)frameLength) {
        break;
      }
    }

    inputBuffer.s16 = in.data();
    outputBuffer.s16 = out.data();
    farInBuffer.s16 = farIn.data();
    farOutBuffer.s16 = farOut.data();

    for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
      if (effectEn[i] == 1) {
        if (i == PREPROC_AEC) {
          int err = preProcSetConfigParam(AEC_PARAM_ECHO_DELAY,
                                          (uint32_t)preProcCfgParams.aecDelay,
                                          effectHandle[PREPROC_AEC]);
          if (err) {
            ALOGE("preProcSetConfigParam returned Error %d\n", err);
            return -1;
          }
        }
        int errCode =
            (*effectHandle[i])
                ->process(effectHandle[i], &inputBuffer, &outputBuffer);
        if (errCode) {
          ALOGE("\nError: Process i = %d returned with error %d\n", i,
                 errCode);
          return errCode;
        }
        if (i == PREPROC_AEC) {
          int errCode = (*effectHandle[i])
                            ->process_reverse(effectHandle[i], &farInBuffer,
                                              &outputBuffer);
          if (errCode) {
            ALOGE("\nError: Process reverse i = %d returned with error %d\n",
                   i, errCode);
            return errCode;
          }
        }
      }
    }
    if (fwrite(out.data(), ioFrameSize, frameLength, fOut) != (size_t)frameLength) {
      ALOGE("\nError: Output file writing failed");
      break;
    }
    frameCounter += frameLength;
  }

  // Release all the effect handles created
  for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
    int err = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effectHandle[i]);
    if (err) {
      ALOGE("Audio Preprocessing release returned an error = %d\n", err);
      return -1;
    }
  }
  fclose(fInp);
  fclose(fOut);
  return 0;
}

