/*
 * Copyright (C) 2011 The Android Open Source Project
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
#define LOG_TAG "PreProcessing"
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

extern "C" {
// types of pre processing modules
enum preproc_id {
  PREPROC_AGC,  // Automatic Gain Control
  PREPROC_AEC,  // Acoustic Echo Canceler
  PREPROC_NS,   // Noise Suppressor
  PREPROC_NUM_EFFECTS
};

enum preproc_params {
  PREPROC_PARAM_DUMMY = 0,
  PREPROC_PARAM_HELP,
  PREPROC_PARAM_IN_FILE,
  PREPROC_PARAM_OUT_FILE,
  PREPROC_PARAM_REV_FILE,
  PREPROC_PARAM_STREAM_FS,
  PREPROC_PARAM_AGC_TGT_LVL,
  PREPROC_PARAM_AGC_COMP_LVL,
  PREPROC_PARAM_AEC_DELAY,
  PREPROC_PARAM_NS_LVL
};

struct preProcConfigParams_t {
  int samplingFreq = 16000;
  int ns_lvl = 0;        // a value between 0-3
  int agc_tgt_lvl = 3;   // in dB
  int agc_comp_lvl = 9;  // in dB
  int aec_delay = 0;     // in ms
};
// This is the only symbol that needs to be exported
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
  printf("\n     <executable> [options] --i <input_file> --o <out_file>\n");
  printf("\nwhere, \n     <inputfile>  is the input file name");
  printf("\n                  on which Pre Processing effects are applied");
  printf("\n     <outputfile> processed output file");
  printf("\n     and options are mentioned below");
  printf("\n");
  printf("\n     --help (or) --h");
  printf("\n           Prints this usage information");
  printf("\n");
  printf("\n     --fs");
  printf("\n           Sampling Frequency");
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

int preProcSetConfigParam(uint32_t param_type, uint32_t param_value,
                          effect_handle_t effect_hdl) {
  int reply = 0;
  uint32_t reply_size = sizeof(reply);
  uint32_t param_data[2] = {param_type, param_value};
  effect_param_t *effect_param =
      (effect_param_t *)malloc(sizeof(*effect_param) + sizeof(param_data));
  memcpy(&effect_param->data[0], &param_data[0], sizeof(param_data));
  effect_param->psize = sizeof(param_data[0]);
  (*effect_hdl)
      ->command(effect_hdl, EFFECT_CMD_SET_PARAM, sizeof(effect_param_t),
                effect_param, &reply_size, &reply);
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
  const char *revfile = nullptr;
  int effect_en[PREPROC_NUM_EFFECTS] = {false};

  const option long_opts[] = {
      {"help", no_argument, nullptr, (int)PREPROC_PARAM_HELP},
      {"i", required_argument, nullptr, (int)PREPROC_PARAM_IN_FILE},
      {"o", required_argument, nullptr, (int)PREPROC_PARAM_OUT_FILE},
      {"irev", required_argument, nullptr, (int)PREPROC_PARAM_REV_FILE},
      {"fs", required_argument, nullptr, (int)PREPROC_PARAM_STREAM_FS},
      {"agc_tgt_lvl", required_argument, nullptr,
       (int)PREPROC_PARAM_AGC_TGT_LVL},
      {"agc_comp_lvl", required_argument, nullptr,
       (int)PREPROC_PARAM_AGC_COMP_LVL},
      {"aec_delay", required_argument, nullptr, (int)PREPROC_PARAM_AEC_DELAY},
      {"ns_lvl", required_argument, nullptr, (int)PREPROC_PARAM_NS_LVL},
      {"aec", no_argument, &effect_en[PREPROC_AEC], 1},
      {"agc", no_argument, &effect_en[PREPROC_AGC], 1},
      {"ns", no_argument, &effect_en[PREPROC_NS], 1},
      {nullptr, 0, nullptr, 0},
  };
  struct preProcConfigParams_t preProcCfgParams {};

  while (true) {
    int opt = getopt_long(argc, (char *const *)argv, "io:", long_opts, nullptr);
    if (opt == -1) {
      break;
    }
    switch (opt) {
      case PREPROC_PARAM_DUMMY:
        break;
      case PREPROC_PARAM_HELP:
        printUsage();
        return 0;
      case PREPROC_PARAM_IN_FILE: {
        infile = (char *)optarg;
        break;
      }
      case PREPROC_PARAM_OUT_FILE: {
        outfile = (char *)optarg;
        break;
      }
      case PREPROC_PARAM_REV_FILE: {
        revfile = (char *)optarg;
        break;
      }
      case PREPROC_PARAM_STREAM_FS: {
        preProcCfgParams.samplingFreq = atoi(optarg);
        break;
      }
      case PREPROC_PARAM_AGC_TGT_LVL: {
        preProcCfgParams.agc_tgt_lvl = atoi(optarg);
        break;
      }
      case PREPROC_PARAM_AGC_COMP_LVL: {
        preProcCfgParams.agc_comp_lvl = atoi(optarg);
        break;
      }
      case PREPROC_PARAM_AEC_DELAY: {
        preProcCfgParams.aec_delay = atoi(optarg);
        break;
      }
      case PREPROC_PARAM_NS_LVL: {
        preProcCfgParams.ns_lvl = atoi(optarg);
        break;
      }
      default:
        printUsage();
        return 0;
    }
  }

  if (infile == nullptr || outfile == nullptr) {
    printf("Error: missing input/output files\n");
    printUsage();
    return -1;
  }

  FILE *finp = fopen(infile, "rb");
  if (finp == nullptr) {
    printf("Cannot open input file %s\n", infile);
    return -1;
  }

  FILE *frev = nullptr;
  if (effect_en[PREPROC_AEC]) {
    frev = fopen(revfile, "rb");
    if (frev == nullptr) {
      printf("Cannot open reverse stream file %s\n", revfile);
      return -1;
    }
  }

  FILE *fout = fopen(outfile, "wb");
  if (fout == nullptr) {
    printf("Cannot open output file %s\n", outfile);
    fclose(finp);
    return -1;
  }

  int num_eff_en = 0;
  for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
    if (1 == effect_en[i]) {
      num_eff_en++;
    }
  }

  if (0 == num_eff_en) {
    printf("\nNo Effect Enabled. Nothing to process\n");
    fclose(finp);
    fclose(fout);
    return 0;
  }

  assert(num_eff_en <= PREPROC_NUM_EFFECTS);

  int32_t sessionId = 1;
  int32_t ioId = 1;
  effect_handle_t effect_hdl[PREPROC_NUM_EFFECTS] = {0};

  // Create all the effect handles requested by user
  for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
    if (effect_en[i]) {
      int err = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(
          &preproc_uuids[i], sessionId, ioId, &effect_hdl[i]);
      if (err) {
        printf("Audio Preprocessing create returned an error = %d\n", err);
        return -1;
      }
    }
  }

  for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
    if (effect_en[i] == 1) {
      int reply;
      uint32_t reply_size = sizeof(reply);
      effect_config_t config;
      config.inputCfg.samplingRate = config.outputCfg.samplingRate =
          preProcCfgParams.samplingFreq;
      config.inputCfg.channels = config.outputCfg.channels =
          AUDIO_CHANNEL_IN_MONO;
      config.inputCfg.format = config.outputCfg.format =
          AUDIO_FORMAT_PCM_16_BIT;
      if (i == PREPROC_AEC) {
        (*effect_hdl[i])
            ->command(effect_hdl[i], EFFECT_CMD_SET_CONFIG_REVERSE,
                      sizeof(effect_config_t), &config, &reply_size, &reply);
      }
      (*effect_hdl[i])
          ->command(effect_hdl[i], EFFECT_CMD_SET_CONFIG,
                    sizeof(effect_config_t), &config, &reply_size, &reply);
    }
  }
  for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
    if (effect_en[i] == 1) {
      int reply;
      uint32_t reply_size = sizeof(reply);
      (*effect_hdl[i])
          ->command(effect_hdl[i], EFFECT_CMD_ENABLE, 0, NULL, &reply_size,
                    &reply);
    }
  }

  // Set Config Params of the effects
  if (effect_en[PREPROC_AGC]) {
    int err = preProcSetConfigParam(AGC_PARAM_TARGET_LEVEL,
                                    (uint32_t)preProcCfgParams.agc_tgt_lvl,
                                    effect_hdl[PREPROC_AGC]);
    if (err) {
      printf("Invalid AGC Target Level. Error %d\n", err);
      exit(1);
    }
    err = preProcSetConfigParam(AGC_PARAM_COMP_GAIN,
                                (uint32_t)preProcCfgParams.agc_comp_lvl,
                                effect_hdl[PREPROC_AGC]);
    if (err) {
      printf("Invalid AGC Comp Gain. Error %d\n", err);
      exit(1);
    }
  }
  if (effect_en[PREPROC_NS]) {
    int err =
        preProcSetConfigParam(NS_PARAM_LEVEL, (uint32_t)preProcCfgParams.ns_lvl,
                              effect_hdl[PREPROC_NS]);
    if (err) {
      printf("Invalid Noise Suppression level Error %d\n", err);
      exit(1);
    }
  }

  // Process Call
  int frameLength = (preProcCfgParams.samplingFreq / 100);
  int ioChannelCount = 1;
  int ioFrameSize = ioChannelCount * sizeof(short);
  int frameCounter = 0;
  std::vector<short> in(frameLength * ioChannelCount);
  std::vector<short> out(frameLength * ioChannelCount);
  std::vector<short> revIn(frameLength * ioChannelCount);
  std::vector<short> revOut(frameLength * ioChannelCount);
  audio_buffer_t input_buffer, output_buffer, revIn_buffer, revOut_buffer;
  input_buffer.frameCount = frameLength;
  output_buffer.frameCount = frameLength;
  revIn_buffer.frameCount = frameLength;
  revOut_buffer.frameCount = frameLength;
  while (fread(in.data(), ioFrameSize, frameLength, finp) ==
         (size_t)frameLength) {
    if (revfile != nullptr && frev != nullptr) {
      if (fread(revIn.data(), ioFrameSize, frameLength, frev) !=
          (size_t)frameLength) {
        break;
      }
    }

    input_buffer.s16 = in.data();
    output_buffer.s16 = out.data();
    revIn_buffer.s16 = revIn.data();
    revOut_buffer.s16 = revOut.data();

    for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
      if (effect_en[i]) {
        if (effect_en[PREPROC_AEC] == 1) {
          int err = preProcSetConfigParam(AEC_PARAM_ECHO_DELAY,
                                          (uint32_t)preProcCfgParams.aec_delay,
                                          effect_hdl[PREPROC_AEC]);
          if (err) {
            printf("preProcSetConfigParam returned Error %d\n", err);
            exit(1);
          }
        }
        int errCode =
            (*effect_hdl[i])
                ->process(effect_hdl[i], &input_buffer, &output_buffer);
        if (errCode) {
          printf("\nError: Process i = %d returned with error %d\n", i,
                 errCode);
          return errCode;
        }
        if (i == PREPROC_AEC) {
          int errCode = (*effect_hdl[i])
                            ->process_reverse(effect_hdl[i], &revIn_buffer,
                                              &output_buffer);
          if (errCode) {
            printf("\nError: Process reverse i = %d returned with error %d\n",
                   i, errCode);
            return errCode;
          }
        }
      }
    }

    (void)fwrite(out.data(), ioFrameSize, frameLength, fout);
    frameCounter += frameLength;
  }

  // Release all the effect handles created
  for (int i = 0; i < PREPROC_NUM_EFFECTS; i++) {
    if (effect_en[i]) {
      int err = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(effect_hdl[i]);
      if (err) {
        printf("Audio Preprocessing release returned an error = %d\n", err);
        return -1;
      }
    }
  }
  printf("\n");
  fclose(finp);
  fclose(fout);
  return 0;
}

};  // extern "C"
