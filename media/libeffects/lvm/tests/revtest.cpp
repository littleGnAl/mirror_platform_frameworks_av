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
#include <assert.h>
#include <inttypes.h>
#include <iterator>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include <audio_utils/channels.h>
#include <audio_utils/primitives.h>
#include <log/log.h>
#include <system/audio.h>

#include "EffectReverb.h"
#include "LVREV.h"

// PreProcessors
#ifdef VERY_VERY_VERBOSE_LOGGING
#define ALOGVV ALOGV
#else
#define ALOGVV(a...) \
  do {               \
  } while (false)
#endif

#define CHECK_ARG(cond)                                  \
  {                                                      \
    if (!(cond)) {                                       \
      ALOGE("\tLVREV_ERROR : Invalid argument: " #cond); \
      return -EINVAL;                                    \
    }                                                    \
  }

#define LVREV_ERROR_CHECK(LvrevStatus, callingFunc, calledFunc) \
  {                                                             \
    if ((LvrevStatus) == LVREV_NULLADDRESS) {                   \
      ALOGE(                                                    \
          "\tLVREV_ERROR : Parameter error - "                  \
          "null pointer returned by %s in %s\n\n\n\n",          \
          callingFunc, calledFunc);                             \
    }                                                           \
    if ((LvrevStatus) == LVREV_INVALIDNUMSAMPLES) {             \
      ALOGE(                                                    \
          "\tLVREV_ERROR : Parameter error - "                  \
          "bad number of samples returned by %s in %s\n\n\n\n", \
          callingFunc, calledFunc);                             \
    }                                                           \
    if ((LvrevStatus) == LVREV_OUTOFRANGE) {                    \
      ALOGE(                                                    \
          "\tLVREV_ERROR : Parameter error - "                  \
          "out of range returned by %s in %s\n",                \
          callingFunc, calledFunc);                             \
    }                                                           \
  }
#define REVERB_DEFAULT_PRESET REVERB_PRESET_NONE

#define REVERB_SEND_LEVEL 0.75f      // 0.75 in 4.12 format
#define REVERB_UNIT_VOLUME (0x1000)  // 1.0 in 4.12 format

// Global Variables
typedef float process_buffer_t;  // process in float

// structures
struct ReverbContext {
  const struct effect_interface_s *itfe;
  effect_config_t config;
  LVREV_Handle_t hInstance;
  int16_t SavedRoomLevel;
  int16_t SavedHfLevel;
  int16_t SavedDecayTime;
  int16_t SavedDecayHfRatio;
  int16_t SavedReverbLevel;
  int16_t SavedDiffusion;
  int16_t SavedDensity;
  bool bEnabled;
  LVM_Fs_en SampleRate;
  process_buffer_t *InFrames;
  process_buffer_t *OutFrames;
  size_t bufferSizeIn;
  size_t bufferSizeOut;
  bool auxiliary;
  bool preset;
  uint16_t curPreset;
  uint16_t nextPreset;
  int SamplesToExitCount;
  LVM_INT16 leftVolume;
  LVM_INT16 rightVolume;
  LVM_INT16 prevLeftVolume;
  LVM_INT16 prevRightVolume;
  int volumeMode;
};

struct reverbConfigParams_t {
  LVM_Fs_en SampleRate = LVM_FS_44100;
  int nrChannels = 2;
  int chMask = AUDIO_CHANNEL_OUT_STEREO;
  int fChannels = 2;
  int monoMode = false;
  int frameLength = 256;
  int preset_val = 0;
  t_reverb_settings revProperties = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  bool auxiliary = 0;
};

enum {
  REVERB_VOLUME_OFF,
  REVERB_VOLUME_FLAT,
  REVERB_VOLUME_RAMP,
};

const static t_reverb_settings sReverbPresets[] = {
    // REVERB_PRESET_NONE: values are unused
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    // REVERB_PRESET_SMALLROOM
    {-400, -600, 1100, 830, -400, 5, 500, 10, 1000, 1000},
    // REVERB_PRESET_MEDIUMROOM
    {-400, -600, 1300, 830, -1000, 20, -200, 20, 1000, 1000},
    // REVERB_PRESET_LARGEROOM
    {-400, -600, 1500, 830, -1600, 5, -1000, 40, 1000, 1000},
    // REVERB_PRESET_MEDIUMHALL
    {-400, -600, 1800, 700, -1300, 15, -800, 30, 1000, 1000},
    // REVERB_PRESET_LARGEHALL
    {-400, -600, 1800, 700, -2000, 30, -1400, 60, 1000, 1000},
    // REVERB_PRESET_PLATE
    {-400, -200, 1300, 900, 0, 2, 0, 10, 1000, 750},
};

int Reverb_LoadPreset(ReverbContext *pContext);

//----------------------------------------------------------------------------
// process()
//----------------------------------------------------------------------------
// Purpose:
// Apply the Reverb
//
// Inputs:
//  pIn:        pointer to stereo/mono float or 16 bit input data
//  pOut:       pointer to stereo float or 16 bit output data
//  frameCount: Frames to process
//  pContext:   effect engine context
//
//  Outputs:
//  pOut:       pointer to updated stereo 16 bit output data
//
//----------------------------------------------------------------------------
int process(effect_buffer_t *pIn, effect_buffer_t *pOut, int frameCount,
            ReverbContext *pContext) {
  int channels =
      audio_channel_count_from_out_mask(pContext->config.inputCfg.channels);
  LVREV_ReturnStatus_en LvrevStatus = LVREV_SUCCESS; /* Function call status */

  // Check that the input is either mono or stereo
  if (channels < 1 || channels > LVM_MAX_CHANNELS) {
    ALOGE("\tLVREV_ERROR : process invalid number of channels");
    return -EINVAL;
  }
  int mChannels = channels > FCC_2 ? FCC_2 : channels;

  size_t inSize = frameCount * sizeof(process_buffer_t) * mChannels;
  size_t outSize = frameCount * sizeof(process_buffer_t) * FCC_2;
  if (pContext->InFrames == NULL || pContext->bufferSizeIn < inSize) {
    free(pContext->InFrames);
    pContext->bufferSizeIn = inSize;
    pContext->InFrames = (process_buffer_t *)calloc(1, pContext->bufferSizeIn);
  }
  if (pContext->OutFrames == NULL || pContext->bufferSizeOut < outSize) {
    free(pContext->OutFrames);
    pContext->bufferSizeOut = outSize;
    pContext->OutFrames =
        (process_buffer_t *)calloc(1, pContext->bufferSizeOut);
  }

  // Check for NULL pointers
  if ((pContext->InFrames == NULL) || (pContext->OutFrames == NULL)) {
    ALOGE(
        "\tLVREV_ERROR : process failed to allocate memory for temporary "
        "buffers ");
    return -EINVAL;
  }
  if (pContext->preset && pContext->nextPreset != pContext->curPreset) {
    Reverb_LoadPreset(pContext);
  }

  for (int i = 0; i < frameCount; i++) {
    for (int j = 0; j < mChannels; j++) {
      pContext->InFrames[i * mChannels + j] =
          (process_buffer_t)pIn[i * channels + j] * REVERB_SEND_LEVEL;
    }
  }

  if (pContext->preset && pContext->curPreset == REVERB_PRESET_NONE) {
    memset(pContext->OutFrames, 0,
           frameCount * sizeof(*pContext->OutFrames) *
               FCC_2);  // always stereo here
  } else {
    if (pContext->bEnabled == LVM_FALSE && pContext->SamplesToExitCount > 0) {
      memset(pContext->InFrames, 0,
             frameCount * sizeof(*pContext->OutFrames) * channels);
      ALOGV("\tZeroing %d samples per frame at the end of call", channels);
    }
    /* Process the samples, producing a stereo output */
    LvrevStatus = LVREV_Process(pContext->hInstance, /* Instance handle */
                                pContext->InFrames,  /* Input buffer */
                                pContext->OutFrames, /* Output buffer */
                                frameCount); /* Number of samples to read */
  }
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_Process", "process")
  if (LvrevStatus != LVREV_SUCCESS) return -EINVAL;

  // Convert to 16 bits
  if (pContext->auxiliary) {
    // nothing to do here
  } else {
    for (int i = 0; i < frameCount; i++) {  // always stereo here
                                            // Mix with dry input
      for (int j = 0; j < FCC_2; j++) {
        pContext->OutFrames[i * FCC_2 + j] += pIn[i * channels + j];
      }
    }

    // apply volume with ramp if needed
    if ((pContext->leftVolume != pContext->prevLeftVolume ||
         pContext->rightVolume != pContext->prevRightVolume) &&
        pContext->volumeMode == REVERB_VOLUME_RAMP) {
      // FIXME: still using int16 volumes.
      // For reference: REVERB_UNIT_VOLUME  (0x1000) // 1.0 in 4.12 format
      float vl = (float)pContext->prevLeftVolume / 4096;
      float incl = (((float)pContext->leftVolume / 4096) - vl) / frameCount;
      float vr = (float)pContext->prevRightVolume / 4096;
      float incr = (((float)pContext->rightVolume / 4096) - vr) / frameCount;

      for (int i = 0; i < frameCount; i++) {
        pContext->OutFrames[FCC_2 * i] *= vl;
        pContext->OutFrames[FCC_2 * i + 1] *= vr;

        vl += incl;
        vr += incr;
      }
      pContext->prevLeftVolume = pContext->leftVolume;
      pContext->prevRightVolume = pContext->rightVolume;
    } else if (pContext->volumeMode != REVERB_VOLUME_OFF) {
      if (pContext->leftVolume != REVERB_UNIT_VOLUME ||
          pContext->rightVolume != REVERB_UNIT_VOLUME) {
        for (int i = 0; i < frameCount; i++) {
          pContext->OutFrames[FCC_2 * i] *=
              ((float)pContext->leftVolume / 4096);
          pContext->OutFrames[FCC_2 * i + 1] *=
              ((float)pContext->rightVolume / 4096);
        }
      }
      pContext->prevLeftVolume = pContext->leftVolume;
      pContext->prevRightVolume = pContext->rightVolume;
      pContext->volumeMode = REVERB_VOLUME_RAMP;
    }
  }

  int mOutChannels = channels < FCC_2 ? FCC_2 : channels;
  for (int i = 0; i < frameCount; i++) {
    for (int j = 0; j < FCC_2; j++) {
      pOut[mOutChannels * i + j] = pContext->OutFrames[i * FCC_2 + j];
    }
  }
  if (channels > FCC_2) {
    for (int i = 0; i < frameCount; i++) {
      for (int j = FCC_2; j < channels; j++) {
        pOut[channels * i + j] = pIn[channels * i + j];
      }
    }
  }
  return 0;
} /* end process */

//----------------------------------------------------------------------------
// Reverb_free()
//----------------------------------------------------------------------------
// Purpose: Free all memory associated with the Bundle.
//
// Inputs:
//  pContext:   effect engine context
//
// Outputs:
//
//----------------------------------------------------------------------------

void Reverb_free(ReverbContext *pContext) {
  LVREV_ReturnStatus_en LvrevStatus = LVREV_SUCCESS; /* Function call status */
  LVREV_MemoryTable_st MemTab;

  /* Free the algorithm memory */
  LvrevStatus = LVREV_GetMemoryTable(pContext->hInstance, &MemTab, LVM_NULL);

  LVREV_ERROR_CHECK(LvrevStatus, "LVM_GetMemoryTable", "Reverb_free")

  for (int i = 0; i < LVM_NR_MEMORY_REGIONS; i++) {
    if (MemTab.Region[i].Size != 0) {
      if (MemTab.Region[i].pBaseAddress != NULL) {
        free(MemTab.Region[i].pBaseAddress);
      } else {
        ALOGV("\tLVM_ERROR : free() - trying to free with NULL pointer %" PRIu32
              " bytes "
              "for region %u at %p ERROR\n",
              MemTab.Region[i].Size, i, MemTab.Region[i].pBaseAddress);
      }
    }
  }
} /* end Reverb_free */

//----------------------------------------------------------------------------
// ReverbConvertLevel()
//----------------------------------------------------------------------------
// Purpose:
// Convert level from OpenSL ES format to LVM format
//
// Inputs:
//  level       level to be applied
//
//----------------------------------------------------------------------------

int16_t ReverbConvertLevel(int16_t level) {
  static int16_t LevelArray[101] = {
      -12000, -4000, -3398, -3046, -2796, -2603, -2444, -2310, -2194, -2092,
      -2000,  -1918, -1842, -1773, -1708, -1648, -1592, -1540, -1490, -1443,
      -1398,  -1356, -1316, -1277, -1240, -1205, -1171, -1138, -1106, -1076,
      -1046,  -1018, -990,  -963,  -938,  -912,  -888,  -864,  -841,  -818,
      -796,   -775,  -754,  -734,  -714,  -694,  -675,  -656,  -638,  -620,
      -603,   -585,  -568,  -552,  -536,  -520,  -504,  -489,  -474,  -459,
      -444,   -430,  -416,  -402,  -388,  -375,  -361,  -348,  -335,  -323,
      -310,   -298,  -286,  -274,  -262,  -250,  -239,  -228,  -216,  -205,
      -194,   -184,  -173,  -162,  -152,  -142,  -132,  -121,  -112,  -102,
      -92,    -82,   -73,   -64,   -54,   -45,   -36,   -27,   -18,   -9,
      0};
  int16_t i;

  for (i = 0; i < 101; i++) {
    if (level <= LevelArray[i]) break;
  }
  return i;
}

//----------------------------------------------------------------------------
// ReverbConvertHFLevel()
//----------------------------------------------------------------------------
// Purpose:
// Convert level from OpenSL ES format to LVM format
//
// Inputs:
//  level       level to be applied
//
//----------------------------------------------------------------------------

int16_t ReverbConvertHfLevel(int16_t Hflevel) {
  int16_t i;

  static LPFPair_t LPFArray[97] = {
      // Limit range to 50 for LVREV parameter range
      {-10000, 50},  {-5000, 50},  {-4000, 50},  {-3000, 158}, {-2000, 502},
      {-1000, 1666}, {-900, 1897}, {-800, 2169}, {-700, 2496}, {-600, 2895},
      {-500, 3400},  {-400, 4066}, {-300, 5011}, {-200, 6537}, {-100, 9826},
      {-99, 9881},   {-98, 9937},  {-97, 9994},  {-96, 10052}, {-95, 10111},
      {-94, 10171},  {-93, 10231}, {-92, 10293}, {-91, 10356}, {-90, 10419},
      {-89, 10484},  {-88, 10549}, {-87, 10616}, {-86, 10684}, {-85, 10753},
      {-84, 10823},  {-83, 10895}, {-82, 10968}, {-81, 11042}, {-80, 11117},
      {-79, 11194},  {-78, 11272}, {-77, 11352}, {-76, 11433}, {-75, 11516},
      {-74, 11600},  {-73, 11686}, {-72, 11774}, {-71, 11864}, {-70, 11955},
      {-69, 12049},  {-68, 12144}, {-67, 12242}, {-66, 12341}, {-65, 12443},
      {-64, 12548},  {-63, 12654}, {-62, 12763}, {-61, 12875}, {-60, 12990},
      {-59, 13107},  {-58, 13227}, {-57, 13351}, {-56, 13477}, {-55, 13607},
      {-54, 13741},  {-53, 13878}, {-52, 14019}, {-51, 14164}, {-50, 14313},
      {-49, 14467},  {-48, 14626}, {-47, 14789}, {-46, 14958}, {-45, 15132},
      {-44, 15312},  {-43, 15498}, {-42, 15691}, {-41, 15890}, {-40, 16097},
      {-39, 16311},  {-38, 16534}, {-37, 16766}, {-36, 17007}, {-35, 17259},
      {-34, 17521},  {-33, 17795}, {-32, 18081}, {-31, 18381}, {-30, 18696},
      {-29, 19027},  {-28, 19375}, {-27, 19742}, {-26, 20129}, {-25, 20540},
      {-24, 20976},  {-23, 21439}, {-22, 21934}, {-21, 22463}, {-20, 23031},
      {-19, 23643},  {-18, 23999}};

  for (i = 0; i < 96; i++) {
    if (Hflevel <= LPFArray[i].Room_HF) break;
  }
  return LPFArray[i].LPF;
}

//----------------------------------------------------------------------------
// ReverbSetRoomHfLevel()
//----------------------------------------------------------------------------
// Purpose:
// Apply the HF level to the Reverb. Must first be converted to LVM format
//
// Inputs:
//  pContext:   effect engine context
//  level       level to be applied
//
//----------------------------------------------------------------------------

void ReverbSetRoomHfLevel(ReverbContext *pContext, int16_t level) {

  LVREV_ControlParams_st ActiveParams; /* Current control Parameters */
  LVREV_ReturnStatus_en LvrevStatus = LVREV_SUCCESS; /* Function call status */

  /* Get the current settings */
  LvrevStatus = LVREV_GetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_GetControlParameters",
                    "ReverbSetRoomHfLevel")

  ActiveParams.LPF = ReverbConvertHfLevel(level);

  /* Activate the initial settings */
  LvrevStatus = LVREV_SetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_SetControlParameters",
                    "ReverbSetRoomHfLevel")
  // ALOGV("\tReverbSetRoomhfLevel() just Set -> %d\n", ActiveParams.LPF);
  pContext->SavedHfLevel = level;
  // ALOGV("\tReverbSetHfRoomLevel end.. saving %d", pContext->SavedHfLevel);
  return;
}

//----------------------------------------------------------------------------
// ReverbSetReverbLevel()
//----------------------------------------------------------------------------
// Purpose:
// Apply the level to the Reverb. Must first be converted to LVM format
//
// Inputs:
//  pContext:   effect engine context
//  level       level to be applied
//
//----------------------------------------------------------------------------

void ReverbSetReverbLevel(ReverbContext *pContext, int16_t level) {
  // ALOGV("\n\tReverbSetReverbLevel start (%d)", level);

  LVREV_ControlParams_st ActiveParams; /* Current control Parameters */
  LVREV_ReturnStatus_en LvrevStatus = LVREV_SUCCESS; /* Function call status */
  LVM_INT32 CombinedLevel;  // Sum of room and reverb level controls

  /* Get the current settings */
  LvrevStatus = LVREV_GetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_GetControlParameters",
                    "ReverbSetReverbLevel")

  // needs to subtract max levels for both RoomLevel and ReverbLevel
  CombinedLevel = (level + pContext->SavedRoomLevel) - LVREV_MAX_REVERB_LEVEL;

  ActiveParams.Level = ReverbConvertLevel(CombinedLevel);

  /* Activate the initial settings */
  LvrevStatus = LVREV_SetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_SetControlParameters",
                    "ReverbSetReverbLevel")

  pContext->SavedReverbLevel = level;
  return;
}

//----------------------------------------------------------------------------
// ReverbSetRoomLevel()
//----------------------------------------------------------------------------
// Purpose:
// Apply the level to the Reverb. Must first be converted to LVM format
//
// Inputs:
//  pContext:   effect engine context
//  level       level to be applied
//
//----------------------------------------------------------------------------

void ReverbSetRoomLevel(ReverbContext *pContext, int16_t level) {
  // ALOGV("\tReverbSetRoomLevel start (%d)", level);

  LVREV_ControlParams_st ActiveParams; /* Current control Parameters */
  LVREV_ReturnStatus_en LvrevStatus = LVREV_SUCCESS; /* Function call status */
  LVM_INT32 CombinedLevel;  // Sum of room and reverb level controls

  /* Get the current settings */
  LvrevStatus = LVREV_GetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_GetControlParameters",
                    "ReverbSetRoomLevel")

  // needs to subtract max levels for both RoomLevel and ReverbLevel
  CombinedLevel = (level + pContext->SavedReverbLevel) - LVREV_MAX_REVERB_LEVEL;
  ActiveParams.Level = ReverbConvertLevel(CombinedLevel);

  /* Activate the initial settings */
  LvrevStatus = LVREV_SetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_SetControlParameters",
                    "ReverbSetRoomLevel")

  pContext->SavedRoomLevel = level;
  return;
}

//----------------------------------------------------------------------------
// ReverbSetDecayTime()
//----------------------------------------------------------------------------
// Purpose:
// Apply the decay time to the Reverb.
//
// Inputs:
//  pContext:   effect engine context
//  time        decay to be applied
//
//----------------------------------------------------------------------------

void ReverbSetDecayTime(ReverbContext *pContext, uint32_t time) {

  LVREV_ControlParams_st ActiveParams; /* Current control Parameters */
  LVREV_ReturnStatus_en LvrevStatus = LVREV_SUCCESS; /* Function call status */

  /* Get the current settings */
  LvrevStatus = LVREV_GetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_GetControlParameters",
                    "ReverbSetDecayTime")

  if (time <= LVREV_MAX_T60) {
    ActiveParams.T60 = (LVM_UINT16)time;
  } else {
    ActiveParams.T60 = LVREV_MAX_T60;
  }

  /* Activate the initial settings */
  LvrevStatus = LVREV_SetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_SetControlParameters",
                    "ReverbSetDecayTime")

  pContext->SamplesToExitCount =
      (ActiveParams.T60 * pContext->config.inputCfg.samplingRate) / 1000;
  pContext->SavedDecayTime = (int16_t)time;
  return;
}

//----------------------------------------------------------------------------
// ReverbSetDecayHfRatio()
//----------------------------------------------------------------------------
// Purpose:
// Apply the HF decay ratio to the Reverb.
//
// Inputs:
//  pContext:   effect engine context
//  ratio       ratio to be applied
//
//----------------------------------------------------------------------------

void ReverbSetDecayHfRatio(ReverbContext *pContext, int16_t ratio) {

  LVREV_ControlParams_st ActiveParams; /* Current control Parameters */
  LVREV_ReturnStatus_en LvrevStatus = LVREV_SUCCESS; /* Function call status */

  /* Get the current settings */
  LvrevStatus = LVREV_GetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_GetControlParameters",
                    "ReverbSetDecayHfRatio")

  ActiveParams.Damping = (LVM_INT16)(ratio / 20);

  /* Activate the initial settings */
  LvrevStatus = LVREV_SetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_SetControlParameters",
                    "ReverbSetDecayHfRatio")

  pContext->SavedDecayHfRatio = ratio;
  return;
}

//----------------------------------------------------------------------------
// ReverbSetDiffusion()
//----------------------------------------------------------------------------
// Purpose:
// Apply the diffusion to the Reverb.
//
// Inputs:
//  pContext:   effect engine context
//  level        decay to be applied
//
//----------------------------------------------------------------------------

void ReverbSetDiffusion(ReverbContext *pContext, int16_t level) {
  // ALOGV("\tReverbSetDiffusion start (%d)", level);

  LVREV_ControlParams_st ActiveParams; /* Current control Parameters */
  LVREV_ReturnStatus_en LvrevStatus = LVREV_SUCCESS; /* Function call status */

  /* Get the current settings */
  LvrevStatus = LVREV_GetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_GetControlParameters",
                    "ReverbSetDiffusion")

  ActiveParams.Density = (LVM_INT16)(level / 10);

  /* Activate the initial settings */
  LvrevStatus = LVREV_SetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_SetControlParameters",
                    "ReverbSetDiffusion")

  pContext->SavedDiffusion = level;
  return;
}

//----------------------------------------------------------------------------
// ReverbSetDensity()
//----------------------------------------------------------------------------
// Purpose:
// Apply the density level the Reverb.
//
// Inputs:
//  pContext:   effect engine context
//  level        decay to be applied
//
//----------------------------------------------------------------------------

void ReverbSetDensity(ReverbContext *pContext, int16_t level) {
  // ALOGV("\tReverbSetDensity start (%d)", level);

  LVREV_ControlParams_st ActiveParams; /* Current control Parameters */
  LVREV_ReturnStatus_en LvrevStatus = LVREV_SUCCESS; /* Function call status */

  /* Get the current settings */
  LvrevStatus = LVREV_GetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_GetControlParameters",
                    "ReverbSetDensity")

  ActiveParams.RoomSize = (LVM_INT16)(((level * 99) / 1000) + 1);

  /* Activate the initial settings */
  LvrevStatus = LVREV_SetControlParameters(pContext->hInstance, &ActiveParams);
  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_SetControlParameters",
                    "ReverbSetDensity")

  pContext->SavedDensity = level;
  return;
}

//----------------------------------------------------------------------------
// Reverb_LoadPreset()
//----------------------------------------------------------------------------
// Purpose:
// Load a the next preset
//
// Inputs:
//  pContext         - handle to instance data
//
// Outputs:
//
// Side Effects:
//
//----------------------------------------------------------------------------
int Reverb_LoadPreset(ReverbContext *pContext) {
  pContext->curPreset = pContext->nextPreset;

  if (pContext->curPreset != REVERB_PRESET_NONE) {
    const t_reverb_settings *preset = &sReverbPresets[pContext->curPreset];
    ReverbSetRoomLevel(pContext, preset->roomLevel);
    ReverbSetRoomHfLevel(pContext, preset->roomHFLevel);
    ReverbSetDecayTime(pContext, preset->decayTime);
    ReverbSetDecayHfRatio(pContext, preset->decayHFRatio);
    ReverbSetReverbLevel(pContext, preset->reverbLevel);
    ReverbSetDiffusion(pContext, preset->diffusion);
    ReverbSetDensity(pContext, preset->density);
  }

  return 0;
}

/**
 * returns the size in bytes of the value of each environmental reverb parameter
 */
int Reverb_paramValueSize(int32_t param) {
  switch (param) {
    case REVERB_PARAM_ROOM_LEVEL:
    case REVERB_PARAM_ROOM_HF_LEVEL:
    case REVERB_PARAM_REFLECTIONS_LEVEL:
    case REVERB_PARAM_REVERB_LEVEL:
      return sizeof(int16_t);  // millibel
    case REVERB_PARAM_DECAY_TIME:
    case REVERB_PARAM_REFLECTIONS_DELAY:
    case REVERB_PARAM_REVERB_DELAY:
      return sizeof(uint32_t);  // milliseconds
    case REVERB_PARAM_DECAY_HF_RATIO:
    case REVERB_PARAM_DIFFUSION:
    case REVERB_PARAM_DENSITY:
      return sizeof(int16_t);  // permille
    case REVERB_PARAM_PROPERTIES:
      return sizeof(s_reverb_settings);  // struct of all reverb properties
  }
  return sizeof(int32_t);
}

//----------------------------------------------------------------------------
// Reverb_init()
//----------------------------------------------------------------------------
// Purpose: Initialize engine with default configuration
//
// Inputs:
//  pContext:   effect engine context
//
// Outputs:
//
//----------------------------------------------------------------------------

int Reverb_init(ReverbContext *pContext) {
  ALOGV("\tReverb_init start");

  CHECK_ARG(pContext != NULL);

  if (pContext->hInstance != NULL) {
    Reverb_free(pContext);
  }

  pContext->config.inputCfg.accessMode = EFFECT_BUFFER_ACCESS_READ;
  if (pContext->auxiliary) {
    pContext->config.inputCfg.channels = AUDIO_CHANNEL_OUT_MONO;
  } else {
    pContext->config.inputCfg.channels = AUDIO_CHANNEL_OUT_STEREO;
  }
  pContext->config.inputCfg.format = EFFECT_BUFFER_FORMAT;
  pContext->config.inputCfg.samplingRate = 44100;
  pContext->config.inputCfg.bufferProvider.getBuffer = NULL;
  pContext->config.inputCfg.bufferProvider.releaseBuffer = NULL;
  pContext->config.inputCfg.bufferProvider.cookie = NULL;
  pContext->config.inputCfg.mask = EFFECT_CONFIG_ALL;
  pContext->config.outputCfg.accessMode = EFFECT_BUFFER_ACCESS_ACCUMULATE;
  pContext->config.outputCfg.channels = AUDIO_CHANNEL_OUT_STEREO;
  pContext->config.outputCfg.format = EFFECT_BUFFER_FORMAT;
  pContext->config.outputCfg.samplingRate = 44100;
  pContext->config.outputCfg.bufferProvider.getBuffer = NULL;
  pContext->config.outputCfg.bufferProvider.releaseBuffer = NULL;
  pContext->config.outputCfg.bufferProvider.cookie = NULL;
  pContext->config.outputCfg.mask = EFFECT_CONFIG_ALL;

  pContext->leftVolume = REVERB_UNIT_VOLUME;
  pContext->rightVolume = REVERB_UNIT_VOLUME;
  pContext->prevLeftVolume = REVERB_UNIT_VOLUME;
  pContext->prevRightVolume = REVERB_UNIT_VOLUME;
  pContext->volumeMode = REVERB_VOLUME_FLAT;

  LVREV_ReturnStatus_en LvrevStatus = LVREV_SUCCESS; /* Function call status */
  LVREV_ControlParams_st params;                     /* Control Parameters */
  LVREV_InstanceParams_st InstParams;                /* Instance parameters */
  LVREV_MemoryTable_st MemTab; /* Memory allocation table */
  bool bMallocFailure = LVM_FALSE;

  /* Set the capabilities */
  InstParams.MaxBlockSize = MAX_CALL_SIZE;
  InstParams.SourceFormat =
      LVM_STEREO;  // Max format, could be mono during process
  InstParams.NumDelays = LVREV_DELAYLINES_4;

  /* Allocate memory, forcing alignment */
  LvrevStatus = LVREV_GetMemoryTable(LVM_NULL, &MemTab, &InstParams);

  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_GetMemoryTable", "Reverb_init")
  if (LvrevStatus != LVREV_SUCCESS) return -EINVAL;

  ALOGV("\tCreateInstance Succesfully called LVREV_GetMemoryTable\n");

  /* Allocate memory */
  for (int i = 0; i < LVREV_NR_MEMORY_REGIONS; i++) {
    if (MemTab.Region[i].Size != 0) {
      MemTab.Region[i].pBaseAddress = calloc(1, MemTab.Region[i].Size);

      if (MemTab.Region[i].pBaseAddress == LVM_NULL) {
        ALOGV(
            "\tLVREV_ERROR :Reverb_init CreateInstance Failed to allocate "
            "%" PRIu32 " bytes for region %u\n",
            MemTab.Region[i].Size, i);
        bMallocFailure = LVM_TRUE;
      } else {
        ALOGV("\tReverb_init CreateInstance allocate %" PRIu32
              " bytes for region %u at %p\n",
              MemTab.Region[i].Size, i, MemTab.Region[i].pBaseAddress);
      }
    }
  }

  /* If one or more of the memory regions failed to allocate, free the regions
   * that were
   * succesfully allocated and return with an error
   */
  if (bMallocFailure == LVM_TRUE) {
    for (int i = 0; i < LVREV_NR_MEMORY_REGIONS; i++) {
      if (MemTab.Region[i].pBaseAddress == LVM_NULL) {
        ALOGV(
            "\tLVREV_ERROR :Reverb_init CreateInstance Failed to allocate "
            "%" PRIu32 " bytes for region %u - Not freeing\n",
            MemTab.Region[i].Size, i);
      } else {
        ALOGV(
            "\tLVREV_ERROR :Reverb_init CreateInstance Failed: but allocated "
            "%" PRIu32 " bytes for region %u at %p- free\n",
            MemTab.Region[i].Size, i, MemTab.Region[i].pBaseAddress);
        free(MemTab.Region[i].pBaseAddress);
      }
    }
    return -EINVAL;
  }
  ALOGV("\tReverb_init CreateInstance Succesfully malloc'd memory\n");

  /* Initialise */
  pContext->hInstance = LVM_NULL;

  /* Init sets the instance handle */
  LvrevStatus =
      LVREV_GetInstanceHandle(&pContext->hInstance, &MemTab, &InstParams);

  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_GetInstanceHandle", "Reverb_init")
  if (LvrevStatus != LVREV_SUCCESS) return -EINVAL;

  ALOGV(
      "\tReverb_init CreateInstance Succesfully called "
      "LVREV_GetInstanceHandle\n");

  /* Set the initial process parameters */
  /* General parameters */
  params.OperatingMode = LVM_MODE_ON;
  params.SampleRate = LVM_FS_44100;
  pContext->SampleRate = LVM_FS_44100;

  if (pContext->config.inputCfg.channels == AUDIO_CHANNEL_OUT_MONO) {
    params.SourceFormat = LVM_MONO;
  } else {
    params.SourceFormat = LVM_STEREO;
  }

  /* Reverb parameters */
  params.Level = 0;
  params.LPF = 23999;
  params.HPF = 50;
  params.T60 = 1490;
  params.Density = 100;
  params.Damping = 21;
  params.RoomSize = 100;

  pContext->SamplesToExitCount =
      (params.T60 * pContext->config.inputCfg.samplingRate) / 1000;

  /* Saved strength is used to return the exact strength that was used in the
   * set to the get
   * because we map the original strength range of 0:1000 to 1:15, and this will
   * avoid
   * quantisation like effect when returning
   */
  pContext->SavedRoomLevel = -6000;
  pContext->SavedHfLevel = 0;
  pContext->bEnabled = LVM_FALSE;
  pContext->SavedDecayTime = params.T60;
  pContext->SavedDecayHfRatio = params.Damping * 20;
  pContext->SavedDensity = params.RoomSize * 10;
  pContext->SavedDiffusion = params.Density * 10;
  pContext->SavedReverbLevel = -6000;

  /* Activate the initial settings */
  LvrevStatus = LVREV_SetControlParameters(pContext->hInstance, &params);

  LVREV_ERROR_CHECK(LvrevStatus, "LVREV_SetControlParameters", "Reverb_init")
  if (LvrevStatus != LVREV_SUCCESS) return -EINVAL;

  ALOGV(
      "\tReverb_init CreateInstance Succesfully called "
      "LVREV_SetControlParameters\n");
  ALOGV("\tReverb_init End");
  return 0;
} /* end Reverb_init */

//----------------------------------------------------------------------------
// Reverb_setParameter()
//----------------------------------------------------------------------------
// Purpose:
// Set a Reverb parameter
//
// Inputs:
//  pContext         - handle to instance data
//  pParam           - pointer to parameter
//  pValue           - pointer to value
//  vsize            - value size
//
// Outputs:
//
//----------------------------------------------------------------------------

int Reverb_setParameter(ReverbContext *pContext, void *pParam, void *pValue,
                        int vsize) {
  int status = 0;
  int16_t level;
  int16_t ratio;
  uint32_t time;
  t_reverb_settings *pProperties;
  int32_t *pParamTemp = (int32_t *)pParam;
  int32_t param = *pParamTemp++;

  // ALOGV("\tReverb_setParameter start");
  if (pContext->preset) {
    if (param != REVERB_PARAM_PRESET) {
      return -EINVAL;
    }
    if (vsize < (int)sizeof(uint16_t)) {
      android_errorWriteLog(0x534e4554, "67647856");
      return -EINVAL;
    }

    uint16_t preset = *(uint16_t *)pValue;
    ALOGV("set REVERB_PARAM_PRESET, preset %d", preset);
    if (preset > REVERB_PRESET_LAST) {
      return -EINVAL;
    }
    pContext->nextPreset = preset;
    return 0;
  }

  if (vsize < Reverb_paramValueSize(param)) {
    android_errorWriteLog(0x534e4554, "63526567");
    return -EINVAL;
  }

  switch (param) {
    case REVERB_PARAM_PROPERTIES:
      ALOGV("\tReverb_setParameter() REVERB_PARAM_PROPERTIES");
      pProperties = (t_reverb_settings *)pValue;
      ReverbSetRoomLevel(pContext, pProperties->roomLevel);
      ReverbSetRoomHfLevel(pContext, pProperties->roomHFLevel);
      ReverbSetDecayTime(pContext, pProperties->decayTime);
      ReverbSetDecayHfRatio(pContext, pProperties->decayHFRatio);
      ReverbSetReverbLevel(pContext, pProperties->reverbLevel);
      ReverbSetDiffusion(pContext, pProperties->diffusion);
      ReverbSetDensity(pContext, pProperties->density);
      break;
    case REVERB_PARAM_ROOM_LEVEL:
      level = *(int16_t *)pValue;
      ReverbSetRoomLevel(pContext, level);
      break;
    case REVERB_PARAM_ROOM_HF_LEVEL:
      level = *(int16_t *)pValue;
      ReverbSetRoomHfLevel(pContext, level);
      break;
    case REVERB_PARAM_DECAY_TIME:
      time = *(uint32_t *)pValue;
      ReverbSetDecayTime(pContext, time);
      break;
    case REVERB_PARAM_DECAY_HF_RATIO:
      ratio = *(int16_t *)pValue;
      ReverbSetDecayHfRatio(pContext, ratio);
      break;
    case REVERB_PARAM_REVERB_LEVEL:
      level = *(int16_t *)pValue;
      ReverbSetReverbLevel(pContext, level);
      break;
    case REVERB_PARAM_DIFFUSION:
      ratio = *(int16_t *)pValue;
      ReverbSetDiffusion(pContext, ratio);
      break;
    case REVERB_PARAM_DENSITY:
      ratio = *(int16_t *)pValue;
      ReverbSetDensity(pContext, ratio);
      break;
      break;
    case REVERB_PARAM_REFLECTIONS_LEVEL:
    case REVERB_PARAM_REFLECTIONS_DELAY:
    case REVERB_PARAM_REVERB_DELAY:
      break;
    default:
      ALOGV("\tLVREV_ERROR : Reverb_setParameter() invalid param %d", param);
      break;
  }
  return status;
} /* end Reverb_setParameter */

constexpr audio_channel_mask_t lvmConfigChMask[] = {
    AUDIO_CHANNEL_OUT_MONO,
    AUDIO_CHANNEL_OUT_STEREO,
    AUDIO_CHANNEL_OUT_2POINT1,
    AUDIO_CHANNEL_OUT_2POINT0POINT2,
    AUDIO_CHANNEL_OUT_QUAD,
    AUDIO_CHANNEL_OUT_QUAD_BACK,
    AUDIO_CHANNEL_OUT_QUAD_SIDE,
    AUDIO_CHANNEL_OUT_SURROUND,
    (1 << 4) - 1,
    AUDIO_CHANNEL_OUT_2POINT1POINT2,
    AUDIO_CHANNEL_OUT_3POINT0POINT2,
    AUDIO_CHANNEL_OUT_PENTA,
    (1 << 5) - 1,
    AUDIO_CHANNEL_OUT_3POINT1POINT2,
    AUDIO_CHANNEL_OUT_5POINT1,
    AUDIO_CHANNEL_OUT_5POINT1_BACK,
    AUDIO_CHANNEL_OUT_5POINT1_SIDE,
    (1 << 6) - 1,
    AUDIO_CHANNEL_OUT_6POINT1,
    (1 << 7) - 1,
    AUDIO_CHANNEL_OUT_5POINT1POINT2,
    AUDIO_CHANNEL_OUT_7POINT1,
    (1 << 8) - 1,
};

void printUsage() {
  printf("\nUsage: ");
  printf("\n     <executable> -i:<input_file> -o:<out_file> [options]\n");
  printf("\nwhere, \n     <inputfile>  is the input file name");
  printf("\n                  on which LVM effects are applied");
  printf("\n     <outputfile> processed output file");
  printf("\n     and options are mentioned below");
  printf("\n");
  printf("\n     -help (or) -h");
  printf("\n           Prints this usage information");
  printf("\n");
  printf("\n     -chMask:<channel_mask>\n");
  printf("\n         0  - AUDIO_CHANNEL_OUT_MONO");
  printf("\n         1  - AUDIO_CHANNEL_OUT_STEREO");
  printf("\n         2  - AUDIO_CHANNEL_OUT_2POINT1");
  printf("\n         3  - AUDIO_CHANNEL_OUT_2POINT0POINT2");
  printf("\n         4  - AUDIO_CHANNEL_OUT_QUAD");
  printf("\n         5  - AUDIO_CHANNEL_OUT_QUAD_BACK");
  printf("\n         6  - AUDIO_CHANNEL_OUT_QUAD_SIDE");
  printf("\n         7  - AUDIO_CHANNEL_OUT_SURROUND");
  printf("\n         8  - canonical channel index mask for 4 ch: (1 << 4) - 1");
  printf("\n         9  - AUDIO_CHANNEL_OUT_2POINT1POINT2");
  printf("\n         10 - AUDIO_CHANNEL_OUT_3POINT0POINT2");
  printf("\n         11 - AUDIO_CHANNEL_OUT_PENTA");
  printf("\n         12 - canonical channel index mask for 5 ch: (1 << 5) - 1");
  printf("\n         13 - AUDIO_CHANNEL_OUT_3POINT1POINT2");
  printf("\n         14 - AUDIO_CHANNEL_OUT_5POINT1");
  printf("\n         15 - AUDIO_CHANNEL_OUT_5POINT1_BACK");
  printf("\n         16 - AUDIO_CHANNEL_OUT_5POINT1_SIDE");
  printf("\n         17 - canonical channel index mask for 6 ch: (1 << 6) - 1");
  printf("\n         18 - AUDIO_CHANNEL_OUT_6POINT1");
  printf("\n         19 - canonical channel index mask for 7 ch: (1 << 7) - 1");
  printf("\n         20 - AUDIO_CHANNEL_OUT_5POINT1POINT2");
  printf("\n         21 - AUDIO_CHANNEL_OUT_7POINT1");
  printf("\n         22 - canonical channel index mask for 8 ch: (1 << 8) - 1");
  printf("\n         default 0");
  printf("\n     -preset:<Reverb Preset Value> ");
  printf("\n         0 - None");
  printf("\n         1 - Small Room");
  printf("\n         2 - Medium Room");
  printf("\n         3 - Large Room");
  printf("\n         4 - Medium Hall");
  printf("\n         5 - Large Hall");
  printf("\n         6 - Plate");
  printf("\n");
}

int main(int argc, const char *argv[]) {
  if (argc == 1) {
    printUsage();
    return -1;
  }

  reverbConfigParams_t revConfigParams{};  // default initialize
  const char *infile = nullptr;
  const char *outfile = nullptr;
  ReverbContext *pContext = new ReverbContext;

  pContext->hInstance = NULL;
  pContext->auxiliary = false;
  pContext->preset = false;

  for (int i = 1; i < argc; i++) {
    printf("%s ", argv[i]);
    if (!strncmp(argv[i], "-i:", 3)) {
      infile = argv[i] + 3;
    } else if (!strncmp(argv[i], "-o:", 3)) {
      outfile = argv[i] + 3;
    } else if (!strncmp(argv[i], "-fs:", 4)) {
      LVM_Fs_en samplingFreq = (LVM_Fs_en)atoi(argv[i] + 4);
      if (samplingFreq != 8000 && samplingFreq != 11025 &&
          samplingFreq != 12000 && samplingFreq != 16000 &&
          samplingFreq != 22050 && samplingFreq != 24000 &&
          samplingFreq != 32000 && samplingFreq != 44100 &&
          samplingFreq != 48000 && samplingFreq != 88200 &&
          samplingFreq != 96000 && samplingFreq != 176400 &&
          samplingFreq != 192000) {
        printf("Error: Unsupported Sampling Frequency : %d\n", samplingFreq);
        return -1;
      }
      revConfigParams.SampleRate = samplingFreq;
    } else if (!strncmp(argv[i], "-chMask:", 8)) {
      const int chMaskConfigIdx = atoi(argv[i] + 8);
      if (chMaskConfigIdx < 0 ||
          (size_t)chMaskConfigIdx >= std::size(lvmConfigChMask)) {
        ALOGE("\nError: Unsupported Channel Mask : %d\n", chMaskConfigIdx);
        return -1;
      }
      const audio_channel_mask_t chMask = lvmConfigChMask[chMaskConfigIdx];
      revConfigParams.chMask = chMask;
      revConfigParams.nrChannels = audio_channel_count_from_out_mask(chMask);
    } else if (!strncmp(argv[i], "-fch:", 5)) {
      const int16_t nrChannels = atoi(argv[i] + 5);
      revConfigParams.fChannels = nrChannels;
    } else if (!strcmp(argv[i], "-M")) {
      revConfigParams.monoMode = 1;
    } else if (!strncmp(argv[i], "-preset:", 8)) {
      const int16_t preset_val = atoi(argv[i] + 8);
      if (preset_val < REVERB_PRESET_NONE ||
          preset_val > REVERB_PRESET_PLATE)
      {
        ALOGE("\nError: Unsupported Preset Value: %d\n", preset_val);
      }
      pContext->curPreset = preset_val;
      pContext->nextPreset = preset_val;
      pContext->preset = true;
    }
  }

  if (infile == nullptr || outfile == nullptr) {
    printf("Error: missing input/output files\n");
    printUsage();
    return -1;
  }

  FILE *finp = fopen(infile, "rb");
  if (finp == nullptr) {
    printf("Cannot open input file %s", infile);
    return -1;
  }

  FILE *fout = fopen(outfile, "wb");
  if (fout == nullptr) {
    printf("Cannot open output file %s", outfile);
    fclose(finp);
    return -1;
  }
  ALOGV("\tEffectCreate - Calling Reverb_init");
  int ret = Reverb_init(pContext);
  if (ret < 0) {
    ALOGV("\tLVREV_ERROR : Reverb_init() init failed");
    delete pContext;
    return ret;
  }
  pContext->config.inputCfg.channels = revConfigParams.chMask;
  int Param = REVERB_PARAM_PRESET;
  ret = Reverb_setParameter(pContext, &Param, &pContext->curPreset,
                            sizeof(revConfigParams.revProperties));
  if (ret < 0) {
    ALOGV("\tLVREV_ERROR : Reverb_init() init failed");
    delete pContext;
    return ret;
  }

  const int channelCount =
      audio_channel_count_from_out_mask(pContext->config.inputCfg.channels);
  const int frameLength = revConfigParams.frameLength;
  const int frameSize = channelCount * sizeof(float);  // processing size
  const int ioChannelCount = revConfigParams.fChannels;
  const int ioFrameSize = ioChannelCount * sizeof(short);  // file load size
  const int maxChannelCount = std::max(channelCount, ioChannelCount);

  /*
   * Mono input will be converted to 2 channels internally in the process call
   * by copying the same data into the second channel.
   * Hence when channelCount is 1, output buffer should be allocated for
   * 2 channels. The memAllocChCount takes care of allocation of sufficient
   * memory for the output buffer.
   */
  const int memAllocChCount = (channelCount == 1 ? 2 : channelCount);

  std::vector<short> in(frameLength * maxChannelCount);
  std::vector<short> out(frameLength * maxChannelCount);
  std::vector<float> floatIn(frameLength * channelCount);
  std::vector<float> floatOut(frameLength * memAllocChCount);

  int frameCounter = 0;
  // Allocate memory for reverb process (*2 is for STEREO)
  pContext->bufferSizeIn =
      LVREV_MAX_FRAME_SIZE * sizeof(process_buffer_t) * channelCount;
  pContext->bufferSizeOut =
      LVREV_MAX_FRAME_SIZE * sizeof(process_buffer_t) * FCC_2;
  pContext->InFrames =
      (process_buffer_t *)calloc(pContext->bufferSizeIn, 1 /* size */);
  pContext->OutFrames =
      (process_buffer_t *)calloc(pContext->bufferSizeOut, 1 /* size */);
  if (ioFrameSize * frameLength == 0) {
    return 0;
  }
  while (fread(in.data(), ioFrameSize, frameLength, finp) ==
         (size_t)frameLength) {
    if (ioChannelCount != channelCount) {
      adjust_channels(in.data(), ioChannelCount, in.data(), channelCount,
                      sizeof(short), frameLength * ioFrameSize);
    }
    memcpy_to_float_from_i16(floatIn.data(), in.data(),
                             frameLength * channelCount);

    // Mono mode will replicate the first channel to all other channels.
    // This ensures all audio channels are identical. This is useful for testing
    // Bass Boost, which extracts a mono signal for processing.
    if (revConfigParams.monoMode && channelCount > 1) {
      for (int i = 0; i < frameLength; ++i) {
        auto *fp = &floatIn[i * channelCount];
        std::fill(fp + 1, fp + channelCount, *fp);  // replicate ch 0
      }
    }
#ifndef BYPASS_EXEC
    int errCode =
        process(floatIn.data(), floatOut.data(), frameLength, pContext);
    if (errCode) {
      printf("\nError: reverb process returned with %d\n", errCode);
      return errCode;
    }

    (void)frameSize;  // eliminate warning
#else
    memcpy(floatOut.data(), floatIn.data(), frameLength * frameSize);
#endif
    memcpy_to_i16_from_float(out.data(), floatOut.data(),
                             frameLength * channelCount);
    if (ioChannelCount != channelCount) {
      adjust_channels(out.data(), channelCount, out.data(), ioChannelCount,
                      sizeof(short),
                      frameLength * channelCount * sizeof(short));
    }
    (void)fwrite(out.data(), ioFrameSize, frameLength, fout);
    frameCounter += frameLength;
  }
  printf("frameCounter: [%d]\n", frameCounter);

  fclose(finp);
  fclose(fout);
  /* Free the allocated buffers */
  return 0;
}
