/*
 * Copyright (C) 2022 The Android Open Source Project
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

#pragma once
#include <limits>
#include <string>
#include <vector>
#include <aidl/android/hardware/audio/effect/BnEffect.h>

#include "effect-impl/EffectUUID.h"
#include "effect-impl/EffectTypes.h"
#include "LVM.h"

namespace aidl::android::hardware::audio::effect {

static const int FIVEBAND_NUMBANDS = 5;
static const int MAX_NUM_BANDS = 5;
static const int MAX_CALL_SIZE = 256;
static const int LVM_MAX_SESSIONS = 32;
static const int LVM_UNUSED_SESSION = std::numeric_limits<int>::max();
static const int BASS_BOOST_CUP_LOAD_ARM9E = 150;   // Expressed in 0.1 MIPS
static const int VIRTUALIZER_CUP_LOAD_ARM9E = 120;  // Expressed in 0.1 MIPS
static const int EQUALIZER_CUP_LOAD_ARM9E = 220;    // Expressed in 0.1 MIPS
static const int VOLUME_CUP_LOAD_ARM9E = 0;         // Expressed in 0.1 MIPS
static const int BUNDLE_MEM_USAGE = 25;             // Expressed in kB

static const int PRESET_CUSTOM = -1;

static const std::vector<Equalizer::BandFrequency> kEqBandFrequency = {{0, 30000, 120000},
                                                                       {1, 120001, 460000},
                                                                       {2, 460001, 1800000},
                                                                       {3, 1800001, 7000000},
                                                                       {4, 7000001, 20000000}};

/*
Frequencies in Hz
Note: If these frequencies change, please update LimitLevel values accordingly.
*/
static const LVM_UINT16 EQNB_5BandPresetsFrequencies[] = {60, 230, 910, 3600, 14000};

/* Q factor multiplied by 100 */
static const LVM_UINT16 EQNB_5BandPresetsQFactors[] = {96, 96, 96, 96, 96};

static const LVM_INT16 EQNB_5BandNormalPresets[] = {3,  0,  0,  0,  3,   /* Normal Preset */
                                                    8,  5,  -3, 5,  6,   /* Classical Preset */
                                                    15, -6, 7,  13, 10,  /* Dance Preset */
                                                    0,  0,  0,  0,  0,   /* Flat Preset */
                                                    6,  -2, -2, 6,  -3,  /* Folk Preset */
                                                    8,  -8, 13, -1, -4,  /* Heavy Metal Preset */
                                                    10, 6,  -4, 5,  8,   /* Hip Hop Preset */
                                                    8,  5,  -4, 5,  9,   /* Jazz Preset */
                                                    -6, 4,  9,  4,  -5,  /* Pop Preset */
                                                    10, 6,  -1, 8,  10}; /* Rock Preset */

static const LVM_INT16 EQNB_5BandSoftPresets[] = {3,  0, 0,  0, 3,  /* Normal Preset */
                                                  5,  3, -2, 4, 4,  /* Classical Preset */
                                                  6,  0, 2,  4, 1,  /* Dance Preset */
                                                  0,  0, 0,  0, 0,  /* Flat Preset */
                                                  3,  0, 0,  2, -1, /* Folk Preset */
                                                  4,  1, 9,  3, 0,  /* Heavy Metal Preset */
                                                  5,  3, 0,  1, 3,  /* Hip Hop Preset */
                                                  4,  2, -2, 2, 5,  /* Jazz Preset */
                                                  -1, 2, 5,  1, -2, /* Pop Preset */
                                                  5,  3, -1, 3, 5}; /* Rock Preset */

static const std::vector<Equalizer::Preset> kEqPresets = {
        {0, "Normal"},      {1, "Classical"}, {2, "Dance"}, {3, "Flat"}, {4, "Folk"},
        {5, "Heavy Metal"}, {6, "Hip Hop"},   {7, "Jazz"},  {8, "Pop"},  {9, "Rock"}};

static const Equalizer::Capability kEqCap = {.bandFrequencies = kEqBandFrequency,
                                             .presets = kEqPresets};
static const Descriptor kEqualizerDesc = {
        .common = {.id = {.type = EqualizerTypeUUID,
                          .uuid = EqualizerBundleImplUUID,
                          .proxy = std::nullopt},
                   .flags = {.type = Flags::Type::INSERT,
                             .insert = Flags::Insert::FIRST,
                             .volume = Flags::Volume::CTRL},
                   .name = "EqualizerBundle",
                   .implementor = "NXP Software Ltd."},
        .capability = Capability::make<Capability::equalizer>(kEqCap)};

// TODO: add descriptors
static const Descriptor kVirtualizerDesc;
static const Descriptor kBassBoostDesc;
static const Descriptor kVolumeDesc;

/* The following tables have been computed using the actual levels measured by the output of
 * white noise or pink noise (IEC268-1) for the EQ and BassBoost Effects. These are estimates of
 * the actual energy that 'could' be present in the given band.
 * If the frequency values in EQNB_5BandPresetsFrequencies change, these values might need to be
 * updated.
 */

static const float LimitLevel_bandEnergyCoefficient[FIVEBAND_NUMBANDS] = {7.56, 9.69, 9.59, 7.37,
                                                                          2.88};

static const float LimitLevel_bandEnergyCrossCoefficient[FIVEBAND_NUMBANDS - 1] = {126.0, 115.0,
                                                                                   125.0, 104.0};

static const float LimitLevel_bassBoostEnergyCrossCoefficient[FIVEBAND_NUMBANDS] = {
        221.21, 208.10, 28.16, 0.0, 0.0};

static const float LimitLevel_bassBoostEnergyCoefficient = 9.00;

static const float LimitLevel_virtualizerContribution = 1.9;


enum class BundleEffectType {
    BASS_BOOST,
    VIRTUALIZER,
    EQUALIZER,
    VOLUME
};

inline std::ostream& operator<<(std::ostream& out, const BundleEffectType& type) {
    switch (type) {
        case BundleEffectType::BASS_BOOST:
            return out << "BASS_BOOST";
        case BundleEffectType::VIRTUALIZER:
            return out << "VIRTUALIZER";
        case BundleEffectType::EQUALIZER:
            return out << "EQUALIZER";
        case BundleEffectType::VOLUME:
            return out << "VOLUME";
    }

    return out << "EnumBundleEffectTypeError";
}

inline std::ostream& operator<<(std::ostream& out, const LVM_ReturnStatus_en& status) {
    switch (status) {
        case LVM_SUCCESS:
            return out << "LVM_SUCCESS";
        case LVM_ALIGNMENTERROR:
            return out << "LVM_ALIGNMENTERROR";
        case LVM_NULLADDRESS:
            return out << "LVM_NULLADDRESS";
        case LVM_OUTOFRANGE:
            return out << "LVM_OUTOFRANGE";
        case LVM_INVALIDNUMSAMPLES:
            return out << "LVM_INVALIDNUMSAMPLES";
        case LVM_WRONGAUDIOTIME:
            return out << "LVM_WRONGAUDIOTIME";
        case LVM_ALGORITHMDISABLED:
            return out << "LVM_ALGORITHMDISABLED";
        case LVM_ALGORITHMPSA:
            return out << "LVM_ALGORITHMPSA";
        case LVM_RETURNSTATUS_DUMMY:
            return out << "LVM_RETURNSTATUS_DUMMY";
    }
    return out << "EnumLvmRetStatusError";
}

#define GOTO_IF_LVM_ERROR(status, tag, log)                                       \
    do {                                                                          \
        LVM_ReturnStatus_en temp = (status);                                      \
        if (temp != LVM_SUCCESS) {                                                \
            LOG(ERROR) << __func__ << " return status: " << temp << " " << (log); \
            goto tag;                                                             \
        }                                                                         \
    } while (0)

}  // namespace aidl::android::hardware::audio::effect
