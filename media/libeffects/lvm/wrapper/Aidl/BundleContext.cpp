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

#define LOG_TAG "BundleContext"
#include <Utils.h>
#include "BundleContext.h"

using aidl::android::media::audio::common::AudioChannelLayout;
using aidl::android::media::audio::common::AudioDeviceType;
using aidl::android::media::audio::common::AudioMode;
using aidl::android::media::audio::common::AudioSource;
using android::hardware::audio::common::getFrameSizeInBytes;

namespace aidl::android::hardware::audio::effect {

RetCode BundleContext::init() {
    mOutputDevice = AudioDeviceType::NONE;
    mVirtualizerForcedDevice = AudioDeviceType::NONE;
    for (int i = 0; i < FIVEBAND_NUMBANDS; i++) {
        mBandGaindB[i] = EQNB_5BandSoftPresets[i];
    }

    // allocate lvm instance
    LVM_ReturnStatus_en status;
    LVM_InstParams_t params = {.BufferMode = LVM_UNMANAGED_BUFFERS,
                               .MaxBlockSize = MAX_CALL_SIZE,
                               .EQNB_NumBands = MAX_NUM_BANDS,
                               .PSA_Included = LVM_PSA_ON};
    status = LVM_GetInstanceHandle(&mInstance, &params);
    GOTO_IF_LVM_ERROR(status, deinit, "LVM_GetInstanceHandleFailed");

    // set control
    LVM_ControlParams_t controlParams;
    initControlParameter(controlParams);
    status = LVM_SetControlParameters(mInstance, &controlParams);
    GOTO_IF_LVM_ERROR(status, deinit, "LVM_SetControlParametersFailed");

    /* Set the headroom parameters */
    LVM_HeadroomParams_t headroomParams;
    initHeadroomParameter(headroomParams);
    status = LVM_SetHeadroomParams(mInstance, &headroomParams);
    GOTO_IF_LVM_ERROR(status, deinit, "LVM_SetHeadroomParamsFailed");

    return RetCode::SUCCESS;

deinit:
    deInit();
    return RetCode::ERROR_EFFECT_LIB_ERROR;
}

void BundleContext::deInit() {
    if (mInstance) {
        LVM_DelInstanceHandle(&mInstance);
        mInstance = nullptr;
    }
}


void BundleContext::setCommonParameter(const Parameter::Common& common) {
    // TODO: update parameters to LVM lib
    mCommon = common;
}

LVM_INT16 BundleContext::LVC_ToDB_s32Tos16(LVM_INT32 Lin_fix) {
    LVM_INT16 db_fix;
    LVM_INT16 Shift;
    LVM_INT16 SmallRemainder;
    LVM_UINT32 Remainder = (LVM_UINT32)Lin_fix;

    /* Count leading bits, 1 cycle in assembly*/
    for (Shift = 0; Shift < 32; Shift++) {
        if ((Remainder & 0x80000000U) != 0) {
            break;
        }
        Remainder = Remainder << 1;
    }

    /*
     * Based on the approximation equation (for Q11.4 format):
     *
     * dB = -96 * Shift + 16 * (8 * Remainder - 2 * Remainder^2)
     */
    db_fix = (LVM_INT16)(-96 * Shift); /* Six dB steps in Q11.4 format*/
    SmallRemainder = (LVM_INT16)((Remainder & 0x7fffffff) >> 24);
    db_fix = (LVM_INT16)(db_fix + SmallRemainder);
    SmallRemainder = (LVM_INT16)(SmallRemainder * SmallRemainder);
    db_fix = (LVM_INT16)(db_fix - (LVM_INT16)((LVM_UINT16)SmallRemainder >> 9));

    /* Correct for small offset */
    db_fix = (LVM_INT16)(db_fix - 5);

    return db_fix;
}

int16_t BundleContext::VolToDb(uint32_t vol) {
    int16_t dB;

    dB = LVC_ToDB_s32Tos16(vol << 7);
    dB = (dB + 8) >> 4;
    dB = (dB < -96) ? -96 : dB;

    return dB;
}

RetCode BundleContext::setVolume(const Parameter::VolumeStereo& volume) {
    LVM_ControlParams_t activeParams;
    LVM_ReturnStatus_en status = LVM_SUCCESS;

    // Convert volume to dB
    int leftdB = VolToDb(volume.left);
    int rightdB = VolToDb(volume.right);
    int maxdB = std::max(leftdB, rightdB);
    int pandB = rightdB - leftdB;
    // TODO: add volume effect implementation here:
    // android::VolumeSetVolumeLevel(pContext, (int16_t)(maxdB * 100));
    LOG(DEBUG) << __func__ << " pandB: " << pandB << " maxdB " << maxdB;

    status = LVM_GetControlParameters(mInstance, &activeParams);
    RETURN_IF_LVM_ERROR(status, RetCode::ERROR_EFFECT_LIB_ERROR, "LVM_GetControlParametersError");

    activeParams.VC_Balance = pandB;

    status = LVM_SetControlParameters(mInstance, &activeParams);
    RETURN_IF_LVM_ERROR(status, RetCode::ERROR_EFFECT_LIB_ERROR, "LVM_SetControlParametersError");

    mVolume = volume;
    return RetCode::SUCCESS;
}
RetCode BundleContext::setEqPreset(const int& presetIdx) {
    if (presetIdx < 0 || presetIdx >= kEqPresets.size()) {
        return RetCode::ERROR_ILLEGAL_PARAMETER;
    }
    mCurPresetIdx = presetIdx;
    return RetCode::SUCCESS;
}

RetCode BundleContext::setEqBandLevels(const std::vector<Equalizer::BandLevel>& bandLevels) {
    if (bandLevels.size() > FIVEBAND_NUMBANDS) {
        LOG(ERROR) << __func__ << " return because size exceed " << FIVEBAND_NUMBANDS;
        return RetCode::ERROR_ILLEGAL_PARAMETER;
    }
    RetCode ret = RetCode::SUCCESS;
    for (auto& it : bandLevels) {
        if (it.index >= FIVEBAND_NUMBANDS || it.index < 0 ) {
            LOG(ERROR) << __func__ << " index illegal, skip: " << it.index << " - " << it.levelMb;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
        }
        mBandGaindB[it.index] = it.levelMb;
    }
    return ret;
}

std::vector<Equalizer::BandLevel> BundleContext::getEqBandLevels() {
    std::vector<Equalizer::BandLevel> bandLevels;
    for (int i = 0; i < FIVEBAND_NUMBANDS; i++) {
        bandLevels.push_back({i, mBandGaindB[i]});
    }
    return bandLevels;
}

/* Set the initial process parameters */
void BundleContext::initControlParameter(LVM_ControlParams_t& params) {
    /* General parameters */
    LVM_EQNB_BandDef_t BandDefs[MAX_NUM_BANDS];

    params.OperatingMode = LVM_MODE_ON;
    params.SampleRate = LVM_FS_44100;
    params.SourceFormat = LVM_STEREO;
    params.SpeakerType = LVM_HEADPHONES;

    /* Concert Sound parameters */
    params.VirtualizerOperatingMode = LVM_MODE_OFF;
    params.VirtualizerType = LVM_CONCERTSOUND;
    params.VirtualizerReverbLevel = 100;
    params.CS_EffectLevel = LVM_CS_EFFECT_NONE;

    /* N-Band Equaliser parameters */
    for (int i = 0; i < FIVEBAND_NUMBANDS; i++) {
        BandDefs[i].Frequency = EQNB_5BandPresetsFrequencies[i];
        BandDefs[i].QFactor = EQNB_5BandPresetsQFactors[i];
        BandDefs[i].Gain = EQNB_5BandSoftPresets[i];
        LOG(ERROR) << __func__ << " " << BandDefs[i].Frequency << " " << BandDefs[i].QFactor << " " << BandDefs[i].Gain;
    }
    params.EQNB_OperatingMode = LVM_EQNB_OFF;
    params.EQNB_NBands = FIVEBAND_NUMBANDS;
    params.pEQNB_BandDefinition = &BandDefs[0];


    /* Volume Control parameters */
    params.VC_EffectLevel = 0;
    params.VC_Balance = 0;

    /* Treble Enhancement parameters */
    params.TE_OperatingMode = LVM_TE_OFF;
    params.TE_EffectLevel = 0;

    /* PSA Control parameters */
    params.PSA_Enable = LVM_PSA_OFF;
    params.PSA_PeakDecayRate = (LVM_PSA_DecaySpeed_en)0;

    /* Bass Enhancement parameters */
    params.BE_OperatingMode = LVM_BE_OFF;
    params.BE_EffectLevel = 0;
    params.BE_CentreFreq = LVM_BE_CENTRE_90Hz;
    params.BE_HPF = LVM_BE_HPF_ON;

    /* PSA Control parameters */
    params.PSA_Enable = LVM_PSA_OFF;
    params.PSA_PeakDecayRate = LVM_PSA_SPEED_MEDIUM;

    /* TE Control parameters */
    params.TE_OperatingMode = LVM_TE_OFF;
    params.TE_EffectLevel = 0;

    params.NrChannels = audio_channel_count_from_out_mask(AUDIO_CHANNEL_OUT_STEREO);
    params.ChMask = AUDIO_CHANNEL_OUT_STEREO;
}

void BundleContext::initHeadroomParameter(LVM_HeadroomParams_t& params) {
    LVM_HeadroomBandDef_t HeadroomBandDef[LVM_HEADROOM_MAX_NBANDS];
        
    HeadroomBandDef[0].Limit_Low = 20;
    HeadroomBandDef[0].Limit_High = 4999;
    HeadroomBandDef[0].Headroom_Offset = 0;
    HeadroomBandDef[1].Limit_Low = 5000;
    HeadroomBandDef[1].Limit_High = 24000;
    HeadroomBandDef[1].Headroom_Offset = 0;
    params.pHeadroomDefinition = &HeadroomBandDef[0];
    params.Headroom_OperatingMode = LVM_HEADROOM_ON;
    params.NHeadroomBands = 2;
}

}  // namespace aidl::android::hardware::audio::effect
