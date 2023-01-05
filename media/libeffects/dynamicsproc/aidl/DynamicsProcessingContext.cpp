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

#define LOG_TAG "AHAL_DPLibEffectsContext"

#include "DynamicsProcessing.h"
#include "DynamicsProcessingContext.h"
#include <functional>
#include <sys/param.h>
#include <unordered_set>

namespace aidl::android::hardware::audio::effect {

DynamicsProcessingContext::DynamicsProcessingContext(int statusDepth,
                                                     const Parameter::Common& common)
    : EffectContext(statusDepth, common) {
    LOG(DEBUG) << __func__;
    init();
}

DynamicsProcessingContext::~DynamicsProcessingContext() {
    LOG(DEBUG) << __func__;
}

RetCode DynamicsProcessingContext::enable() {
    std::lock_guard lg(mMutex);
    if (mState != DYNAMICS_PROCESSING_STATE_INITIALIZED) {
        return RetCode::ERROR_EFFECT_LIB_ERROR;
    }
    mState = DYNAMICS_PROCESSING_STATE_ACTIVE;
    return RetCode::SUCCESS;
}

RetCode DynamicsProcessingContext::disable() {
    std::lock_guard lg(mMutex);
    if (mState != DYNAMICS_PROCESSING_STATE_ACTIVE) {
        return RetCode::ERROR_EFFECT_LIB_ERROR;
    }
    mState = DYNAMICS_PROCESSING_STATE_INITIALIZED;
    return RetCode::SUCCESS;
}

void DynamicsProcessingContext::reset() {
    std::lock_guard lg(mMutex);
    if (mDpFreq != nullptr) {
        LOG(ERROR) << __func__ << " reset xxx";
        mDpFreq.reset();
    }
}

RetCode DynamicsProcessingContext::setCommon(const Parameter::Common& common) {
    mCommon = common;
    init();
    return RetCode::SUCCESS;
}

void DynamicsProcessingContext::dpSetFreqDomainVariant_l(
        const DynamicsProcessing::EngineArchitecture& engine) {
    mDpFreq.reset(new dp_fx::DPFrequency());
    mDpFreq->init(mChannelCount, engine.preEqStage.inUse, engine.preEqStage.bandCount,
                  engine.mbcStage.inUse, engine.mbcStage.bandCount, engine.postEqStage.inUse,
                  engine.postEqStage.bandCount, engine.limiterInUse);

    int32_t sampleRate = mCommon.input.base.sampleRate;
    int32_t minBlockSize = (int32_t)dp_fx::DPFrequency::getMinBockSize();
    int32_t desiredBlock =
            engine.preferredProcessingDurationMs * sampleRate / 1000.0f;
    int32_t currentBlock = desiredBlock;
    LOG(INFO) << __func__ << " sampleRate " << sampleRate << " desiredBlock length "
              << engine.preferredProcessingDurationMs << " ms (" << desiredBlock << "samples)";
    if (desiredBlock < minBlockSize) {
        currentBlock = minBlockSize;
    } else if (!powerof2(desiredBlock)) {
        //find next highest power of 2.
        currentBlock = 1 << (32 - __builtin_clz(desiredBlock));
    }
    mDpFreq->configure(currentBlock, currentBlock >> 1, sampleRate);
}

RetCode DynamicsProcessingContext::setEngineArchitecture(
        const DynamicsProcessing::EngineArchitecture& engineArchitecture) {
    RETURN_VALUE_IF(!validateEngineConfig(engineArchitecture), RetCode::ERROR_ILLEGAL_PARAMETER,
                    "illegalEngineConfig");

    std::lock_guard lg(mMutex);
    if (mEngineArchitecture == engineArchitecture) {
        LOG(INFO) << __func__ << " no change to engine" << engineArchitecture.toString();
        return RetCode::SUCCESS;
    }
    if (!mEngineInited ||
        mEngineArchitecture.resolutionPreference != engineArchitecture.resolutionPreference) {
        if (engineArchitecture.resolutionPreference ==
            DynamicsProcessing::ResolutionPreference::FAVOR_FREQUENCY_RESOLUTION) {
            dpSetFreqDomainVariant_l(engineArchitecture);
        } else {
            LOG(WARNING) << __func__ << toString(engineArchitecture.resolutionPreference)
                         << " not available now";
        }
        mEngineInited = true;
    }
    mEngineArchitecture = engineArchitecture;
    LOG(INFO) << __func__ << engineArchitecture.toString();
    return RetCode::SUCCESS;
}

RetCode DynamicsProcessingContext::setPreEq(
        const std::vector<DynamicsProcessing::ChannelConfig>& eqChannels) {
    RetCode ret = RetCode::SUCCESS;
    std::unordered_set<int> channelSet;

    std::lock_guard lg(mMutex);
    RETURN_VALUE_IF(!mEngineArchitecture.preEqStage.inUse, RetCode::ERROR_ILLEGAL_PARAMETER,
                    "preEqNotInUse");
    for (auto& it : eqChannels) {
        if (0 != channelSet.count(it.channel)) {
            LOG(WARNING) << __func__ << " duplicated channel " << it.channel;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
        } else {
            channelSet.insert(it.channel);
        }
        if (it.channel < 0 || it.channel >= mChannelCount) {
            LOG(WARNING) << __func__ << " skip illegal ChannelConfig " << it.toString() << " max "
                         << mChannelCount;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;;
        }
        auto preEq = getPreEq_l(it.channel);
        if (!preEq) {
            LOG(WARNING) << __func__ << " preEq channel " << it.channel << " not exist";
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;
        }
        if (preEq->isEnabled() != it.enable) {
            LOG(INFO) << __func__ << it.toString();
            preEq->setEnabled(it.enable);
        }
    }
    return ret;
}

RetCode DynamicsProcessingContext::setPreEqBand(
        const std::vector<DynamicsProcessing::EqBandConfig>& eqBands) {
    RetCode ret = RetCode::SUCCESS;
    std::set<std::pair<int /* channel */, int /* band */>> bandSet;

    std::lock_guard lg(mMutex);
    RETURN_VALUE_IF(!mEngineArchitecture.preEqStage.inUse, RetCode::ERROR_ILLEGAL_PARAMETER,
                    "preEqNotInUse");
    auto maxBand = mEngineArchitecture.preEqStage.bandCount;
    for (auto& it : eqBands) {
        if (0 != bandSet.count({it.channel, it.band})) {
            LOG(WARNING) << __func__ << " duplicated channel " << it.channel << " band " << it.band;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
        } else {
            bandSet.insert({it.channel, it.band});
        }
        if (!validateEqBandConfig(it, mChannelCount, maxBand)) {
            LOG(WARNING) << __func__ << " skip invalid band " << it.toString();
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;;
        }
        auto preEq = getPreEq_l(it.channel);
        if (!preEq || !preEq->isEnabled()) {
            LOG(WARNING) << __func__ << " preEq channel " << it.channel << " not enabled";
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;
        }
        dp_fx::DPEqBand eqBand;
        eqBand.init(it.enable, it.cutoffFrequencyHz, it.gainDb);
        preEq->setBand(it.band, eqBand);
        LOG(INFO) << __func__ << it.toString();
    }
    return ret;
}

RetCode DynamicsProcessingContext::setPostEq(
        const std::vector<DynamicsProcessing::ChannelConfig>& eqChannels) {
    RetCode ret = RetCode::SUCCESS;
    std::unordered_set<int> channelSet;

    std::lock_guard lg(mMutex);
    RETURN_VALUE_IF(!mEngineArchitecture.postEqStage.inUse, RetCode::ERROR_ILLEGAL_PARAMETER,
                    "postEqNotInUse");
    for (auto& it : eqChannels) {
        if (0 != channelSet.count(it.channel)) {
            LOG(WARNING) << __func__ << " duplicated channel " << it.channel;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
        } else {
            channelSet.insert(it.channel);
        }
        if (it.channel < 0 || it.channel >= mChannelCount) {
            LOG(WARNING) << __func__ << " skip illegal ChannelConfig " << it.toString() << " max "
                         << mChannelCount;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;;
        }
        auto postEq = getPostEq_l(it.channel);
        if (!postEq) {
            LOG(WARNING) << __func__ << " postEq channel " << it.channel << " not exist";
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;
        }
        if (postEq->isEnabled() != it.enable) {
            LOG(INFO) << __func__ << it.toString();
            postEq->setEnabled(it.enable);
        }
    }
    return ret;
}

RetCode DynamicsProcessingContext::setPostEqBand(
        const std::vector<DynamicsProcessing::EqBandConfig>& eqBands) {
    RetCode ret = RetCode::SUCCESS;
    std::set<std::pair<int /* channel */, int /* band */>> bandSet;

    std::lock_guard lg(mMutex);
    RETURN_VALUE_IF(!mEngineArchitecture.postEqStage.inUse, RetCode::ERROR_ILLEGAL_PARAMETER,
                    "postEqNotInUse");
    auto maxBand = mEngineArchitecture.postEqStage.bandCount;
    for (auto& it : eqBands) {
        if (0 != bandSet.count({it.channel, it.band})) {
            LOG(WARNING) << __func__ << " duplicated channel " << it.channel << " band " << it.band;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
        } else {
            bandSet.insert({it.channel, it.band});
        }
        if (!validateEqBandConfig(it, mChannelCount, maxBand)) {
            LOG(WARNING) << __func__ << " skip invalid band " << it.toString();
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;;
        }
        auto postEq = getPostEq_l(it.channel);
        if (!postEq || !postEq->isEnabled()) {
            LOG(WARNING) << __func__ << " postEq channel " << it.channel << " not enabled";
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;
        }
        dp_fx::DPEqBand eqBand;
        eqBand.init(it.enable, it.cutoffFrequencyHz, it.gainDb);
        postEq->setBand(it.band, eqBand);
        LOG(INFO) << __func__ << it.toString();
    }
    return ret;
}

RetCode DynamicsProcessingContext::setMbc(
        const std::vector<DynamicsProcessing::ChannelConfig>& mbcs) {
    RetCode ret = RetCode::SUCCESS;
    std::unordered_set<int> channelSet;

    std::lock_guard lg(mMutex);
    RETURN_VALUE_IF(!mEngineArchitecture.mbcStage.inUse, RetCode::ERROR_ILLEGAL_PARAMETER,
                    "mbcNotInUse");
    for (auto& it : mbcs) {
        if (0 != channelSet.count(it.channel)) {
            LOG(WARNING) << __func__ << " duplicated channel " << it.channel;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
        } else {
            channelSet.insert(it.channel);
        }
        auto mbc = getMbc_l(it.channel);
        if (!mbc) {
            LOG(WARNING) << __func__ << " postEq channel does not exist" << it.channel;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;
        }
        if (mbc->isEnabled() != it.enable) {
            LOG(INFO) << __func__ << it.toString();
            mbc->setEnabled(it.enable);
        }
    }
    return ret;
}

RetCode DynamicsProcessingContext::setMbcBand(
        const std::vector<DynamicsProcessing::MbcBandConfig>& bands) {
    RetCode ret = RetCode::SUCCESS;
    std::set<std::pair<int /* channel */, int /* band */>> bandSet;

    std::lock_guard lg(mMutex);
    RETURN_VALUE_IF(!mEngineArchitecture.mbcStage.inUse, RetCode::ERROR_ILLEGAL_PARAMETER,
                    "mbcNotInUse");
    auto maxBand = mEngineArchitecture.mbcStage.bandCount;
    for (auto& it : bands) {
        if (0 != bandSet.count({it.channel, it.band})) {
            LOG(WARNING) << __func__ << " duplicated channel " << it.channel << " band " << it.band;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
        } else {
            bandSet.insert({it.channel, it.band});
        }
        if (!validateMbcBandConfig(it, mChannelCount, maxBand)) {
            LOG(WARNING) << __func__ << " skip invalid band " << it.toString();
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;;
        }
        auto mbc = getMbc_l(it.channel);
        if (!mbc || !mbc->isEnabled()) {
            LOG(WARNING) << __func__ << " MBC in channel " << it.channel << " does not exist";
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;
        }
        dp_fx::DPMbcBand mbcBand;
        mbcBand.init(it.enable, it.cutoffFrequencyHz, it.attackTimeMs, it.releaseTimeMs, it.ratio,
                     it.thresholdDb, it.kneeWidthDb, it.noiseGateThresholdDb, it.expanderRatio,
                     it.preGainDb, it.postGainDb);
        mbc->setBand(it.band, mbcBand);
        LOG(INFO) << __func__ << it.toString();
    }
    return ret;
}

RetCode DynamicsProcessingContext::setLimiter(
        const std::vector<DynamicsProcessing::LimiterConfig>& limiters) {
    RetCode ret = RetCode::SUCCESS;
    std::unordered_set<int> channelSet;

    std::lock_guard lg(mMutex);
    RETURN_VALUE_IF(!mEngineArchitecture.limiterInUse, RetCode::ERROR_ILLEGAL_PARAMETER,
                    "limiterNotInUse");
    for (auto& it : limiters) {
        if (0 != channelSet.count(it.channel)) {
            LOG(WARNING) << __func__ << " duplicated channel " << it.channel;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
        } else {
            channelSet.insert(it.channel);
        }
        if (!validateLimiterConfig(it, mChannelCount)) {
            LOG(WARNING) << __func__ << " skip invalid limiter " << it.toString();
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;;
        }
        auto channel = getChannel_l(it.channel);
        if (!channel) {
            LOG(WARNING) << __func__ << " channel " << it.channel << " not exist";
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;
        }
        dp_fx::DPLimiter limiter;
        limiter.init(mEngineArchitecture.limiterInUse, it.enable, it.linkGroup, it.attackTimeMs,
                     it.releaseTimeMs, it.ratio, it.thresholdDb, it.postGainDb);
        channel->setLimiter(limiter);
        LOG(INFO) << __func__ << it.toString();
    }
    return ret;
}

RetCode DynamicsProcessingContext::setInputGain(
        const std::vector<DynamicsProcessing::InputGain>& inputGain) {
    RetCode ret = RetCode::SUCCESS;
    std::unordered_set<int> channelSet;

    std::lock_guard lg(mMutex);
    for (auto& it : inputGain) {
        if (0 != channelSet.count(it.channel)) {
            LOG(WARNING) << __func__ << " duplicated channel " << it.channel;
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
        } else {
            channelSet.insert(it.channel);
        }
        if (it.channel >= mChannelCount || it.channel < 0) {
            LOG(WARNING) << __func__ << " skip invalid inputGain " << it.toString();
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;;
        }
        auto channel = getChannel_l(it.channel);
        if (!channel) {
            LOG(WARNING) << __func__ << " channel " << it.channel << " does not exist";
            ret = RetCode::ERROR_ILLEGAL_PARAMETER;
            continue;
        }
        channel->setInputGain(it.gainDb);
        LOG(INFO) << __func__ << it.toString();
    }
    return ret;
}

DynamicsProcessing::EngineArchitecture DynamicsProcessingContext::getEngineArchitecture() {
    std::lock_guard lg(mMutex);
    LOG(INFO) << __func__ << mEngineArchitecture.toString();
    return mEngineArchitecture;
};
std::vector<DynamicsProcessing::ChannelConfig> DynamicsProcessingContext::getPreEq() {
    return getChannelConfig(StageType::PREEQ);
}
std::vector<DynamicsProcessing::ChannelConfig> DynamicsProcessingContext::getPostEq() {
    return getChannelConfig(StageType::POSTEQ);
}
std::vector<DynamicsProcessing::EqBandConfig> DynamicsProcessingContext::getPreEqBand() {
    return getEqBandConfigs(StageType::PREEQ);
}
std::vector<DynamicsProcessing::EqBandConfig> DynamicsProcessingContext::getPostEqBand() {
    return getEqBandConfigs(StageType::POSTEQ);
}
std::vector<DynamicsProcessing::ChannelConfig> DynamicsProcessingContext::getMbc() {
    return getChannelConfig(StageType::MBC);
}
std::vector<DynamicsProcessing::MbcBandConfig> DynamicsProcessingContext::getMbcBand() {
    std::vector<DynamicsProcessing::MbcBandConfig> bands;

    std::lock_guard lg(mMutex);
    auto maxBand = mEngineArchitecture.mbcStage.bandCount;
    for (int32_t ch = 0; ch < mChannelCount; ch++) {
        auto mbc = getMbc_l(ch);
        if (!mbc) {
            continue;
        }
        for (int32_t bandId = 0; bandId < maxBand; bandId++) {
            auto band = mbc->getBand(bandId);
            if (!band) {
                continue;
            }
            bands.push_back({.channel = ch,
                             .band = bandId,
                             .enable = band->isEnabled(),
                             .cutoffFrequencyHz = band->getCutoffFrequency(),
                             .attackTimeMs = band->getAttackTime(),
                             .releaseTimeMs = band->getReleaseTime(),
                             .ratio = band->getRatio(),
                             .thresholdDb = band->getThreshold(),
                             .kneeWidthDb = band->getKneeWidth(),
                             .noiseGateThresholdDb = band->getNoiseGateThreshold(),
                             .expanderRatio = band->getExpanderRatio(),
                             .preGainDb = band->getPreGain(),
                             .postGainDb = band->getPostGain()});
        }
    }
    return bands;
}

std::vector<DynamicsProcessing::LimiterConfig> DynamicsProcessingContext::getLimiter() {
    std::vector<DynamicsProcessing::LimiterConfig> ret;

    std::lock_guard lg(mMutex);
    for (int32_t ch = 0; ch < mChannelCount; ch++) {
        auto limiter = getLimiter_l(ch);
        if (!limiter) {
            continue;
        }
        ret.push_back({.channel = ch,
                       .enable = limiter->isEnabled(),
                       .linkGroup = static_cast<int32_t>(limiter->getLinkGroup()),
                       .attackTimeMs = limiter->getAttackTime(),
                       .releaseTimeMs = limiter->getReleaseTime(),
                       .ratio = limiter->getRatio(),
                       .thresholdDb = limiter->getThreshold(),
                       .postGainDb = limiter->getPostGain()});
    }
    return ret;
}
std::vector<DynamicsProcessing::InputGain> DynamicsProcessingContext::getInputGain() {
    std::vector<DynamicsProcessing::InputGain> ret;

    std::lock_guard lg(mMutex);
    for (int32_t ch = 0; ch < mChannelCount; ch++) {
        auto channel = getChannel_l(ch);
        if (!channel) {
            continue;
        }
        ret.push_back({.channel = ch, .gainDb = channel->getInputGain()});
    }
    return ret;
}

IEffect::Status DynamicsProcessingContext::lvmProcess(float* in, float* out, int samples) {
    LOG(DEBUG) << __func__ << " in " << in << " out " << out << " sample " << samples;

    IEffect::Status status = {EX_NULL_POINTER, 0, 0};
    RETURN_VALUE_IF(!in, status, "nullInput");
    RETURN_VALUE_IF(!out, status, "nullOutput");
    status = {EX_ILLEGAL_STATE, 0, 0};

    LOG(DEBUG) << __func__ << " start processing";
    {
        std::lock_guard lg(mMutex);
        RETURN_VALUE_IF(mState != DynamicsProcessingState::DYNAMICS_PROCESSING_STATE_ACTIVE, status,
                        "notInActiveState");
        RETURN_VALUE_IF(!mDpFreq, status, "engineNotInited");
        mDpFreq->processSamples(in, out, samples);
    }
    return {STATUS_OK, samples, samples};
}

void DynamicsProcessingContext::init() {
    std::lock_guard lg(mMutex);
    mState = DYNAMICS_PROCESSING_STATE_INITIALIZED;
    mChannelCount =
            ::android::hardware::audio::common::getChannelCount(mCommon.input.base.channelMask);
}

dp_fx::DPChannel* DynamicsProcessingContext::getChannel_l(int32_t channel) {
    RETURN_VALUE_IF(mDpFreq == nullptr, nullptr, "DPFreqNotInited");

    return mDpFreq->getChannel(channel);
}

dp_fx::DPEq* DynamicsProcessingContext::getPreEq_l(int32_t ch) {
    auto channel = getChannel_l(ch);
    RETURN_VALUE_IF(channel == nullptr, nullptr, "ChannelNotExist");

    return channel->getPreEq();
}

dp_fx::DPEq* DynamicsProcessingContext::getPostEq_l(int32_t ch) {
    auto channel = getChannel_l(ch);
    RETURN_VALUE_IF(channel == nullptr, nullptr, "ChannelNotExist");

    return channel->getPostEq();
}

dp_fx::DPMbc* DynamicsProcessingContext::getMbc_l(int32_t ch) {
    auto channel = getChannel_l(ch);
    RETURN_VALUE_IF(channel == nullptr, nullptr, "ChannelNotExist");

    return channel->getMbc();
}

dp_fx::DPLimiter* DynamicsProcessingContext::getLimiter_l(int32_t ch) {
    auto channel = getChannel_l(ch);
    RETURN_VALUE_IF(channel == nullptr, nullptr, "ChannelNotExist");

    return channel->getLimiter();
}

dp_fx::DPBandStage* DynamicsProcessingContext::getStageWithType_l(
        DynamicsProcessingContext::StageType type, int32_t ch) {
    switch (type) {
        case StageType::PREEQ: {
            return getEqWithType_l(type, ch);
        }
        case StageType::POSTEQ: {
            return getEqWithType_l(type, ch);
        }
        case StageType::MBC: {
            return getMbc_l(ch);
        }
        case StageType::LIMITER: {
            return nullptr;
        }
    }
}

dp_fx::DPEq* DynamicsProcessingContext::getEqWithType_l(DynamicsProcessingContext::StageType type,
                                                        int32_t ch) {
    switch (type) {
        case StageType::PREEQ: {
            return getPreEq_l(ch);
        }
        case StageType::POSTEQ: {
            return getPostEq_l(ch);
        }
        default: {
            return nullptr;
        }
    }
}

std::vector<DynamicsProcessing::ChannelConfig> DynamicsProcessingContext::getChannelConfig(
        StageType type) {
    std::vector<DynamicsProcessing::ChannelConfig> ret;

    std::lock_guard lg(mMutex);
    for (int32_t ch = 0; ch < mChannelCount; ch++) {
        auto stage = getStageWithType_l(type, ch);
        if (!stage) {
            continue;
        }
        ret.push_back({.channel = ch, .enable = stage->isEnabled()});
    }
    return ret;
}

std::vector<DynamicsProcessing::EqBandConfig> DynamicsProcessingContext::getEqBandConfigs(
        StageType type) {
    std::vector<DynamicsProcessing::EqBandConfig> eqBands;

    std::lock_guard lg(mMutex);
    auto maxBand = mEngineArchitecture.preEqStage.bandCount;
    for (int32_t ch = 0; ch < mChannelCount; ch++) {
        auto eq = getEqWithType_l(type, ch);
        if (!eq) {
            continue;
        }
        for (int32_t bandId = 0; bandId < maxBand; bandId++) {
            auto band = eq->getBand(bandId);
            if (!band) {
                continue;
            }
            eqBands.push_back({.channel = ch,
                               .band = bandId,
                               .enable = band->isEnabled(),
                               .cutoffFrequencyHz = band->getCutoffFrequency(),
                               .gainDb = band->getGain()});
        }
    }
    return eqBands;
}

/**
 * When StageEnablement not in use, doesn't care about the bandCount; if it's in use, bandCount
 * needs to be positive.
 */
bool DynamicsProcessingContext::validateStageEnablement(
        const DynamicsProcessing::StageEnablement& enablement) {
    return !enablement.inUse || (enablement.inUse && enablement.bandCount > 0);
}

bool DynamicsProcessingContext::validateEngineConfig(
        const DynamicsProcessing::EngineArchitecture& engine) {
    return engine.preferredProcessingDurationMs >= 0 &&
           validateStageEnablement(engine.preEqStage) &&
           validateStageEnablement(engine.postEqStage) && validateStageEnablement(engine.mbcStage);
}

bool DynamicsProcessingContext::validateCutoffFrequency(float freq) {
    return freq >= DynamicsProcessingImpl::kCapability.minCutOffFreq &&
           freq <= DynamicsProcessingImpl::kCapability.maxCutOffFreq;
}

bool DynamicsProcessingContext::validateEqBandConfig(const DynamicsProcessing::EqBandConfig& band,
                                                     int maxChannel, int maxBand) {
    return band.channel >= 0 && band.channel < maxChannel && band.band >= 0 &&
           band.band < maxBand && validateCutoffFrequency(band.cutoffFrequencyHz);
}

bool DynamicsProcessingContext::validateMbcBandConfig(const DynamicsProcessing::MbcBandConfig& band,
                                                      int maxChannel, int maxBand) {
    return band.channel >= 0 && band.channel < maxChannel && band.band >= 0 &&
           band.band < maxBand && validateCutoffFrequency(band.cutoffFrequencyHz) &&
           band.attackTimeMs >= 0 && band.releaseTimeMs >= 0 && band.ratio >= 0 &&
           band.thresholdDb <= 0 && band.kneeWidthDb <= 0 && band.noiseGateThresholdDb <= 0 &&
           band.expanderRatio >= 0;
}

bool DynamicsProcessingContext::validateLimiterConfig(
        const DynamicsProcessing::LimiterConfig& limiter, int maxChannel) {
    return limiter.channel >= 0 && limiter.channel < maxChannel && limiter.attackTimeMs >= 0 &&
           limiter.releaseTimeMs >= 0 && limiter.ratio >= 0 && limiter.thresholdDb <= 0;
}

}  // namespace aidl::android::hardware::audio::effect
