/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <aidl/android/hardware/audio/effect/BnEffect.h>

#include "effect-impl/EffectImpl.h"
#include "effect-impl/EffectUUID.h"
#include "DynamicsProcessingContext.h"

namespace aidl::android::hardware::audio::effect {

class DynamicsProcessingImpl final : public EffectImpl {
  public:
    static const std::string kEffectName;
    static const Descriptor kDescriptor;
    static const Capability kCapability;

    DynamicsProcessingImpl() { LOG(DEBUG) << __func__; }
    ~DynamicsProcessingImpl() {
        cleanUp();
        LOG(DEBUG) << __func__;
    }

    ndk::ScopedAStatus open(const Parameter::Common& common,
                            const std::optional<Parameter::Specific>& specific,
                            OpenEffectReturn* ret) override;
    ndk::ScopedAStatus commandImpl(CommandId command) override;
    ndk::ScopedAStatus getDescriptor(Descriptor* _aidl_return) override;
    ndk::ScopedAStatus setParameterSpecific(const Parameter::Specific& specific) override;
    ndk::ScopedAStatus getParameterSpecific(const Parameter::Id& id,
                                            Parameter::Specific* specific) override;
    IEffect::Status effectProcessImpl(float* in, float* out, int process) override;
    std::shared_ptr<EffectContext> createContext(const Parameter::Common& common) override;
    RetCode releaseContext() override;

    std::shared_ptr<EffectContext> getContext() override { return mContext; }
    std::string getEffectName() override { return kEffectName; }

  private:
    std::shared_ptr<DynamicsProcessingContext> mContext;
    ndk::ScopedAStatus getParameterDynamicsProcessing(const DynamicsProcessing::Tag& tag,
                                                      Parameter::Specific* specific);

    int locateMinMaxForTag(DynamicsProcessing::Tag tag);
    bool isParamInRange(const Parameter::Specific& specific);
    bool isEngineConfigValid(const DynamicsProcessing::EngineArchitecture& cfg,
                             const DynamicsProcessing::EngineArchitecture& min,
                             const DynamicsProcessing::EngineArchitecture& max);
    bool isChannelConfigValid(const std::vector<DynamicsProcessing::ChannelConfig>& cfgs,
                              const DynamicsProcessing::ChannelConfig& min,
                              const DynamicsProcessing::ChannelConfig& max);
    template <typename T>
    bool isInLimits(const T& value, const T& low, const T& high) {
        return !(value < low) && (value < high);
    }
};

}  // namespace aidl::android::hardware::audio::effect
