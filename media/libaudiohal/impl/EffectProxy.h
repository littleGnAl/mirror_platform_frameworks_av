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
#include <aidl/android/hardware/audio/effect/BnFactory.h>
#include <map>
#include <memory>

namespace android {
namespace effect {

/**
 * EffectProxy is the proxy for one or more effect AIDL implementations (sub effect) of same type
 * of effects.
 * The audio framework use EffectProxy as a composite implementation of all sub effect
 * implementations.
 * At any given time, there is only one active effect which consuming and producing data for each
 * proxy, but the commands/parameters applies to all sub effects, only reply from the active effect.
 */
class EffectProxy : public ::aidl::android::hardware::audio::effect::BnEffect {
  public:
    EffectProxy(const ::aidl::android::media::audio::common::AudioUuid uuid,
                const std::shared_ptr<::aidl::android::hardware::audio::effect::IFactory> factory);

    /**
     * Return true if successfully add a sub effect into the proxy, return false if the sub effect
     * already exist, or the type/proxy mismatch.
     */
    bool addSubEffect(const ::aidl::android::hardware::audio::effect::Descriptor& sub);

    /**
     * Create all sub-effects via AIDL IFactory.
     */
    status_t create();

    /**
     * Select the first sub effect in list as the active effect if checker callback is true, return
     * false if no sub effect is selected (checker is false for all sub-effects).
     */
    using activeCheckerCallback =
            std::function<bool(::aidl::android::hardware::audio::effect::Descriptor)>;
    bool setActiveSub(activeCheckerCallback activeChecker);

    // IEffect interfaces override
    ndk::ScopedAStatus open(
            const ::aidl::android::hardware::audio::effect::Parameter::Common& common,
            const std::optional<::aidl::android::hardware::audio::effect::Parameter::Specific>&
                    specific,
            ::aidl::android::hardware::audio::effect::IEffect::OpenEffectReturn* ret) override;
    ndk::ScopedAStatus close() override;
    ndk::ScopedAStatus getDescriptor(
            ::aidl::android::hardware::audio::effect::Descriptor* desc) override;
    ndk::ScopedAStatus command(::aidl::android::hardware::audio::effect::CommandId id) override;
    ndk::ScopedAStatus getState(::aidl::android::hardware::audio::effect::State* state) override;
    ndk::ScopedAStatus setParameter(
            const ::aidl::android::hardware::audio::effect::Parameter& param) override;
    ndk::ScopedAStatus getParameter(
            const ::aidl::android::hardware::audio::effect::Parameter::Id& id,
            ::aidl::android::hardware::audio::effect::Parameter* param) override;

  private:
    // Proxy implement UUID
    const ::aidl::android::media::audio::common::AudioUuid mUuid;
    const std::shared_ptr<::aidl::android::hardware::audio::effect::IFactory> mFactory;

    // A map of sub effects descriptor to the IEffect and return FMQ
    using EffectProxySub = std::pair<
            std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>,
            std::unique_ptr<::aidl::android::hardware::audio::effect::IEffect::OpenEffectReturn>>;
    std::map<const ::aidl::android::hardware::audio::effect::Descriptor, EffectProxySub>
            mSubEffects;

    // Index of the only active effect in the list
    ::aidl::android::hardware::audio::effect::Descriptor mActiveSub;

    // close and release all sub-effects
    ~EffectProxy();
};

} // namespace effect
} // namespace android
