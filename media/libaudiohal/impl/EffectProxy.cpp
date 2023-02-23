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

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <type_traits>
#include <utility>
#define LOG_TAG "EffectHalAidl"
//#define LOG_NDEBUG 0

#include <algorithm>
#include <memory>
#include <utils/Log.h>

#include "EffectProxy.h"

using ::aidl::android::hardware::audio::effect::CommandId;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::IEffect;
using ::aidl::android::hardware::audio::effect::IFactory;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::State;
using ::aidl::android::media::audio::common::AudioUuid;

namespace android {
namespace effect {

EffectProxy::EffectProxy(
        const ::aidl::android::media::audio::common::AudioUuid uuid,
        const std::shared_ptr<::aidl::android::hardware::audio::effect::IFactory> factory)
    : mUuid(uuid), mFactory(factory) {}

EffectProxy::~EffectProxy() {
    // go over mSubEffects and release all sub-effects
    for (const auto& sub : mSubEffects) {
        if (sub.second.first) {
            sub.second.first->close();
        }
    }
    mSubEffects.clear();
}

bool EffectProxy::addSubEffect(const Descriptor& sub) {
    if (0 != mSubEffects.count(sub) || !sub.common.id.proxy.has_value() ||
        sub.common.id.proxy.value() != mUuid) {
        ALOGE("%s sub effect already exist or mismatch %s", __func__, sub.toString().c_str());
        return false;
    }

    // not create sub-effect yet
    mSubEffects[sub] = std::make_pair(nullptr, nullptr);
    return true;
}

status_t EffectProxy::create() {
    // TODO: create sub effects
    return OK;
}

bool EffectProxy::setActiveSub(activeCheckerCallback activeChecker) {
    for (const auto& sub : mSubEffects) {
        if (activeChecker(sub.first)) {
            mActiveSub = sub.first;
            return true;
        }
    }
    return false;
}

// IEffect interfaces, EffectProxy go over sub-effects and call same IEffect interfaces for each
ndk::ScopedAStatus EffectProxy::open(const Parameter::Common& common __unused,
                                     const std::optional<Parameter::Specific>& specific __unused,
                                     OpenEffectReturn* ret __unused) {
    // TODO
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectProxy::close() {
    // TODO
    return ndk::ScopedAStatus::ok();
}

// Return the active sub-effect descriptor, but fill the UUID and with mUUID
ndk::ScopedAStatus EffectProxy::getDescriptor(Descriptor* desc __unused) {
    // TODO
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectProxy::command(CommandId id __unused) {
    // TODO
    return ndk::ScopedAStatus::ok();
}

// Return the active sub-effect state
ndk::ScopedAStatus EffectProxy::getState(State* state __unused) {
    // TODO
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectProxy::setParameter(const Parameter& param __unused) {
    // TODO
    return ndk::ScopedAStatus::ok();
}

// Return the active sub-effect parameter
ndk::ScopedAStatus EffectProxy::getParameter(const Parameter::Id& id __unused,
                                             Parameter* param __unused) {
    // TODO
    return ndk::ScopedAStatus::ok();
}

} // namespace effect
} // namespace android
