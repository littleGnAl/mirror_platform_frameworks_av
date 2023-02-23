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
#include <memory>
#define LOG_TAG "EffectProxy"
//#define LOG_NDEBUG 0

#include <fmq/AidlMessageQueue.h>
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

EffectProxy::EffectProxy(const Descriptor::Identity& id, const std::shared_ptr<IFactory>& factory)
    : mIdentity([](const Descriptor::Identity& subId) {
          // update EffectProxy implementation UUID to the sub-effect proxy UUID
          ALOG_ASSERT(subId.proxy.has_value(), "Sub-effect Identity must have valid proxy UUID");
          Descriptor::Identity tempId = subId;
          tempId.uuid = subId.proxy.value();
          return tempId;
      }(id)),
      mFactory(factory) {}

EffectProxy::~EffectProxy() {
    // go over all sub-effects, close and release
    for (auto& sub : mSubEffects) {
        if (sub.second.first) {
            sub.second.first->close();
            mFactory->destroyEffect(sub.second.first);
        }
    }
    mSubEffects.clear();
}

// sub effect must have same proxy UUID as EffectProxy, and the type UUID must match.
ndk::ScopedAStatus EffectProxy::addSubEffect(const Descriptor& sub) {
    if (0 != mSubEffects.count(sub) || !sub.common.id.proxy.has_value() ||
        sub.common.id.proxy.value() != mIdentity.uuid) {
        ALOGE("%s sub effect already exist or mismatch %s", __func__, sub.toString().c_str());
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                "illegalSubEffect");
    }

    // not create sub-effect yet
    mSubEffects[sub].first = nullptr;
    // set the last added sub-effect to active before setActiveSubEffect()
    mActiveSub = sub;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectProxy::create() {
    ndk::ScopedAStatus status = ndk::ScopedAStatus::ok();

    for (auto& sub : mSubEffects) {
        status = mFactory->createEffect(sub.first.common.id.uuid, &sub.second.first);
        if (!status.isOk()) {
            break;
        }
    }

    // destroy all created effects if failure
    if (!status.isOk()) {
        for (auto& sub : mSubEffects) {
            if (sub.second.first) {
                mFactory->destroyEffect(sub.second.first);
            }
        }
    }
    return status;
}

const IEffect::OpenEffectReturn* EffectProxy::getEffectReturnParam() {
    return &mSubEffects[mActiveSub].second;
}

ndk::ScopedAStatus EffectProxy::setActiveSubEffect(
        const ActiveCheckerCallback& activeChecker) {
    const auto& itor = std::find_if(mSubEffects.begin(), mSubEffects.end(),
                                    [&](const auto& sub) { return activeChecker(sub.first); });
    if (itor == mSubEffects.end()) {
        ALOGE("%s no subeffect found with checker", __func__);
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                                "noActiveEffctFound");
    }

    mActiveSub = itor->first;
    return ndk::ScopedAStatus::ok();
}

// EffectProxy go over sub-effects and call IEffect interfaces
ndk::ScopedAStatus EffectProxy::open(const Parameter::Common& common,
                                     const std::optional<Parameter::Specific>& specific,
                                     IEffect::OpenEffectReturn* ret __unused) {
    if (!mSubEffects[mActiveSub].first) {
        ALOGE("%s null sub-effect interface", __func__);
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                                "activeSubEffectNull");
    }
    ndk::ScopedAStatus status = ndk::ScopedAStatus::ok();
    for (auto& sub : mSubEffects) {
        if (sub.first != mActiveSub && sub.second.first) {
            status = sub.second.first->open(common, specific, &sub.second.second);
            if (!status.isOk()) {
                break;
            }
        }
    }

    // close all opened effects if failure
    if (!status.isOk()) {
        for (auto& sub : mSubEffects) {
            if (sub.second.first) {
                sub.second.first->close();
            }
        }
    }

    return status;
}

ndk::ScopedAStatus EffectProxy::close() {
    for (auto& sub : mSubEffects) {
        if (sub.second.first) {
            sub.second.first->close();
        }
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectProxy::getDescriptor(Descriptor* desc) {
    desc->common.id = mIdentity;
    desc->common.name = "EffectProxy";
    desc->common.implementor = "Android Open Source Project";
    desc->capability = mActiveSub.capability;
    ALOGE("%s with %s", __func__, desc->toString().c_str());
    return ndk::ScopedAStatus::ok();
}

// Handle with active sub-effect first, only send to other sub-effects when success
ndk::ScopedAStatus EffectProxy::command(CommandId id) {
    if (!mSubEffects[mActiveSub].first) {
        ALOGE("%s null sub-effect interface", __func__);
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                                "activeSubEffectNull");
    }
    ndk::ScopedAStatus status = mSubEffects[mActiveSub].first->command(id);
    if (!status.isOk()) {
        return status;
    }

    for (const auto& sub : mSubEffects) {
        if (sub.first != mActiveSub && sub.second.first) {
            sub.second.first->command(id);
        }
    }
    return ndk::ScopedAStatus::ok();
}

// Return the active sub-effect state
ndk::ScopedAStatus EffectProxy::getState(State* state) {
    if (!mSubEffects[mActiveSub].first) {
        ALOGE("%s null sub-effect interface", __func__);
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                                "activeSubEffectNull");
    }
    return mSubEffects[mActiveSub].first->getState(state);
}

// Handle with active sub-effect first, only send to other sub-effects when success
ndk::ScopedAStatus EffectProxy::setParameter(const Parameter& param) {
    if (!mSubEffects[mActiveSub].first) {
        ALOGE("%s null sub-effect interface", __func__);
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                                "activeSubEffectNull");
    }
    ndk::ScopedAStatus status = mSubEffects[mActiveSub].first->setParameter(param);
    if (!status.isOk()) {
        return status;
    }

    for (const auto& sub : mSubEffects) {
        if (sub.first != mActiveSub && sub.second.first) {
            sub.second.first->setParameter(param);
        }
    }
    return status;
}

// Return the active sub-effect parameter
ndk::ScopedAStatus EffectProxy::getParameter(const Parameter::Id& id, Parameter* param) {
    if (!mSubEffects[mActiveSub].first) {
        ALOGE("%s null sub-effect interface", __func__);
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                                "activeSubEffectNull");
    }
    return mSubEffects[mActiveSub].first->getParameter(id, param);
}

} // namespace effect
} // namespace android
