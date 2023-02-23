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
using ::aidl::android::hardware::audio::effect::Flags;
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
    close();
    destroy();
    mSubEffects.clear();
}

// sub effect must have same proxy UUID as EffectProxy, and the type UUID must match.
ndk::ScopedAStatus EffectProxy::addSubEffect(const Descriptor& sub) {
    if (0 != mSubEffects.count(sub.common.id) || !sub.common.id.proxy.has_value() ||
        sub.common.id.proxy.value() != mIdentity.uuid) {
        ALOGE("%s sub effect already exist or mismatch %s", __func__, sub.toString().c_str());
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_ILLEGAL_ARGUMENT,
                                                                "illegalSubEffect");
    }

    // not create sub-effect yet
    std::get<SubEffectTupleIndex::HANDLE>(mSubEffects[sub.common.id]) = nullptr;
    std::get<SubEffectTupleIndex::DESCRIPTOR>(mSubEffects[sub.common.id]) = sub;
    // set the last added sub-effect to active before setActiveSubEffect()
    mActiveSub = sub.common.id;
    ALOGI("%s add %s to proxy %s", __func__, mActiveSub.toString().c_str(),
          mIdentity.toString().c_str());
    if (sub.common.flags.hwAcceleratorMode == Flags::HardwareAccelerator::TUNNEL) {
        mSupportOffload = true;
    }
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus EffectProxy::create() {
    ndk::ScopedAStatus status = ndk::ScopedAStatus::ok();

    for (auto& sub : mSubEffects) {
        auto& effectHandle = std::get<SubEffectTupleIndex::HANDLE>(sub.second);
        ALOGI("%s sub-effect %s", __func__, sub.first.uuid.toString().c_str());
        status = mFactory->createEffect(sub.first.uuid, &effectHandle);
        if (!status.isOk() || !effectHandle) {
            ALOGE("%s sub-effect failed %s", __func__, sub.first.uuid.toString().c_str());
            break;
        }
    }

    // destroy all created effects if failure
    if (!status.isOk()) {
        destroy();
    }
    return status;
}

ndk::ScopedAStatus EffectProxy::destroy() {
    return runWithAllSubEffects([&](std::shared_ptr<IEffect>& effect) {
        ndk::ScopedAStatus status = mFactory->destroyEffect(effect);
        if (status.isOk()) {
            effect.reset();
        }
        return status;
    });
}

const IEffect::OpenEffectReturn* EffectProxy::getEffectReturnParam() {
    return &std::get<SubEffectTupleIndex::RETURN>(mSubEffects[mActiveSub]);
}

ndk::ScopedAStatus EffectProxy::setActiveSubEffect(
        const ActiveCheckerCallback& activeChecker) {
    const auto& itor = std::find_if(mSubEffects.begin(), mSubEffects.end(), [&](const auto& sub) {
        return activeChecker(std::get<SubEffectTupleIndex::DESCRIPTOR>(sub.second));
    });
    if (itor == mSubEffects.end()) {
        ALOGE("%s no subeffect found with checker", __func__);
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                                "noActiveEffctFound");
    }

    mActiveSub = itor->first;
    ALOGI("%s: %s", __func__, mActiveSub.uuid.toString().c_str());
    return ndk::ScopedAStatus::ok();
}

// EffectProxy go over sub-effects and call IEffect interfaces
ndk::ScopedAStatus EffectProxy::open(const Parameter::Common& common,
                                     const std::optional<Parameter::Specific>& specific,
                                     IEffect::OpenEffectReturn* ret __unused) {
    ndk::ScopedAStatus status = ndk::ScopedAStatus::ok();
    for (auto& sub : mSubEffects) {
        auto& effect = std::get<SubEffectTupleIndex::HANDLE>(sub.second);
        auto& openRet = std::get<SubEffectTupleIndex::RETURN>(sub.second);
        if (effect) {
            ALOGI("%s: %s", __func__, sub.first.uuid.toString().c_str());
            status = effect->open(common, specific, &openRet);
            if (!status.isOk()) {
                ALOGE("%s: failed %s", __func__, sub.first.uuid.toString().c_str());
                break;
            }
        }
    }

    // close all opened effects if failure
    if (!status.isOk()) {
        close();
    }

    return status;
}

ndk::ScopedAStatus EffectProxy::close() {
    return runWithAllSubEffects([&](std::shared_ptr<IEffect>& effect) {
        return effect->close();
    });
}

ndk::ScopedAStatus EffectProxy::getDescriptor(Descriptor* desc) {
    auto& descriptor = std::get<SubEffectTupleIndex::DESCRIPTOR>(mSubEffects[mActiveSub]);
    desc->common.id = mIdentity;
    // add offload indication if there is a sub-effect support offload
    desc->common.flags.offloadIndication = mSupportOffload;
    desc->common.name = "EffectProxy";
    desc->common.implementor = "Android Open Source Project";
    desc->capability = descriptor.capability;
    ALOGI("%s with %s", __func__, desc->toString().c_str());
    return ndk::ScopedAStatus::ok();
}

// Handle with active sub-effect first, only send to other sub-effects when success
ndk::ScopedAStatus EffectProxy::command(CommandId id) {
    return runWithActiveSubEffectThenOthers(
            [&](const std::shared_ptr<IEffect>& effect) -> ndk::ScopedAStatus {
                return effect->command(id);
            });
}

// Return the active sub-effect state
ndk::ScopedAStatus EffectProxy::getState(State* state) {
    return runWithActiveSubEffect(
            [&](const std::shared_ptr<IEffect>& effect) -> ndk::ScopedAStatus {
                return effect->getState(state);
            });
}

// Handle with active sub-effect first, only send to other sub-effects when success
ndk::ScopedAStatus EffectProxy::setParameter(const Parameter& param) {
    return runWithActiveSubEffectThenOthers(
            [&](const std::shared_ptr<IEffect>& effect) -> ndk::ScopedAStatus {
                return effect->setParameter(param);
            });
}

// Return the active sub-effect parameter
ndk::ScopedAStatus EffectProxy::getParameter(const Parameter::Id& id, Parameter* param) {
    return runWithActiveSubEffect(
            [&](const std::shared_ptr<IEffect>& effect) -> ndk::ScopedAStatus {
                return effect->getParameter(id, param);
            });
}

ndk::ScopedAStatus EffectProxy::runWithActiveSubEffectThenOthers(
        std::function<ndk::ScopedAStatus(const std::shared_ptr<IEffect>&)> const& func) {
    ndk::ScopedAStatus status = runWithActiveSubEffect(func);
    if (!status.isOk()) {
        return status;
    }

    // proceed with others if active sub-effect success
    for (const auto& sub : mSubEffects) {
        auto& effect = std::get<SubEffectTupleIndex::HANDLE>(sub.second);
        if (sub.first != mActiveSub) {
            if (!effect) {
                ALOGE("%s null sub-effect interface for %s", __func__,
                      sub.first.toString().c_str());
                continue;
            }
            func(effect);
        }
    }
    return status;
}

ndk::ScopedAStatus EffectProxy::runWithActiveSubEffect(
        std::function<ndk::ScopedAStatus(const std::shared_ptr<IEffect>&)> const& func) {
    auto& effect = std::get<SubEffectTupleIndex::HANDLE>(mSubEffects[mActiveSub]);
    if (!effect) {
        ALOGE("%s null active sub-effect interface", __func__);
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                                "activeSubEffectNull");
    }
    return func(effect);
}

ndk::ScopedAStatus EffectProxy::runWithAllSubEffects(
        std::function<ndk::ScopedAStatus(std::shared_ptr<IEffect>&)> const& func) {
    ndk::ScopedAStatus status = ndk::ScopedAStatus::ok();
    // proceed with others if active sub-effect success
    for (auto& sub : mSubEffects) {
        auto& effect = std::get<SubEffectTupleIndex::HANDLE>(sub.second);
        if (!effect) {
            ALOGE("%s null sub-effect interface for %s", __func__, sub.first.toString().c_str());
            continue;
        }
        ndk::ScopedAStatus temp = func(effect);
        if (!temp.isOk()) {
            status = ndk::ScopedAStatus::fromStatus(temp.getStatus());
        }
    }
    return status;
}

} // namespace effect
} // namespace android
