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

#include <algorithm>
#include <cstdint>
#include <memory>
#define LOG_TAG "EffectsFactoryHalAidl"
//#define LOG_NDEBUG 0

#include <aidl/android/hardware/audio/effect/IFactory.h>
#include <android/binder_manager.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionNdk.h>
#include <utils/Log.h>

#include "EffectBufferHalAidl.h"
#include "EffectHalAidl.h"
#include "EffectsFactoryHalAidl.h"

using aidl::android::hardware::audio::effect::IFactory;
using aidl::android::media::audio::common::AudioUuid;
using android::detail::AudioHalVersionInfo;

namespace android {
namespace effect {

EffectsFactoryHalAidl::EffectsFactoryHalAidl(std::shared_ptr<IFactory> effectsFactory) {
    std::lock_guard lg(mLock);
    ALOG_ASSERT(effectsFactory != nullptr, "Provided IEffectsFactory service is NULL");
    mFactory = std::move(effectsFactory);

    int32_t versionNumber = 0;
    if (mFactory && mFactory->getInterfaceVersion(&versionNumber).isOk()) {
        halVersion = std::make_unique<AudioHalVersionInfo>(
                AudioHalVersionInfo(AudioHalVersionInfo::Type::AIDL, versionNumber, 0 /* minor */));
    }
}

status_t EffectsFactoryHalAidl::queryNumberEffects(uint32_t *pNumEffects) {
    if (pNumEffects == nullptr) {
        return BAD_VALUE;
    }

    {
        std::lock_guard lg(mLock);
        RETURN_IF_NOT_OK(queryEffectList_l());
        *pNumEffects = mDescList->size();
    }
    ALOGI("%s %d", __func__, *pNumEffects);
    return OK;
}

status_t EffectsFactoryHalAidl::getDescriptor(uint32_t index, effect_descriptor_t* pDescriptor) {
    if (pDescriptor == nullptr) {
        return BAD_VALUE;
    }

    status_t ret = OK;
    {
        std::lock_guard lg(mLock);
        RETURN_IF_NOT_OK(queryEffectList_l());

        auto listSize = mDescList->size();
        if (index >= listSize) {
            ALOGE("%s index %d exceed size DescList %zd", __func__, index, listSize);
            return INVALID_OPERATION;
        }

        *pDescriptor = VALUE_OR_RETURN_STATUS(
                ::aidl::android::aidl2legacy_Descriptor_effect_descriptor(mDescList->at(index)));
    }
    return ret;
}

status_t EffectsFactoryHalAidl::getDescriptor(const effect_uuid_t* halUuid,
                                              effect_descriptor_t* pDescriptor) {
    if (halUuid == nullptr || pDescriptor == nullptr) {
        return BAD_VALUE;
    }

    AudioUuid uuid =
            VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_audio_uuid_t_AudioUuid(*halUuid));
    std::lock_guard lg(mLock);
    return getHalDescriptorWithImplUuid_l(uuid, pDescriptor);
}

status_t EffectsFactoryHalAidl::getDescriptors(const effect_uuid_t* halType,
                                               std::vector<effect_descriptor_t>* descriptors) {
    if (halType == nullptr || descriptors == nullptr) {
        return BAD_VALUE;
    }

    AudioUuid type =
            VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_audio_uuid_t_AudioUuid(*halType));
    std::lock_guard lg(mLock);
    return getHalDescriptorWithTypeUuid_l(type, descriptors);
}

status_t EffectsFactoryHalAidl::createEffect(const effect_uuid_t* uuid, int32_t sessionId,
                                             int32_t ioId, int32_t deviceId __unused,
                                             sp<EffectHalInterface>* effect) {
    if (uuid == nullptr || effect == nullptr) {
        return BAD_VALUE;
    }
    ALOGI("%s session %d ioId %d", __func__, sessionId, ioId);

    AudioUuid aidlUuid =
            VALUE_OR_RETURN_STATUS(::aidl::android::legacy2aidl_audio_uuid_t_AudioUuid(*uuid));
    std::shared_ptr<IEffect> aidlEffect;
    ndk::ScopedAStatus status;
    uint64_t effectId;
    {
        std::lock_guard lg(mLock);
        status = mFactory->createEffect(aidlUuid, &aidlEffect);
        if (!status.isOk() || aidlEffect == nullptr) {
            ALOGE("%s IFactory::createFactory failed %s UUID %s", __func__,
                status.getDescription().c_str(), aidlUuid.toString().c_str());
            return INVALID_OPERATION;
        }
        effectId = ++mEffectIdCounter;
    }

    *effect = new EffectHalAidl(aidlEffect, effectId, sessionId, ioId);
    return OK;
}

status_t EffectsFactoryHalAidl::dumpEffects(int fd) {
    ALOGE("%s not implemented yet, fd %d", __func__, fd);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::allocateBuffer(size_t size, sp<EffectBufferHalInterface>* buffer) {
    ALOGI("%s size %zu buffer %p", __func__, size, buffer);
    // Buffer doesn't allocated here for AIDL, instead each effect open will return I/O data FMQ.
    return EffectBufferHalAidl::allocate(size, buffer);
}

status_t EffectsFactoryHalAidl::mirrorBuffer(void* external, size_t size,
                                             sp<EffectBufferHalInterface>* buffer) {
    ALOGI("%s extern %p size %zu buffer %p", __func__, external, size, buffer);
    // TODO: implement with FMQ
    return EffectBufferHalAidl::mirror(external, size, buffer);
}

AudioHalVersionInfo EffectsFactoryHalAidl::getHalVersion() const {
    AudioHalVersionInfo invalid(AudioHalVersionInfo::Type::AIDL, 0, 0);
    return halVersion ? *halVersion : invalid;
}

status_t EffectsFactoryHalAidl::queryEffectList_l() {
    if (!mDescList) {
        std::vector<Descriptor> list;
        auto status = mFactory->queryEffects(std::nullopt, std::nullopt, std::nullopt, &list);
        if (!status.isOk()) {
            ALOGE("%s IFactory::queryEffects failed %s", __func__, status.getDescription().c_str());
            return status.getStatus();
        }

        mDescList = std::make_unique<std::vector<Descriptor>>(list);
    }
    return OK;
}

status_t EffectsFactoryHalAidl::getHalDescriptorWithImplUuid_l(const AudioUuid& uuid,
                                                               effect_descriptor_t* pDescriptor) {
    if (pDescriptor == nullptr) {
        return BAD_VALUE;
    }
    if (!mDescList) {
        RETURN_IF_NOT_OK(queryEffectList_l());
    }

    auto matchIt = std::find_if(mDescList->begin(), mDescList->end(),
                                 [&](const auto& desc) { return desc.common.id.uuid == uuid; });
    if (matchIt == mDescList->end()) {
        ALOGE("%s UUID %s not found", __func__, uuid.toString().c_str());
        return BAD_VALUE;
    }

    *pDescriptor = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_Descriptor_effect_descriptor(*matchIt));
    return OK;
}

status_t EffectsFactoryHalAidl::getHalDescriptorWithTypeUuid_l(
        const AudioUuid& type, std::vector<effect_descriptor_t>* descriptors) {
    if (descriptors == nullptr) {
        return BAD_VALUE;
    }
    if (!mDescList) {
        RETURN_IF_NOT_OK(queryEffectList_l());
    }
    std::vector<Descriptor> result;
    std::copy_if(mDescList->begin(), mDescList->end(), std::back_inserter(result),
                 [&](auto& desc) { return desc.common.id.type == type; });
    if (result.size() == 0) {
        ALOGE("%s type UUID %s not found", __func__, type.toString().c_str());
        return BAD_VALUE;
    }

    std::transform(result.begin(), result.end(), std::back_inserter(*descriptors), [&](auto& desc) {
        return ::aidl::android::aidl2legacy_Descriptor_effect_descriptor(desc).value();
    });
    *descriptors = VALUE_OR_RETURN_STATUS(
            aidl::android::convertContainer<std::vector<effect_descriptor_t>>(
                    result, ::aidl::android::aidl2legacy_Descriptor_effect_descriptor));
    return OK;
}

} // namespace effect

// When a shared library is built from a static library, even explicit
// exports from a static library are optimized out unless actually used by
// the shared library. See EffectsFactoryHalEntry.cpp.
extern "C" void* createIEffectsFactoryImpl() {
    auto serviceName = std::string() + IFactory::descriptor + "/default";
    auto service = IFactory::fromBinder(
            ndk::SpAIBinder(AServiceManager_waitForService(serviceName.c_str())));
    ALOGW("%s fromBinder %s %s", __func__, serviceName.c_str(), service ? "succ" : "fail");
    return service ? new effect::EffectsFactoryHalAidl(service) : nullptr;
}

} // namespace android
