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
#include <cstddef>
#include <cstdint>
#include <memory>
#define LOG_TAG "EffectsFactoryHalAidl"
//#define LOG_NDEBUG 0

#include <error/expected_utils.h>
#include <android/binder_manager.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionEffect.h>
#include <system/audio.h>
#include <utils/Log.h>

#include "EffectBufferHalAidl.h"
#include "EffectHalAidl.h"
#include "EffectProxy.h"
#include "EffectsFactoryHalAidl.h"

using ::aidl::android::legacy2aidl_audio_uuid_t_AudioUuid;
using aidl::android::aidl_utils::statusTFromBinderStatus;
using aidl::android::hardware::audio::effect::Descriptor;
using aidl::android::hardware::audio::effect::IFactory;
using aidl::android::media::audio::common::AudioUuid;
using android::detail::AudioHalVersionInfo;

namespace android {
namespace effect {

EffectsFactoryHalAidl::EffectsFactoryHalAidl(std::shared_ptr<IFactory> effectsFactory)
    : mFactory(effectsFactory),
      mHalVersion(AudioHalVersionInfo(
              AudioHalVersionInfo::Type::AIDL,
              [this]() {
                  int32_t majorVersion = 0;
                  return (mFactory && mFactory->getInterfaceVersion(&majorVersion).isOk())
                                 ? majorVersion
                                 : 0;
              }())),
      mHalDescList([this]() {
          std::vector<Descriptor> list;
          if (mFactory) {
              mFactory->queryEffects(std::nullopt, std::nullopt, std::nullopt, &list).isOk();
          }
          return list;
      }()),
      mUuidProxyMap([this]() {
          std::map<AudioUuid, std::shared_ptr<EffectProxy>> proxyMap;
          for (const auto& desc : mHalDescList) {
              // create EffectProxy
              if (desc.common.id.proxy.has_value()) {
                  const auto& uuid = desc.common.id.proxy.value();
                  if (0 == proxyMap.count(uuid)) {
                      proxyMap.insert({uuid, ndk::SharedRefBase::make<EffectProxy>(desc.common.id,
                                                                                   mFactory)});
                  }
                  proxyMap[uuid]->addSubEffect(desc);
              }
          }
          return proxyMap;
      }()),
      mProxyDescList([this]() {
          std::vector<Descriptor> list;
          for (const auto& proxy : mUuidProxyMap) {
              if (Descriptor desc; proxy.second && proxy.second->getDescriptor(&desc).isOk()) {
                  list.emplace_back(std::move(desc));
              }
          }
          return list;
      }()),
      mEffectCount(mHalDescList.size() + mProxyDescList.size()) {
    ALOG_ASSERT(effectsFactory != nullptr, "Provided IEffectsFactory service is NULL");
    ALOGI("%s with %zu halEffects and %zu proxyEffects", __func__, mHalDescList.size(),
          mProxyDescList.size());
}

status_t EffectsFactoryHalAidl::queryNumberEffects(uint32_t *pNumEffects) {
    if (pNumEffects == nullptr) {
        return BAD_VALUE;
    }

    *pNumEffects = mHalDescList.size() + mProxyDescList.size();
    ALOGI("%s %d", __func__, *pNumEffects);
    return OK;
}

status_t EffectsFactoryHalAidl::getDescriptor(uint32_t index, effect_descriptor_t* pDescriptor) {
    if (pDescriptor == nullptr) {
        return BAD_VALUE;
    }

    if (index >= mEffectCount) {
        ALOGE("%s index %d exceed max number %zu", __func__, index, mEffectCount);
        return INVALID_OPERATION;
    }

    if (index >= mHalDescList.size()) {
        *pDescriptor =
                VALUE_OR_RETURN_STATUS(::aidl::android::aidl2legacy_Descriptor_effect_descriptor(
                        mProxyDescList.at(index - mHalDescList.size())));
    } else {
        *pDescriptor = VALUE_OR_RETURN_STATUS(
                ::aidl::android::aidl2legacy_Descriptor_effect_descriptor(mHalDescList.at(index)));
    }
    return OK;
}

status_t EffectsFactoryHalAidl::getDescriptor(const effect_uuid_t* halUuid,
                                              effect_descriptor_t* pDescriptor) {
    if (halUuid == nullptr) {
        return BAD_VALUE;
    }

    AudioUuid uuid = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_uuid_t_AudioUuid(*halUuid));
    return getHalDescriptorWithImplUuid(uuid, pDescriptor);
}

status_t EffectsFactoryHalAidl::getDescriptors(const effect_uuid_t* halType,
                                               std::vector<effect_descriptor_t>* descriptors) {
    if (halType == nullptr) {
        return BAD_VALUE;
    }

    AudioUuid type = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_uuid_t_AudioUuid(*halType));
    return getHalDescriptorWithTypeUuid(type, descriptors);
}

status_t EffectsFactoryHalAidl::createEffect(const effect_uuid_t* uuid, int32_t sessionId,
                                             int32_t ioId, int32_t deviceId __unused,
                                             sp<EffectHalInterface>* effect) {
    if (uuid == nullptr || effect == nullptr) {
        return BAD_VALUE;
    }
    if (sessionId == AUDIO_SESSION_DEVICE && ioId == AUDIO_IO_HANDLE_NONE) {
        return INVALID_OPERATION;
    }
    ALOGI("%s session %d ioId %d", __func__, sessionId, ioId);

    AudioUuid aidlUuid = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_uuid_t_AudioUuid(*uuid));
    std::shared_ptr<IEffect> aidlEffect;
    // Use EffectProxy interface instead of IFactory to create
    if (isProxyEffect(aidlUuid)) {
        aidlEffect = mUuidProxyMap.at(aidlUuid);
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mUuidProxyMap.at(aidlUuid)->create()));
    } else {
        RETURN_STATUS_IF_ERROR(
                statusTFromBinderStatus(mFactory->createEffect(aidlUuid, &aidlEffect)));
    }
    if (aidlEffect == nullptr) {
        ALOGE("%s failed to create effect with UUID: %s", __func__, aidlUuid.toString().c_str());
        return NAME_NOT_FOUND;
    }
    Descriptor desc;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(aidlEffect->getDescriptor(&desc)));

    uint64_t effectId;
    {
        std::lock_guard lg(mLock);
        effectId = ++mEffectIdCounter;
    }

    *effect = sp<EffectHalAidl>::make(mFactory, aidlEffect, effectId, sessionId, ioId, desc);
    return OK;
}

status_t EffectsFactoryHalAidl::dumpEffects(int fd) {
    status_t ret = OK;
    // record the error ret and continue dump as many effects as possible
    for (const auto& proxy : mUuidProxyMap) {
        if (proxy.second) {
            if (status_t temp = proxy.second->dump(fd, nullptr, 0); temp != OK) {
                ret = temp;
            }
        }
    }
    RETURN_STATUS_IF_ERROR(mFactory->dump(fd, nullptr, 0));
    return ret;
}

status_t EffectsFactoryHalAidl::allocateBuffer(size_t size, sp<EffectBufferHalInterface>* buffer) {
    ALOGI("%s size %zu buffer %p", __func__, size, buffer);
    return EffectBufferHalAidl::allocate(size, buffer);
}

status_t EffectsFactoryHalAidl::mirrorBuffer(void* external, size_t size,
                                             sp<EffectBufferHalInterface>* buffer) {
    ALOGI("%s extern %p size %zu buffer %p", __func__, external, size, buffer);
    return EffectBufferHalAidl::mirror(external, size, buffer);
}

AudioHalVersionInfo EffectsFactoryHalAidl::getHalVersion() const {
    return mHalVersion;
}

status_t EffectsFactoryHalAidl::getHalDescriptorWithImplUuid(const AudioUuid& uuid,
                                                             effect_descriptor_t* pDescriptor) {
    if (pDescriptor == nullptr) {
        return BAD_VALUE;
    }

    const auto& list = isProxyEffect(uuid) ? mProxyDescList : mHalDescList;
    auto matchIt = std::find_if(list.begin(), list.end(),
                                [&](const auto& desc) { return desc.common.id.uuid == uuid; });
    if (matchIt == list.end()) {
        ALOGE("%s UUID not found in HAL and proxy list %s", __func__, uuid.toString().c_str());
        return BAD_VALUE;
    }

    *pDescriptor = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_Descriptor_effect_descriptor(*matchIt));
    return OK;
}

status_t EffectsFactoryHalAidl::getHalDescriptorWithTypeUuid(
        const AudioUuid& type, std::vector<effect_descriptor_t>* descriptors) {
    if (descriptors == nullptr) {
        return BAD_VALUE;
    }

    std::vector<Descriptor> result;
    std::copy_if(mHalDescList.begin(), mHalDescList.end(), std::back_inserter(result),
                 [&](auto& desc) { return desc.common.id.type == type; });
    std::copy_if(mProxyDescList.begin(), mProxyDescList.end(), std::back_inserter(result),
                 [&](auto& desc) { return desc.common.id.type == type; });

    *descriptors = VALUE_OR_RETURN_STATUS(
            aidl::android::convertContainer<std::vector<effect_descriptor_t>>(
                    result, ::aidl::android::aidl2legacy_Descriptor_effect_descriptor));
    return OK;
}

bool EffectsFactoryHalAidl::isProxyEffect(const AudioUuid& uuid) const {
    return 0 != mUuidProxyMap.count(uuid);
}

} // namespace effect

// When a shared library is built from a static library, even explicit
// exports from a static library are optimized out unless actually used by
// the shared library. See EffectsFactoryHalEntry.cpp.
extern "C" void* createIEffectsFactoryImpl() {
    auto serviceName = std::string(IFactory::descriptor) + "/default";
    auto service = IFactory::fromBinder(
            ndk::SpAIBinder(AServiceManager_waitForService(serviceName.c_str())));
    if (!service) {
        ALOGE("%s binder service %s not exist", __func__, serviceName.c_str());
        return nullptr;
    }
    return new effect::EffectsFactoryHalAidl(service);
}

} // namespace android
