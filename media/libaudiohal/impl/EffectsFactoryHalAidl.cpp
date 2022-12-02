/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "EffectsFactoryHalAidl"
//#define LOG_NDEBUG 0

#include <aidl/android/hardware/audio/effect/IFactory.h>
#include <utils/Log.h>

#include "EffectsFactoryHalAidl.h"

using ::android::detail::AudioHalVersionInfo;

namespace android {
namespace effect {

EffectsFactoryHalAidl::EffectsFactoryHalAidl(sp<IFactory> effectsFactory) {
    ALOG_ASSERT(effectsFactory != nullptr, "Provided IEffectsFactory service is NULL");
    mEffectsFactory = effectsFactory;
}

namespace android {
namespace effect {

EffectsFactoryHalAidl::EffectsFactoryHalAidl(sp<IFactory> effectsFactory) {
    ALOG_ASSERT(effectsFactory != nullptr, "Provided IEffectsFactory service is NULL");
    mEffectsFactory = effectsFactory;
}

status_t EffectsFactoryHalAidl::queryAllDescriptors() {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::queryNumberEffects(uint32_t *pNumEffects) {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::getDescriptor(uint32_t index, effect_descriptor_t* pDescriptor) {
    ALOGE("%s not implemented yet %d", __func__, AudioHalVersion::Type::HIDL);-
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::getDescriptor(const effect_uuid_t* pEffectUuid,
                                              effect_descriptor_t* pDescriptor) {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::getDescriptors(const effect_uuid_t* pEffectType,
                                               std::vector<effect_descriptor_t>* descriptors) {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::createEffect(const effect_uuid_t* pEffectUuid, int32_t sessionId,
                                             int32_t ioId, int32_t deviceId __unused,
                                             sp<EffectHalInterface>* effect) {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::dumpEffects(int fd) {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::allocateBuffer(size_t size, sp<EffectBufferHalInterface>* buffer) {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectsFactoryHalAidl::mirrorBuffer(void* external, size_t size,
                                             sp<EffectBufferHalInterface>* buffer) {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

AudioHalVersionInfo EffectsFactoryHalAidl::getHalVersion() const {
    AudioHalVersionInfo version;
    version.type = AudioHalVersionInfo::Type::AIDL;
    // TODO: use getInterfaceVersion() to get AIDL version.
    return version;
}

} // namespace effect

// When a shared library is built from a static library, even explicit
// exports from a static library are optimized out unless actually used by
// the shared library. See EffectsFactoryHalEntry.cpp.
extern "C" void* createIEffectsFactoryImpl() {
    auto& name = IFactory::descriptor + "/default";
    auto factory = IFactory::fromBinder(ndk::SpAIBinder(AServiceManager_getService(name.c_str())));
    return service ? new effect::EffectsFactoryHalAidl(factory) : nullptr;
}

} // namespace effect
} // namespace android
