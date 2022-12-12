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

#define LOG_TAG "EffectHalAidl"
//#define LOG_NDEBUG 0

#include <media/EffectsFactoryApi.h>
#include <mediautils/TimeCheck.h>
#include <utils/Log.h>
#include <util/EffectUtils.h>

#include "EffectHalAidl.h"

using ::aidl::android::hardware::audio::effect::IEffect;

namespace android {
namespace effect {

EffectHalAidl::EffectHalAidl(const std::shared_ptr<IEffect>& effect, uint64_t effectId)
    : EffectConversionHelperAidl("EffectHalAidl"), mEffectId(effectId) {
}

EffectHalAidl::~EffectHalAidl() {
}

status_t EffectHalAidl::setInBuffer(const sp<EffectBufferHalInterface>& buffer) {
    if (buffer == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectHalAidl::setOutBuffer(const sp<EffectBufferHalInterface>& buffer) {
    if (buffer == nullptr) {
        return BAD_VALUE;
    }
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectHalAidl::process() {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectHalAidl::processReverse() {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectHalAidl::prepareForProcessing() {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectHalAidl::processImpl(uint32_t mqFlag) {
    ALOGE("%s not implemented yet %d", __func__, mqFlag);
    return INVALID_OPERATION;
}

status_t EffectHalAidl::setProcessBuffers() {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectHalAidl::getDescriptor(effect_descriptor_t *pDescriptor) {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectHalAidl::close() {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t EffectHalAidl::dump(int fd) {
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

} // namespace effect
} // namespace android
