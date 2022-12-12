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

#pragma once

#include <aidl/android/hardware/audio/effect/IEffect.h>
#include <media/audiohal/EffectHalInterface.h>
#include <system/audio_effect.h>

#include "EffectConversionHelperAidl.h"

namespace android {
namespace effect {

class EffectHalAidl : public EffectHalInterface, public EffectConversionHelperAidl
{
  public:
    // Set the input buffer.
    virtual status_t setInBuffer(const sp<EffectBufferHalInterface>& buffer);

    // Set the output buffer.
    virtual status_t setOutBuffer(const sp<EffectBufferHalInterface>& buffer);

    // Effect process function.
    virtual status_t process();

    // Process reverse stream function. This function is used to pass
    // a reference stream to the effect engine.
    virtual status_t processReverse();

    // Send a command and receive a response to/from effect engine.
    virtual status_t command(uint32_t cmdCode, uint32_t cmdSize, void *pCmdData,
            uint32_t *replySize, void *pReplyData);

    // Returns the effect descriptor.
    virtual status_t getDescriptor(effect_descriptor_t *pDescriptor);

    // Free resources on the remote side.
    virtual status_t close();

    // Whether it's a local implementation.
    virtual bool isLocal() const { return false; }

    virtual status_t dump(int fd);

    virtual uint64_t effectId() const { return mEffectId; }

  private:
    const uint64_t mEffectId;
    // Can not be constructed directly by clients.
    EffectHalAidl(const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>& effect,
                  uint64_t effectId);

    // The destructor automatically releases the effect.
    virtual ~EffectHalAidl();
};

} // namespace effect
} // namespace android
