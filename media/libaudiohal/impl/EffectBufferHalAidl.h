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

#include <media/audiohal/EffectBufferHalInterface.h>
#include <system/audio_effect.h>

namespace android {
namespace effect {

class EffectBufferHalAidl : public EffectBufferHalInterface
{
  public:
    static status_t allocate(size_t size, sp<EffectBufferHalInterface>* buffer);
    static status_t mirror(void* external, size_t size, sp<EffectBufferHalInterface>* buffer);

    virtual audio_buffer_t* audioBuffer();
    virtual void* externalData() const;

    virtual size_t getSize() const override { return mBufferSize; }

    virtual void setExternalData(void* external);
    virtual void setFrameCount(size_t frameCount);
    virtual bool checkFrameCountChange();

    virtual void update();
    virtual void commit();
    virtual void update(size_t size);
    virtual void commit(size_t size);

  private:
    friend class EffectBufferHalInterface;

    const size_t mBufferSize;
    bool mFrameCountChanged = false;
    void* mExternalData;
    audio_buffer_t mAudioBuffer;

    // Can not be constructed directly by clients.
    explicit EffectBufferHalAidl(size_t size);

    virtual ~EffectBufferHalAidl();

    status_t init();
};

} // namespace effect
} // namespace android
