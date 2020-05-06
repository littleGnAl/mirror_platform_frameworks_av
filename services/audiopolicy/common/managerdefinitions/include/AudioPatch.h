/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "HandleGenerator.h"
#include <system/audio.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/String8.h>

namespace android {

class AudioPatch : public RefBase, private HandleGenerator<audio_patch_handle_t>
{
public:
    AudioPatch(const struct audio_patch *patch, uid_t uid);

    audio_patch_handle_t getHandle() const { return mHandle; }

    audio_patch_handle_t getAfHandle() const { return mAfPatchHandle; }

    void setAfHandle(audio_patch_handle_t afHandle) { mAfPatchHandle = afHandle; }

    uid_t getUid() const { return mUid; }

    void setUid(uid_t uid) { mUid = uid; }

    void dump(String8 *dst, int spaces, int index) const;

    struct audio_patch mPatch;

private:
    const audio_patch_handle_t mHandle;
    uid_t mUid;
    audio_patch_handle_t mAfPatchHandle = AUDIO_PATCH_HANDLE_NONE;
};

class AudioPatchCollection : public DefaultKeyedVector<audio_patch_handle_t, sp<AudioPatch> >
{
public:
    status_t addAudioPatch(audio_patch_handle_t handle, const sp<AudioPatch>& patch);

    status_t removeAudioPatch(audio_patch_handle_t handle);

    status_t listAudioPatches(unsigned int *num_patches, struct audio_patch *patches) const;

    void dump(String8 *dst) const;

    /**
     * @brief findPatchInvolvingSourceMix searches the first patch handle involving a source mix
     * port referred by its portId. Normally, mix port are involved only in one patch at a given
     * time, except for output that might be reused and attached to a SW Bridge convention patch.
     * @param portId of the mix port
     * @return valid patch handle if found, AUDIO_PATCH_HANDLE_NONE otherwise
     */
    audio_patch_handle_t findPatchInvolvingSourceMix(audio_port_handle_t portId);
};

} // namespace android
