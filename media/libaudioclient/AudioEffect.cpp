/*
**
** Copyright 2010, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/


//#define LOG_NDEBUG 0
#define LOG_TAG "AudioEffect"

#include <stdint.h>
#include <sys/types.h>
#include <limits.h>

#include <private/media/AudioEffectShared.h>
#include <media/AudioEffect.h>

#include <utils/Log.h>
#include <binder/IPCThreadState.h>



namespace android {

// ---------------------------------------------------------------------------

AudioEffect::AudioEffect(const String16& opPackageName)
    : mStatus(NO_INIT), mOpPackageName(opPackageName)
{
}


AudioEffect::AudioEffect(const effect_uuid_t *type,
                const String16& opPackageName,
                const effect_uuid_t *uuid,
                int32_t priority,
                effect_callback_t cbf,
                void* user,
                audio_session_t sessionId,
                audio_io_handle_t io,
                const AudioDeviceTypeAddr& device
                )
    : mStatus(NO_INIT), mOpPackageName(opPackageName)
{
    AutoMutex lock(mConstructLock);
    mStatus = set(type, uuid, priority, cbf, user, sessionId, io, device);
}

AudioEffect::AudioEffect(const char *typeStr,
                const String16& opPackageName,
                const char *uuidStr,
                int32_t priority,
                effect_callback_t cbf,
                void* user,
                audio_session_t sessionId,
                audio_io_handle_t io,
                const AudioDeviceTypeAddr& device
                )
    : mStatus(NO_INIT), mOpPackageName(opPackageName)
{
    effect_uuid_t type;
    effect_uuid_t *pType = NULL;
    effect_uuid_t uuid;
    effect_uuid_t *pUuid = NULL;

    ALOGV("Constructor string\n - type: %s\n - uuid: %s", typeStr, uuidStr);

    if (typeStr != NULL) {
        if (stringToGuid(typeStr, &type) == NO_ERROR) {
            pType = &type;
        }
    }

    if (uuidStr != NULL) {
        if (stringToGuid(uuidStr, &uuid) == NO_ERROR) {
            pUuid = &uuid;
        }
    }

    AutoMutex lock(mConstructLock);
    mStatus = set(pType, pUuid, priority, cbf, user, sessionId, io, device);
}

status_t AudioEffect::set(const effect_uuid_t *type,
                const effect_uuid_t *uuid,
                int32_t priority,
                effect_callback_t cbf,
                void* user,
                audio_session_t sessionId,
                audio_io_handle_t io,
                const AudioDeviceTypeAddr& device)
{
    sp<IEffect> iEffect;
    sp<IMemory> cblk;
    int enabled;

    ALOGV("set %p mUserData: %p uuid: %p timeLow %08x", this, user, type, type ? type->timeLow : 0);

    if (mIEffect != 0) {
        ALOGW("Effect already in use");
        return INVALID_OPERATION;
    }

    if (sessionId == AUDIO_SESSION_DEVICE && io != AUDIO_IO_HANDLE_NONE) {
        ALOGW("IO handle should not be specified for device effect");
        return BAD_VALUE;
    }
    const sp<IAudioFlinger>& audioFlinger = AudioSystem::get_audio_flinger();
    if (audioFlinger == 0) {
        ALOGE("set(): Could not get audioflinger");
        return NO_INIT;
    }

    if (type == NULL && uuid == NULL) {
        ALOGW("Must specify at least type or uuid");
        return BAD_VALUE;
    }

    mPriority = priority;
    mCbf = cbf;
    mUserData = user;
    mSessionId = sessionId;

    memset(&mDescriptor, 0, sizeof(effect_descriptor_t));
    mDescriptor.type = *(type != NULL ? type : EFFECT_UUID_NULL);
    mDescriptor.uuid = *(uuid != NULL ? uuid : EFFECT_UUID_NULL);

    mIEffectClient = new EffectClient(this);
    mClientPid = IPCThreadState::self()->getCallingPid();

    iEffect = audioFlinger->createEffect((effect_descriptor_t *)&mDescriptor,
            mIEffectClient, priority, io, mSessionId, device, mOpPackageName, mClientPid,
            &mStatus, &mId, &enabled);

    if (iEffect == 0 || (mStatus != NO_ERROR && mStatus != ALREADY_EXISTS)) {
        char typeBuffer[64] = {}, uuidBuffer[64] = {};
        guidToString(type, typeBuffer, sizeof(typeBuffer));
        guidToString(uuid, uuidBuffer, sizeof(uuidBuffer));
        ALOGE("set(): AudioFlinger could not create effect %s / %s, status: %d",
                type != nullptr ? typeBuffer : "NULL",
                uuid != nullptr ? uuidBuffer : "NULL",
                mStatus);
        if (iEffect == 0) {
            mStatus = NO_INIT;
        }
        return mStatus;
    }

    mEnabled = (volatile int32_t)enabled;

    cblk = iEffect->getCblk();
    if (cblk == 0) {
        mStatus = NO_INIT;
        ALOGE("Could not get control block");
        return mStatus;
    }

    mIEffect = iEffect;
    mCblkMemory = cblk;
    mCblk = static_cast<effect_param_cblk_t*>(cblk->pointer());
    int bufOffset = ((sizeof(effect_param_cblk_t) - 1) / sizeof(int) + 1) * sizeof(int);
    mCblk->buffer = (uint8_t *)mCblk + bufOffset;

    IInterface::asBinder(iEffect)->linkToDeath(mIEffectClient);
    ALOGV("set() %p OK effect: %s id: %d status %d enabled %d pid %d", this, mDescriptor.name, mId,
            mStatus, mEnabled, mClientPid);

    if (!audio_is_global_session(mSessionId)) {
        AudioSystem::acquireAudioSessionId(mSessionId, mClientPid);
    }

    return mStatus;
}


AudioEffect::~AudioEffect()
{
    ALOGV("Destructor %p", this);

    if (mStatus == NO_ERROR || mStatus == ALREADY_EXISTS) {
        if (!audio_is_global_session(mSessionId)) {
            AudioSystem::releaseAudioSessionId(mSessionId, mClientPid);
        }
        if (mIEffect != NULL) {
            mIEffect->disconnect();
            IInterface::asBinder(mIEffect)->unlinkToDeath(mIEffectClient);
        }
        mIEffect.clear();
        mCblkMemory.clear();
        mIEffectClient.clear();
        IPCThreadState::self()->flushCommands();
    }
}


status_t AudioEffect::initCheck() const
{
    return mStatus;
}

// -------------------------------------------------------------------------

effect_descriptor_t AudioEffect::descriptor() const
{
    return mDescriptor;
}

bool AudioEffect::getEnabled() const
{
    return (mEnabled != 0);
}

status_t AudioEffect::setEnabled(bool enabled)
{
    if (mStatus != NO_ERROR) {
        return (mStatus == ALREADY_EXISTS) ? (status_t) INVALID_OPERATION : mStatus;
    }

    status_t status = NO_ERROR;

    AutoMutex lock(mLock);
    if (enabled != mEnabled) {
        if (enabled) {
            ALOGV("enable %p", this);
            status = mIEffect->enable();
        } else {
            ALOGV("disable %p", this);
            status = mIEffect->disable();
        }
        if (status == NO_ERROR) {
            mEnabled = enabled;
        }
    }
    return status;
}

status_t AudioEffect::command(uint32_t cmdCode,
                              uint32_t cmdSize,
                              void *cmdData,
                              uint32_t *replySize,
                              void *replyData)
{
    if (mStatus != NO_ERROR && mStatus != ALREADY_EXISTS) {
        ALOGV("command() bad status %d", mStatus);
        return mStatus;
    }

    if (cmdCode == EFFECT_CMD_ENABLE || cmdCode == EFFECT_CMD_DISABLE) {
        if (mEnabled == (cmdCode == EFFECT_CMD_ENABLE)) {
            return NO_ERROR;
        }
        if (replySize == NULL || *replySize != sizeof(status_t) || replyData == NULL) {
            return BAD_VALUE;
        }
        mLock.lock();
    }

    status_t status = mIEffect->command(cmdCode, cmdSize, cmdData, replySize, replyData);

    if (cmdCode == EFFECT_CMD_ENABLE || cmdCode == EFFECT_CMD_DISABLE) {
        if (status == NO_ERROR) {
            status = *(status_t *)replyData;
        }
        if (status == NO_ERROR) {
            mEnabled = (cmdCode == EFFECT_CMD_ENABLE);
        }
        mLock.unlock();
    }

    return status;
}


status_t AudioEffect::setParameter(effect_param_t *param)
{
    if (mStatus != NO_ERROR) {
        return (mStatus == ALREADY_EXISTS) ? (status_t) INVALID_OPERATION : mStatus;
    }

    if (param == NULL || param->psize == 0 || param->vsize == 0) {
        return BAD_VALUE;
    }

    uint32_t size = sizeof(int);
    uint32_t psize = ((param->psize - 1) / sizeof(int) + 1) * sizeof(int) + param->vsize;

    ALOGV("setParameter: param: %d, param2: %d", *(int *)param->data,
            (param->psize == 8) ? *((int *)param->data + 1): -1);

    return mIEffect->command(EFFECT_CMD_SET_PARAM, sizeof (effect_param_t) + psize, param, &size,
            &param->status);
}

status_t AudioEffect::setParameterDeferred(effect_param_t *param)
{
    if (mStatus != NO_ERROR) {
        return (mStatus == ALREADY_EXISTS) ? (status_t) INVALID_OPERATION : mStatus;
    }

    if (param == NULL || param->psize == 0 || param->vsize == 0) {
        return BAD_VALUE;
    }

    Mutex::Autolock _l(mCblk->lock);

    int psize = ((param->psize - 1) / sizeof(int) + 1) * sizeof(int) + param->vsize;
    int size = ((sizeof(effect_param_t) + psize - 1) / sizeof(int) + 1) * sizeof(int);

    if (mCblk->clientIndex + size > EFFECT_PARAM_BUFFER_SIZE) {
        return NO_MEMORY;
    }
    int *p = (int *)(mCblk->buffer + mCblk->clientIndex);
    *p++ = size;
    memcpy(p, param, sizeof(effect_param_t) + psize);
    mCblk->clientIndex += size;

    return NO_ERROR;
}

status_t AudioEffect::setParameterCommit()
{
    if (mStatus != NO_ERROR) {
        return (mStatus == ALREADY_EXISTS) ? (status_t) INVALID_OPERATION : mStatus;
    }

    Mutex::Autolock _l(mCblk->lock);
    if (mCblk->clientIndex == 0) {
        return INVALID_OPERATION;
    }
    uint32_t size = 0;
    return mIEffect->command(EFFECT_CMD_SET_PARAM_COMMIT, 0, NULL, &size, NULL);
}

status_t AudioEffect::getParameter(effect_param_t *param)
{
    if (mStatus != NO_ERROR && mStatus != ALREADY_EXISTS) {
        return mStatus;
    }

    if (param == NULL || param->psize == 0 || param->vsize == 0) {
        return BAD_VALUE;
    }

    ALOGV("getParameter: param: %d, param2: %d", *(int *)param->data,
            (param->psize == 8) ? *((int *)param->data + 1): -1);

    uint32_t psize = sizeof(effect_param_t) + ((param->psize - 1) / sizeof(int) + 1) * sizeof(int) +
            param->vsize;

    return mIEffect->command(EFFECT_CMD_GET_PARAM, sizeof(effect_param_t) + param->psize, param,
            &psize, param);
}


// -------------------------------------------------------------------------

void AudioEffect::binderDied()
{
    ALOGW("IEffect died");
    mStatus = DEAD_OBJECT;
    if (mCbf != NULL) {
        status_t status = DEAD_OBJECT;
        mCbf(EVENT_ERROR, mUserData, &status);
    }
    mIEffect.clear();
}

// -------------------------------------------------------------------------

void AudioEffect::controlStatusChanged(bool controlGranted)
{
    ALOGV("controlStatusChanged %p control %d callback %p mUserData %p", this, controlGranted, mCbf,
            mUserData);
    if (controlGranted) {
        if (mStatus == ALREADY_EXISTS) {
            mStatus = NO_ERROR;
        }
    } else {
        if (mStatus == NO_ERROR) {
            mStatus = ALREADY_EXISTS;
        }
    }
    if (mCbf != NULL) {
        mCbf(EVENT_CONTROL_STATUS_CHANGED, mUserData, &controlGranted);
    }
}

void AudioEffect::enableStatusChanged(bool enabled)
{
    ALOGV("enableStatusChanged %p enabled %d mCbf %p", this, enabled, mCbf);
    if (mStatus == ALREADY_EXISTS) {
        mEnabled = enabled;
        if (mCbf != NULL) {
            mCbf(EVENT_ENABLE_STATUS_CHANGED, mUserData, &enabled);
        }
    }
}

void AudioEffect::commandExecuted(uint32_t cmdCode,
                                  uint32_t cmdSize __unused,
                                  void *cmdData,
                                  uint32_t replySize __unused,
                                  void *replyData)
{
    if (cmdData == NULL || replyData == NULL) {
        return;
    }

    if (mCbf != NULL && cmdCode == EFFECT_CMD_SET_PARAM) {
        effect_param_t *cmd = (effect_param_t *)cmdData;
        cmd->status = *(int32_t *)replyData;
        mCbf(EVENT_PARAMETER_CHANGED, mUserData, cmd);
    }
}

// -------------------------------------------------------------------------

status_t AudioEffect::queryNumberEffects(uint32_t *numEffects)
{
    const sp<IAudioFlinger>& af = AudioSystem::get_audio_flinger();
    if (af == 0) return PERMISSION_DENIED;
    return af->queryNumberEffects(numEffects);
}

status_t AudioEffect::queryEffect(uint32_t index, effect_descriptor_t *descriptor)
{
    const sp<IAudioFlinger>& af = AudioSystem::get_audio_flinger();
    if (af == 0) return PERMISSION_DENIED;
    return af->queryEffect(index, descriptor);
}

status_t AudioEffect::getEffectDescriptor(const effect_uuid_t *uuid,
                                          const effect_uuid_t *type,
                                          uint32_t preferredTypeFlag,
                                          effect_descriptor_t *descriptor)
{
    const sp<IAudioFlinger>& af = AudioSystem::get_audio_flinger();
    if (af == 0) return PERMISSION_DENIED;
    return af->getEffectDescriptor(uuid, type, preferredTypeFlag, descriptor);
}

status_t AudioEffect::queryDefaultPreProcessing(audio_session_t audioSession,
                                          effect_descriptor_t *descriptors,
                                          uint32_t *count)
{
    const sp<IAudioPolicyService>& aps = AudioSystem::get_audio_policy_service();
    if (aps == 0) return PERMISSION_DENIED;
    return aps->queryDefaultPreProcessing(audioSession, descriptors, count);
}

status_t AudioEffect::newEffectUniqueId(audio_unique_id_t* id)
{
    const sp<IAudioFlinger>& af = AudioSystem::get_audio_flinger();
    if (af == 0) return PERMISSION_DENIED;
    *id = af->newAudioUniqueId(AUDIO_UNIQUE_ID_USE_EFFECT);
    return NO_ERROR;
}

status_t AudioEffect::addSourceDefaultEffect(const char *typeStr,
                                             const String16& opPackageName,
                                             const char *uuidStr,
                                             int32_t priority,
                                             audio_source_t source,
                                             audio_unique_id_t *id)
{
    const sp<IAudioPolicyService>& aps = AudioSystem::get_audio_policy_service();
    if (aps == 0) return PERMISSION_DENIED;

    if (typeStr == NULL && uuidStr == NULL) return BAD_VALUE;

    // Convert type & uuid from string to effect_uuid_t.
    effect_uuid_t type;
    if (typeStr != NULL) {
        status_t res = stringToGuid(typeStr, &type);
        if (res != OK) return res;
    } else {
        type = *EFFECT_UUID_NULL;
    }

    effect_uuid_t uuid;
    if (uuidStr != NULL) {
        status_t res = stringToGuid(uuidStr, &uuid);
        if (res != OK) return res;
    } else {
        uuid = *EFFECT_UUID_NULL;
    }

    return aps->addSourceDefaultEffect(&type, opPackageName, &uuid, priority, source, id);
}

status_t AudioEffect::addStreamDefaultEffect(const char *typeStr,
                                             const String16& opPackageName,
                                             const char *uuidStr,
                                             int32_t priority,
                                             audio_usage_t usage,
                                             audio_unique_id_t *id)
{
    const sp<IAudioPolicyService>& aps = AudioSystem::get_audio_policy_service();
    if (aps == 0) return PERMISSION_DENIED;

    if (typeStr == NULL && uuidStr == NULL) return BAD_VALUE;

    // Convert type & uuid from string to effect_uuid_t.
    effect_uuid_t type;
    if (typeStr != NULL) {
        status_t res = stringToGuid(typeStr, &type);
        if (res != OK) return res;
    } else {
        type = *EFFECT_UUID_NULL;
    }

    effect_uuid_t uuid;
    if (uuidStr != NULL) {
        status_t res = stringToGuid(uuidStr, &uuid);
        if (res != OK) return res;
    } else {
        uuid = *EFFECT_UUID_NULL;
    }

    return aps->addStreamDefaultEffect(&type, opPackageName, &uuid, priority, usage, id);
}

status_t AudioEffect::removeSourceDefaultEffect(audio_unique_id_t id)
{
    const sp<IAudioPolicyService>& aps = AudioSystem::get_audio_policy_service();
    if (aps == 0) return PERMISSION_DENIED;

    return aps->removeSourceDefaultEffect(id);
}

status_t AudioEffect::removeStreamDefaultEffect(audio_unique_id_t id)
{
    const sp<IAudioPolicyService>& aps = AudioSystem::get_audio_policy_service();
    if (aps == 0) return PERMISSION_DENIED;

    return aps->removeStreamDefaultEffect(id);
}

// -------------------------------------------------------------------------

status_t AudioEffect::stringToGuid(const char *str, effect_uuid_t *guid)
{
    if (str == NULL || guid == NULL) {
        return BAD_VALUE;
    }

    int tmp[10];

    if (sscanf(str, "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
            tmp, tmp+1, tmp+2, tmp+3, tmp+4, tmp+5, tmp+6, tmp+7, tmp+8, tmp+9) < 10) {
        return BAD_VALUE;
    }
    guid->timeLow = (uint32_t)tmp[0];
    guid->timeMid = (uint16_t)tmp[1];
    guid->timeHiAndVersion = (uint16_t)tmp[2];
    guid->clockSeq = (uint16_t)tmp[3];
    guid->node[0] = (uint8_t)tmp[4];
    guid->node[1] = (uint8_t)tmp[5];
    guid->node[2] = (uint8_t)tmp[6];
    guid->node[3] = (uint8_t)tmp[7];
    guid->node[4] = (uint8_t)tmp[8];
    guid->node[5] = (uint8_t)tmp[9];

    return NO_ERROR;
}

status_t AudioEffect::guidToString(const effect_uuid_t *guid, char *str, size_t maxLen)
{
    if (guid == NULL || str == NULL) {
        return BAD_VALUE;
    }

    snprintf(str, maxLen, "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
            guid->timeLow,
            guid->timeMid,
            guid->timeHiAndVersion,
            guid->clockSeq,
            guid->node[0],
            guid->node[1],
            guid->node[2],
            guid->node[3],
            guid->node[4],
            guid->node[5]);

    return NO_ERROR;
}


} // namespace android
