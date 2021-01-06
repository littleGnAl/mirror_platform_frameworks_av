/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */
#include <binder/IBinder.h>
#include <binder/IServiceManager.h>
#include <binder/MemoryBase.h>
#include <binder/MemoryDealer.h>
#include <binder/MemoryHeapBase.h>
#include <media/AudioRecord.h>
#include <media/AudioSystem.h>
#include <media/AudioTrack.h>
#include <media/IAudioFlinger.h>
#include <media/IEffect.h>
#include <media/IEffectClient.h>
#include <utils/Log.h>
#include <utils/String8.h>
#include "fuzzer/FuzzedDataProvider.h"

#define MAX_EFFECTS 10
#define MAX_STRING_LENGTH 256
#define MAX_ARRAY_LENGTH 256

using namespace std;
using namespace android;

std::vector<audio_unique_id_use_t> kUniqueIds = {
    AUDIO_UNIQUE_ID_USE_UNSPECIFIED, AUDIO_UNIQUE_ID_USE_SESSION, AUDIO_UNIQUE_ID_USE_MODULE,
    AUDIO_UNIQUE_ID_USE_EFFECT,      AUDIO_UNIQUE_ID_USE_PATCH,   AUDIO_UNIQUE_ID_USE_OUTPUT,
    AUDIO_UNIQUE_ID_USE_INPUT,       AUDIO_UNIQUE_ID_USE_CLIENT,  AUDIO_UNIQUE_ID_USE_MAX,
    AUDIO_UNIQUE_ID_USE_MASK,
};

std::vector<audio_stream_type_t> kStreamtypes = {
    AUDIO_STREAM_VOICE_CALL,     AUDIO_STREAM_SYSTEM,
    AUDIO_STREAM_RING,           AUDIO_STREAM_MUSIC,
    AUDIO_STREAM_ALARM,          AUDIO_STREAM_NOTIFICATION,
    AUDIO_STREAM_BLUETOOTH_SCO,  AUDIO_STREAM_ENFORCED_AUDIBLE,
    AUDIO_STREAM_DTMF,           AUDIO_STREAM_TTS,
    AUDIO_STREAM_ACCESSIBILITY,  AUDIO_STREAM_ASSISTANT,
    AUDIO_STREAM_REROUTING,      AUDIO_STREAM_PATCH,
    AUDIO_STREAM_CALL_ASSISTANT,
};

std::vector<audio_mode_t> kAudioModes = {
    AUDIO_MODE_INVALID, AUDIO_MODE_CURRENT,          AUDIO_MODE_NORMAL,     AUDIO_MODE_RINGTONE,
    AUDIO_MODE_IN_CALL, AUDIO_MODE_IN_COMMUNICATION, AUDIO_MODE_CALL_SCREEN};

std::vector<audio_format_t> kFormats = {AUDIO_FORMAT_PCM_16_BIT, AUDIO_FORMAT_PCM_8_BIT,
                                        AUDIO_FORMAT_PCM_32_BIT, AUDIO_FORMAT_PCM_FLOAT};

std::vector<audio_channel_mask_t> kChannelMasks = {AUDIO_CHANNEL_OUT_STEREO, AUDIO_CHANNEL_OUT_MONO,
                                                   AUDIO_CHANNEL_OUT_5POINT1,
                                                   AUDIO_CHANNEL_OUT_7POINT1};

std::vector<audio_channel_mask_t> kRecordChannelMask = {AUDIO_CHANNEL_IN_MONO,
                                                        AUDIO_CHANNEL_IN_STEREO};

std::vector<audio_input_flags_t> kInputFlags = {
    AUDIO_INPUT_FLAG_NONE,    AUDIO_INPUT_FLAG_FAST,       AUDIO_INPUT_FLAG_HW_HOTWORD,
    AUDIO_INPUT_FLAG_RAW,     AUDIO_INPUT_FLAG_SYNC,       AUDIO_INPUT_FLAG_MMAP_NOIRQ,
    AUDIO_INPUT_FLAG_VOIP_TX, AUDIO_INPUT_FLAG_HW_AV_SYNC, AUDIO_INPUT_FLAG_DIRECT,
};

std::vector<audio_output_flags_t> kOutputFlags = {
    AUDIO_OUTPUT_FLAG_NONE,         AUDIO_OUTPUT_FLAG_DIRECT,
    AUDIO_OUTPUT_FLAG_PRIMARY,      AUDIO_OUTPUT_FLAG_FAST,
    AUDIO_OUTPUT_FLAG_DEEP_BUFFER,  AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD,
    AUDIO_OUTPUT_FLAG_NON_BLOCKING, AUDIO_OUTPUT_FLAG_HW_AV_SYNC,
    AUDIO_OUTPUT_FLAG_TTS,          AUDIO_OUTPUT_FLAG_RAW,
    AUDIO_OUTPUT_FLAG_SYNC,         AUDIO_OUTPUT_FLAG_IEC958_NONAUDIO,
    AUDIO_OUTPUT_FLAG_DIRECT_PCM,   AUDIO_OUTPUT_FLAG_MMAP_NOIRQ,
    AUDIO_OUTPUT_FLAG_VOIP_RX,      AUDIO_OUTPUT_FLAG_INCALL_MUSIC,
};

std::vector<audio_session_t> kSessionId = {AUDIO_SESSION_NONE, AUDIO_SESSION_OUTPUT_STAGE,
                                           AUDIO_SESSION_DEVICE};

std::vector<audio_usage_t> kUsage = {
    AUDIO_USAGE_UNKNOWN,
    AUDIO_USAGE_MEDIA,
    AUDIO_USAGE_VOICE_COMMUNICATION,
    AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
    AUDIO_USAGE_ALARM,
    AUDIO_USAGE_NOTIFICATION,
    AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
    AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST,
    AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT,
    AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED,
    AUDIO_USAGE_NOTIFICATION_EVENT,
    AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY,
    AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
    AUDIO_USAGE_ASSISTANCE_SONIFICATION,
    AUDIO_USAGE_GAME,
    AUDIO_USAGE_VIRTUAL_SOURCE,
    AUDIO_USAGE_ASSISTANT,
    AUDIO_USAGE_CALL_ASSISTANT,
    AUDIO_USAGE_EMERGENCY,
    AUDIO_USAGE_SAFETY,
    AUDIO_USAGE_VEHICLE_STATUS,
    AUDIO_USAGE_ANNOUNCEMENT,
};

std::vector<audio_content_type_t> kAudioContentType = {
    AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_CONTENT_TYPE_SPEECH, AUDIO_CONTENT_TYPE_MUSIC,
    AUDIO_CONTENT_TYPE_MOVIE, AUDIO_CONTENT_TYPE_SONIFICATION};

std::vector<audio_source_t> kInputSource = {
    AUDIO_SOURCE_DEFAULT,           AUDIO_SOURCE_MIC,
    AUDIO_SOURCE_VOICE_UPLINK,      AUDIO_SOURCE_VOICE_DOWNLINK,
    AUDIO_SOURCE_VOICE_CALL,        AUDIO_SOURCE_CAMCORDER,
    AUDIO_SOURCE_VOICE_RECOGNITION, AUDIO_SOURCE_VOICE_COMMUNICATION,
    AUDIO_SOURCE_REMOTE_SUBMIX,     AUDIO_SOURCE_UNPROCESSED,
    AUDIO_SOURCE_VOICE_PERFORMANCE, AUDIO_SOURCE_ECHO_REFERENCE,
    AUDIO_SOURCE_FM_TUNER,
};

std::vector<audio_encapsulation_mode_t> kEncapsulation = {
    AUDIO_ENCAPSULATION_MODE_NONE,
    AUDIO_ENCAPSULATION_MODE_ELEMENTARY_STREAM,
    AUDIO_ENCAPSULATION_MODE_HANDLE,
};

std::vector<audio_devices_t> kAudioDevices = {
    AUDIO_DEVICE_NONE,
    AUDIO_DEVICE_OUT_EARPIECE,
    AUDIO_DEVICE_OUT_SPEAKER,
    AUDIO_DEVICE_OUT_WIRED_HEADSET,
    AUDIO_DEVICE_OUT_WIRED_HEADPHONE,
    AUDIO_DEVICE_OUT_BLUETOOTH_SCO,
    AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
    AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,
    AUDIO_DEVICE_OUT_BLUETOOTH_A2DP,
    AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
    AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,
    AUDIO_DEVICE_OUT_HDMI,
    AUDIO_DEVICE_OUT_ANLG_DOCK_HEADSET,
    AUDIO_DEVICE_OUT_DGTL_DOCK_HEADSET,
    AUDIO_DEVICE_OUT_USB_ACCESSORY,
    AUDIO_DEVICE_OUT_USB_DEVICE,
    AUDIO_DEVICE_OUT_REMOTE_SUBMIX,
    AUDIO_DEVICE_OUT_TELEPHONY_TX,
    AUDIO_DEVICE_OUT_LINE,
    AUDIO_DEVICE_OUT_HDMI_ARC,
    AUDIO_DEVICE_OUT_SPDIF,
    AUDIO_DEVICE_OUT_FM,
    AUDIO_DEVICE_OUT_AUX_LINE,
    AUDIO_DEVICE_OUT_SPEAKER_SAFE,
    AUDIO_DEVICE_OUT_IP,
    AUDIO_DEVICE_OUT_BUS,
    AUDIO_DEVICE_OUT_PROXY,
    AUDIO_DEVICE_OUT_USB_HEADSET,
    AUDIO_DEVICE_OUT_HEARING_AID,
    AUDIO_DEVICE_OUT_ECHO_CANCELLER,
    AUDIO_DEVICE_OUT_BLE_HEADSET,
    AUDIO_DEVICE_OUT_BLE_SPEAKER,
    AUDIO_DEVICE_OUT_DEFAULT,
    AUDIO_DEVICE_IN_COMMUNICATION,
    AUDIO_DEVICE_IN_AMBIENT,
    AUDIO_DEVICE_IN_BUILTIN_MIC,
    AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET,
    AUDIO_DEVICE_IN_WIRED_HEADSET,
    AUDIO_DEVICE_IN_HDMI,
    AUDIO_DEVICE_IN_TELEPHONY_RX,
    AUDIO_DEVICE_IN_BACK_MIC,
    AUDIO_DEVICE_IN_REMOTE_SUBMIX,
    AUDIO_DEVICE_IN_ANLG_DOCK_HEADSET,
    AUDIO_DEVICE_IN_DGTL_DOCK_HEADSET,
    AUDIO_DEVICE_IN_USB_ACCESSORY,
    AUDIO_DEVICE_IN_USB_DEVICE,
    AUDIO_DEVICE_IN_FM_TUNER,
    AUDIO_DEVICE_IN_TV_TUNER,
    AUDIO_DEVICE_IN_LINE,
    AUDIO_DEVICE_IN_SPDIF,
    AUDIO_DEVICE_IN_BLUETOOTH_A2DP,
    AUDIO_DEVICE_IN_LOOPBACK,
    AUDIO_DEVICE_IN_IP,
    AUDIO_DEVICE_IN_BUS,
    AUDIO_DEVICE_IN_PROXY,
    AUDIO_DEVICE_IN_USB_HEADSET,
    AUDIO_DEVICE_IN_BLUETOOTH_BLE,
    AUDIO_DEVICE_IN_HDMI_ARC,
    AUDIO_DEVICE_IN_ECHO_REFERENCE,
    AUDIO_DEVICE_IN_BLE_HEADSET,
    AUDIO_DEVICE_IN_DEFAULT,
    AUDIO_DEVICE_OUT_AUX_DIGITAL,
    AUDIO_DEVICE_OUT_STUB,
    AUDIO_DEVICE_IN_VOICE_CALL,
    AUDIO_DEVICE_IN_AUX_DIGITAL,
    AUDIO_DEVICE_IN_STUB,
};

std::vector<audio_source_t> kAudioSource = {
    AUDIO_SOURCE_DEFAULT,           AUDIO_SOURCE_MIC,
    AUDIO_SOURCE_VOICE_UPLINK,      AUDIO_SOURCE_VOICE_DOWNLINK,
    AUDIO_SOURCE_VOICE_CALL,        AUDIO_SOURCE_CAMCORDER,
    AUDIO_SOURCE_VOICE_RECOGNITION, AUDIO_SOURCE_VOICE_COMMUNICATION,
    AUDIO_SOURCE_REMOTE_SUBMIX,     AUDIO_SOURCE_UNPROCESSED,
    AUDIO_SOURCE_VOICE_PERFORMANCE, AUDIO_SOURCE_ECHO_REFERENCE,
    AUDIO_SOURCE_FM_TUNER,          AUDIO_SOURCE_HOTWORD,
};

std::vector<audio_port_role_t> kAudioPortRole = {
    AUDIO_PORT_ROLE_NONE,
    AUDIO_PORT_ROLE_SOURCE,
    AUDIO_PORT_ROLE_SINK,
};

std::vector<audio_port_type_t> kAudioPortType = {
    AUDIO_PORT_TYPE_NONE,
    AUDIO_PORT_TYPE_DEVICE,
    AUDIO_PORT_TYPE_MIX,
    AUDIO_PORT_TYPE_SESSION,
};

std::vector<audio_gain_mode_t> kAudioGainMode = {AUDIO_GAIN_MODE_JOINT, AUDIO_GAIN_MODE_CHANNELS,
                                                 AUDIO_GAIN_MODE_RAMP};

template <typename T>
T getValueFromArray(FuzzedDataProvider *fdp, std::vector<T> arr) {
    return arr[fdp->ConsumeIntegralInRange<int32_t>(0, arr.size() - 1)];
}

template <typename T>
T getValue(FuzzedDataProvider *fdp, std::vector<T> arr) {
    if (fdp->ConsumeBool()) {
        return static_cast<T>(fdp->ConsumeIntegral<int32_t>());
    }
    return getValueFromArray(fdp, arr);
}

class DeathNotifier : public IBinder::DeathRecipient {
   public:
    DeathNotifier() = default;
    ~DeathNotifier() = default;
    void binderDied(const wp<IBinder> &) { abort(); }
};

class AudioFlingerFuzzer {
   public:
    AudioFlingerFuzzer();
    ~AudioFlingerFuzzer() = default;
    void process(const uint8_t *data, size_t size);

   private:
    FuzzedDataProvider *mFdp = nullptr;
    void invokeAudioTrack();
    void invokeAudioRecord();
    void invokeAudioEffect();
    void invokeAudioSystem();
    void invokeAudioInputDevice();
    void invokeAudioOutputDevice();
    void invokeAudioPatch();

    sp<DeathNotifier> mDeathNotifier;
};

AudioFlingerFuzzer::AudioFlingerFuzzer() {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("media.audio_flinger"));
    if (binder == nullptr) {
        return;
    }
    mDeathNotifier = new DeathNotifier();
    binder->linkToDeath(mDeathNotifier);
}

void AudioFlingerFuzzer::invokeAudioTrack() {
    uint32_t sampleRate = mFdp->ConsumeIntegral<uint32_t>();
    audio_format_t format = getValueFromArray(mFdp, kFormats);
    audio_channel_mask_t channelMask = getValueFromArray(mFdp, kChannelMasks);
    size_t frameCount = static_cast<size_t>(mFdp->ConsumeIntegral<uint32_t>());
    int32_t notificationFrames = mFdp->ConsumeIntegral<int32_t>();
    uint32_t useSharedBuffer = mFdp->ConsumeBool();
    audio_output_flags_t flags = getValueFromArray(mFdp, kOutputFlags);
    audio_session_t sessionId = getValueFromArray(mFdp, kSessionId);
    audio_usage_t usage = getValue(mFdp, kUsage);
    audio_content_type_t contentType = getValueFromArray(mFdp, kAudioContentType);
    audio_attributes_t attributes = {};
    sp<IMemory> sharedBuffer = nullptr;
    sp<MemoryDealer> heap = nullptr;
    audio_offload_info_t offloadInfo = AUDIO_INFO_INITIALIZER;

    bool offload = false;
    bool fast = false;

    if (useSharedBuffer != 0) {
        size_t heapSize = audio_channel_count_from_out_mask(channelMask) *
                          audio_bytes_per_sample(format) * frameCount;
        heap = new MemoryDealer(heapSize, "AudioTrack Heap Base");
        sharedBuffer = heap->allocate(heapSize);
        frameCount = 0;
        notificationFrames = 0;
    }
    if ((flags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) != 0) {
        offloadInfo.sample_rate = sampleRate;
        offloadInfo.channel_mask = channelMask;
        offloadInfo.format = format;
        offload = true;
    }
    if ((flags & AUDIO_OUTPUT_FLAG_FAST) != 0) {
        fast = true;
    }

    attributes.content_type = contentType;
    attributes.usage = usage;
    sp<AudioTrack> track = new AudioTrack();

    track->set(AUDIO_STREAM_DEFAULT, sampleRate, format, channelMask, frameCount, flags, nullptr,
               nullptr, notificationFrames, sharedBuffer, false, sessionId,
               ((fast && sharedBuffer == 0) || offload) ? AudioTrack::TRANSFER_CALLBACK
                                                        : AudioTrack::TRANSFER_DEFAULT,
               offload ? &offloadInfo : nullptr, getuid(), getpid(), &attributes, false, 1.0f,
               AUDIO_PORT_HANDLE_NONE);

    status_t status = track->initCheck();
    if (status != NO_ERROR) {
        track.clear();
        return;
    }
    track->getSampleRate();
    track->latency();
    track->getUnderrunCount();
    track->streamType();
    track->channelCount();
    track->getNotificationPeriodInFrames();
    uint32_t bufferSizeInFrames = mFdp->ConsumeIntegral<uint32_t>();
    track->setBufferSizeInFrames(bufferSizeInFrames);
    track->getBufferSizeInFrames();

    int64_t duration = mFdp->ConsumeIntegral<int64_t>();
    track->getBufferDurationInUs(&duration);
    sp<IMemory> sharedBuffer2 = track->sharedBuffer();
    track->setCallerName(mFdp->ConsumeRandomLengthString(MAX_STRING_LENGTH));

    track->setVolume(mFdp->ConsumeFloatingPoint<float>(), mFdp->ConsumeFloatingPoint<float>());
    track->setVolume(mFdp->ConsumeFloatingPoint<float>());
    track->setAuxEffectSendLevel(mFdp->ConsumeFloatingPoint<float>());

    float auxEffectSendLevel;
    track->getAuxEffectSendLevel(&auxEffectSendLevel);
    track->setSampleRate(mFdp->ConsumeIntegral<uint32_t>());
    track->getSampleRate();
    track->getOriginalSampleRate();

    AudioPlaybackRate playbackRate = {};
    playbackRate.mSpeed = mFdp->ConsumeFloatingPoint<float>();
    playbackRate.mPitch = mFdp->ConsumeFloatingPoint<float>();
    track->setPlaybackRate(playbackRate);
    track->getPlaybackRate();
    track->setLoop(mFdp->ConsumeIntegral<uint32_t>(), mFdp->ConsumeIntegral<uint32_t>(),
                   mFdp->ConsumeIntegral<uint32_t>());
    track->setMarkerPosition(mFdp->ConsumeIntegral<uint32_t>());

    uint32_t marker = {};
    track->getMarkerPosition(&marker);
    track->setPositionUpdatePeriod(mFdp->ConsumeIntegral<uint32_t>());

    uint32_t updatePeriod = {};
    track->getPositionUpdatePeriod(&updatePeriod);
    track->setPosition(mFdp->ConsumeIntegral<uint32_t>());
    uint32_t position = {};
    track->getPosition(&position);
    track->getBufferPosition(&position);
    track->reload();
    track->start();
    track->pause();
    track->flush();
    track->stop();
    track->stopped();
}

void AudioFlingerFuzzer::invokeAudioRecord() {
    int32_t notificationFrames = mFdp->ConsumeIntegral<int32_t>();
    uint32_t sampleRate = mFdp->ConsumeIntegral<uint32_t>();
    size_t frameCount = static_cast<size_t>(mFdp->ConsumeIntegral<uint32_t>());
    audio_format_t format = getValue(mFdp, kFormats);
    audio_channel_mask_t channelMask = getValue(mFdp, kChannelMasks);
    audio_input_flags_t flags = getValue(mFdp, kInputFlags);
    audio_session_t sessionId = getValue(mFdp, kSessionId);
    audio_source_t inputSource = getValue(mFdp, kInputSource);

    audio_attributes_t attributes = {};
    bool fast = false;

    if ((flags & AUDIO_INPUT_FLAG_FAST) != 0) {
        fast = true;
    }

    attributes.source = inputSource;

    sp<AudioRecord> record = new AudioRecord(String16(mFdp->ConsumeRandomLengthString().c_str()));
    record->set(AUDIO_SOURCE_DEFAULT, sampleRate, format, channelMask, frameCount, nullptr, nullptr,
                notificationFrames, false, sessionId,
                fast ? AudioRecord::TRANSFER_CALLBACK : AudioRecord::TRANSFER_DEFAULT, flags,
                getuid(), getpid(), &attributes, AUDIO_PORT_HANDLE_NONE);
    status_t status = record->initCheck();
    if (status != NO_ERROR) {
        return;
    }
    record->latency();
    record->format();
    record->channelCount();
    record->frameCount();
    record->frameSize();
    record->inputSource();
    record->getNotificationPeriodInFrames();
    record->start();
    record->stop();
    record->stopped();

    uint32_t marker = mFdp->ConsumeIntegral<uint32_t>();
    record->setMarkerPosition(marker);
    record->getMarkerPosition(&marker);

    uint32_t updatePeriod = mFdp->ConsumeIntegral<uint32_t>();
    record->setPositionUpdatePeriod(updatePeriod);
    record->getPositionUpdatePeriod(&updatePeriod);

    uint32_t position;
    record->getPosition(&position);

    ExtendedTimestamp timestamp;
    record->getTimestamp(&timestamp);
    record->getSessionId();
    record->getCallerName();
    android::AudioRecord::Buffer audioBuffer;
    int32_t waitCount = mFdp->ConsumeIntegral<int32_t>();
    size_t nonContig = static_cast<size_t>(mFdp->ConsumeIntegral<uint32_t>());
    audioBuffer.frameCount = static_cast<size_t>(mFdp->ConsumeIntegral<uint32_t>());
    record->obtainBuffer(&audioBuffer, waitCount, &nonContig);
    bool blocking = false;
    record->read(audioBuffer.raw, audioBuffer.size, blocking);
    record->getInputFramesLost();
    record->getFlags();

    std::vector<media::MicrophoneInfo> activeMicrophones;
    record->getActiveMicrophones(&activeMicrophones);
    record->releaseBuffer(&audioBuffer);

    audio_port_handle_t deviceId =
        static_cast<audio_port_handle_t>(mFdp->ConsumeIntegral<int32_t>());
    record->setInputDevice(deviceId);
    record->getInputDevice();
    record->getRoutedDeviceId();
    record->getPortId();
}

struct EffectClient : public android::BnEffectClient {
    EffectClient() {}
    virtual void controlStatusChanged(bool controlGranted __unused) {}
    virtual void enableStatusChanged(bool enabled __unused) {}
    virtual void commandExecuted(uint32_t cmdCode __unused, uint32_t cmdSize __unused,
                                 void *pCmdData __unused, uint32_t replySize __unused,
                                 void *pReplyData __unused) {}
};

void AudioFlingerFuzzer::invokeAudioEffect() {
    effect_uuid_t type = {0xe46b26a0, 0xdddd, 0x11db, 0x8afd, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};

    effect_descriptor_t descriptor = {};
    descriptor.type = type;
    descriptor.uuid = *EFFECT_UUID_NULL;

    sp<EffectClient> effectClient(new EffectClient());

    const int32_t priority = mFdp->ConsumeIntegral<int32_t>();
    audio_session_t sessionId = static_cast<audio_session_t>(mFdp->ConsumeIntegral<int32_t>());
    const audio_io_handle_t io = mFdp->ConsumeIntegral<int32_t>();
    String16 opPackageName = static_cast<String16>(mFdp->ConsumeRandomLengthString().c_str());
    AudioDeviceTypeAddr device;
    status_t status;
    int32_t id;
    int enabled;

    const sp<IAudioFlinger> &af = AudioSystem::get_audio_flinger();
    if (!af) {
        return;
    }

    sp<IEffect> effect;
    for (int i = 0; i < MAX_EFFECTS; i++) {
        effect = af->createEffect(&descriptor, effectClient, priority, io, sessionId, device,
                                  opPackageName, getpid(), false, &status, &id, &enabled);
    }
    if (!effect) {
        return;
    }

    uint32_t numEffects;
    af->queryNumberEffects(&numEffects);
    if (numEffects) {
        for (int i = 0; i < numEffects; i++) {
            af->queryEffect(i, &descriptor);
        }
    }

    effect_descriptor_t getDescriptor;
    uint32_t preferredTypeFlag = mFdp->ConsumeIntegral<int32_t>();
    af->getEffectDescriptor(&descriptor.uuid, &descriptor.type, preferredTypeFlag, &getDescriptor);

    sessionId = static_cast<audio_session_t>(mFdp->ConsumeIntegral<int32_t>());
    audio_io_handle_t srcOutput = mFdp->ConsumeIntegral<int32_t>();
    audio_io_handle_t dstOutput = mFdp->ConsumeIntegral<int32_t>();
    af->moveEffects(sessionId, srcOutput, dstOutput);

    int effectId = mFdp->ConsumeIntegral<int32_t>();
    sessionId = static_cast<audio_session_t>(mFdp->ConsumeIntegral<int32_t>());
    af->setEffectSuspended(effectId, sessionId, mFdp->ConsumeBool());
}

void AudioFlingerFuzzer::invokeAudioSystem() {
    AudioSystem::muteMicrophone(mFdp->ConsumeBool());
    AudioSystem::setMasterMute(mFdp->ConsumeBool());
    AudioSystem::setMasterVolume(mFdp->ConsumeFloatingPoint<float>());
    AudioSystem::setMasterBalance(mFdp->ConsumeFloatingPoint<float>());
    AudioSystem::setVoiceVolume(mFdp->ConsumeFloatingPoint<float>());

    float volume;
    AudioSystem::getMasterVolume(&volume);

    bool state;
    AudioSystem::getMasterMute(&state);
    AudioSystem::isMicrophoneMuted(&state);

    audio_stream_type_t stream = getValue(mFdp, kStreamtypes);
    AudioSystem::setStreamMute(getValue(mFdp, kStreamtypes), mFdp->ConsumeBool());

    stream = getValue(mFdp, kStreamtypes);
    AudioSystem::setStreamVolume(stream, mFdp->ConsumeFloatingPoint<float>(),
                                 mFdp->ConsumeIntegral<int32_t>());

    audio_mode_t mode = getValue(mFdp, kAudioModes);
    AudioSystem::setMode(mode);

    size_t frameCount;
    stream = getValue(mFdp, kStreamtypes);
    AudioSystem::getOutputFrameCount(&frameCount, stream);

    uint32_t latency;
    stream = getValue(mFdp, kStreamtypes);
    AudioSystem::getOutputLatency(&latency, stream);

    stream = getValue(mFdp, kStreamtypes);
    AudioSystem::getStreamVolume(stream, &volume, mFdp->ConsumeIntegral<int32_t>());

    stream = getValue(mFdp, kStreamtypes);
    AudioSystem::getStreamMute(stream, &state);

    uint32_t samplingRate;
    AudioSystem::getSamplingRate(mFdp->ConsumeIntegral<int32_t>(), &samplingRate);

    AudioSystem::getFrameCount(mFdp->ConsumeIntegral<int32_t>(), &frameCount);
    AudioSystem::getLatency(mFdp->ConsumeIntegral<int32_t>(), &latency);
    AudioSystem::setVoiceVolume(mFdp->ConsumeFloatingPoint<float>());

    uint32_t halFrames;
    uint32_t dspFrames;
    AudioSystem::getRenderPosition(mFdp->ConsumeIntegral<int32_t>(), &halFrames, &dspFrames);

    AudioSystem::getInputFramesLost(mFdp->ConsumeIntegral<int32_t>());
    AudioSystem::getInputFramesLost(mFdp->ConsumeIntegral<int32_t>());

    audio_unique_id_use_t uniqueIdUse = getValue(mFdp, kUniqueIds);
    AudioSystem::newAudioUniqueId(uniqueIdUse);

    audio_session_t sessionId = getValue(mFdp, kSessionId);
    pid_t pid = mFdp->ConsumeBool() ? getpid() : mFdp->ConsumeIntegral<int32_t>();
    uid_t uid = mFdp->ConsumeBool() ? getuid() : mFdp->ConsumeIntegral<int32_t>();
    AudioSystem::acquireAudioSessionId(sessionId, pid, uid);

    pid = mFdp->ConsumeBool() ? getpid() : mFdp->ConsumeIntegral<int32_t>();
    sessionId = getValue(mFdp, kSessionId);
    AudioSystem::releaseAudioSessionId(sessionId, pid);

    sessionId = getValue(mFdp, kSessionId);
    AudioSystem::getAudioHwSyncForSession(sessionId);

    AudioSystem::systemReady();
    AudioSystem::getFrameCountHAL(mFdp->ConsumeIntegral<int32_t>(), &frameCount);

    size_t buffSize;
    uint32_t sampleRate = mFdp->ConsumeIntegral<uint32_t>();
    audio_format_t format = getValue(mFdp, kFormats);
    audio_channel_mask_t channelMask = getValue(mFdp, kChannelMasks);
    AudioSystem::getInputBufferSize(sampleRate, format, channelMask, &buffSize);

    AudioSystem::getPrimaryOutputSamplingRate();
    AudioSystem::getPrimaryOutputFrameCount();
    AudioSystem::setLowRamDevice(mFdp->ConsumeBool(), mFdp->ConsumeIntegral<int64_t>());

    std::vector<media::MicrophoneInfo> microphones;
    AudioSystem::getMicrophones(&microphones);

    std::vector<pid_t> pids;
    pids.insert(pids.begin(), getpid());
    for (int i = 1; i < mFdp->ConsumeIntegralInRange<int32_t>(2, MAX_ARRAY_LENGTH); ++i) {
        pids.insert(pids.begin() + i, static_cast<pid_t>(mFdp->ConsumeIntegral<int32_t>()));
    }
    AudioSystem::setAudioHalPids(pids);
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (!af) {
        return;
    }
    af->setRecordSilenced(mFdp->ConsumeIntegral<uint32_t>(), mFdp->ConsumeBool());

    float balance = mFdp->ConsumeFloatingPoint<float>();
    af->getMasterBalance(&balance);
    af->invalidateStream(static_cast<audio_stream_type_t>(mFdp->ConsumeIntegral<uint32_t>()));
}

void AudioFlingerFuzzer::invokeAudioInputDevice() {
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (!af) {
        return;
    }

    audio_config_t config = {};
    audio_module_handle_t module = mFdp->ConsumeIntegral<int32_t>();
    audio_io_handle_t input = mFdp->ConsumeIntegral<int32_t>();
    config.frame_count = mFdp->ConsumeIntegral<uint32_t>();
    String8 address = static_cast<String8>(mFdp->ConsumeRandomLengthString().c_str());

    config.offload_info = AUDIO_INFO_INITIALIZER;
    config.offload_info.bit_rate = mFdp->ConsumeIntegral<uint32_t>();
    config.offload_info.duration_us = mFdp->ConsumeIntegral<int64_t>();
    config.offload_info.has_video = mFdp->ConsumeBool();
    config.offload_info.is_streaming = mFdp->ConsumeBool();
    config.offload_info.bit_width = mFdp->ConsumeIntegral<uint32_t>();
    config.offload_info.content_id = mFdp->ConsumeIntegral<uint32_t>();
    config.offload_info.sync_id = mFdp->ConsumeIntegral<uint32_t>();

    audio_devices_t device;
    audio_source_t source;
    audio_input_flags_t flags = getValue(mFdp, kInputFlags);

    config.sample_rate = mFdp->ConsumeIntegral<uint32_t>();
    config.offload_info.sample_rate = (mFdp->ConsumeIntegral<uint32_t>());
    config.channel_mask = getValue(mFdp, kChannelMasks);
    config.format = getValue(mFdp, kFormats);
    config.offload_info.channel_mask = getValue(mFdp, kChannelMasks);
    config.offload_info.format = getValue(mFdp, kFormats);
    config.offload_info.stream_type = getValue(mFdp, kStreamtypes);
    config.offload_info.usage = getValue(mFdp, kUsage);
    config.offload_info.encapsulation_mode = getValue(mFdp, kEncapsulation);
    device = getValue(mFdp, kAudioDevices);
    source = getValue(mFdp, kAudioSource);
    flags = getValue(mFdp, kInputFlags);

    af->openInput(module, &input, &config, &device, address, source, flags);
    af->closeInput(input);
}

void AudioFlingerFuzzer::invokeAudioOutputDevice() {
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (!af) {
        return;
    }

    audio_config_t config = {};
    audio_module_handle_t module = mFdp->ConsumeIntegral<int32_t>();
    audio_io_handle_t output = mFdp->ConsumeIntegral<int32_t>();
    config.frame_count = mFdp->ConsumeIntegral<uint32_t>();
    String8 address = static_cast<String8>(mFdp->ConsumeRandomLengthString().c_str());

    config.offload_info = AUDIO_INFO_INITIALIZER;
    config.offload_info.bit_rate = mFdp->ConsumeIntegral<uint32_t>();
    config.offload_info.duration_us = mFdp->ConsumeIntegral<int64_t>();
    config.offload_info.has_video = mFdp->ConsumeBool();
    config.offload_info.is_streaming = mFdp->ConsumeBool();
    config.offload_info.bit_width = mFdp->ConsumeIntegral<uint32_t>();
    config.offload_info.content_id = mFdp->ConsumeIntegral<uint32_t>();
    config.offload_info.sync_id = mFdp->ConsumeIntegral<uint32_t>();

    sp<DeviceDescriptorBase> device;
    audio_output_flags_t flags = getValue(mFdp, kOutputFlags);

    config.sample_rate = mFdp->ConsumeIntegral<uint32_t>();
    config.offload_info.sample_rate = mFdp->ConsumeIntegral<uint32_t>();
    config.channel_mask = getValue(mFdp, kChannelMasks);
    config.format = getValue(mFdp, kFormats);
    config.offload_info.channel_mask = getValue(mFdp, kChannelMasks);
    config.offload_info.format = getValue(mFdp, kFormats);
    config.offload_info.stream_type = getValue(mFdp, kStreamtypes);
    config.offload_info.usage = getValue(mFdp, kUsage);
    config.offload_info.encapsulation_mode = getValue(mFdp, kEncapsulation);
    flags = getValue(mFdp, kOutputFlags);
    device = new DeviceDescriptorBase(getValue(mFdp, kAudioDevices));
    uint32_t latencyMs = mFdp->ConsumeIntegral<uint32_t>();
    af->openOutput(module, &output, &config, device, &latencyMs, flags);

    audio_io_handle_t output1 = mFdp->ConsumeIntegral<int32_t>();
    af->openDuplicateOutput(output, output1);
    af->suspendOutput(output);
    af->restoreOutput(output);
    af->closeOutput(output);
}

void AudioFlingerFuzzer::invokeAudioPatch() {
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (!af) {
        return;
    }
    struct audio_patch patch = {};
    audio_patch_handle_t handle = mFdp->ConsumeIntegral<int32_t>();

    patch.id = mFdp->ConsumeIntegral<int32_t>();
    patch.num_sources = mFdp->ConsumeIntegral<uint32_t>();
    patch.num_sinks = mFdp->ConsumeIntegral<uint32_t>();

    for (int i = 0; i < AUDIO_PATCH_PORTS_MAX; ++i) {
        patch.sources[i].config_mask = mFdp->ConsumeIntegral<uint32_t>();
        patch.sources[i].sample_rate = mFdp->ConsumeIntegral<uint32_t>();
        patch.sources[i].id = static_cast<audio_format_t>(mFdp->ConsumeIntegral<int32_t>());
        patch.sinks[i].config_mask = mFdp->ConsumeIntegral<uint32_t>();
        patch.sinks[i].sample_rate = mFdp->ConsumeIntegral<uint32_t>();
        patch.sinks[i].id = static_cast<audio_format_t>(mFdp->ConsumeIntegral<int32_t>());
        patch.sources[i].gain.index = mFdp->ConsumeIntegral<int32_t>();
        patch.sinks[i].gain.index = mFdp->ConsumeIntegral<int32_t>();
        patch.sources[i].gain.ramp_duration_ms = mFdp->ConsumeIntegral<uint32_t>();
        patch.sinks[i].gain.ramp_duration_ms = mFdp->ConsumeIntegral<uint32_t>();
        patch.sources[i].sample_rate = mFdp->ConsumeIntegral<uint32_t>();

        patch.sources[i].role = getValue(mFdp, kAudioPortRole);
        patch.sources[i].type = getValue(mFdp, kAudioPortType);
        patch.sources[i].channel_mask = getValue(mFdp, kChannelMasks);
        patch.sources[i].format = getValue(mFdp, kFormats);
        patch.sources[i].gain.mode = getValue(mFdp, kAudioGainMode);
        patch.sources[i].gain.channel_mask = getValue(mFdp, kChannelMasks);

        patch.sinks[i].role = getValue(mFdp, kAudioPortRole);
        patch.sinks[i].type = getValue(mFdp, kAudioPortType);
        patch.sinks[i].channel_mask = getValue(mFdp, kChannelMasks);
        patch.sinks[i].format = getValue(mFdp, kFormats);
        patch.sinks[i].gain.mode = getValue(mFdp, kAudioGainMode);
        patch.sinks[i].gain.channel_mask = getValue(mFdp, kChannelMasks);
    }

    af->createAudioPatch(&patch, &handle);
    unsigned int num_patches = mFdp->ConsumeIntegral<uint32_t>();
    struct audio_patch patches = {};
    af->listAudioPatches(&num_patches, &patches);
    af->releaseAudioPatch(handle);
}

void AudioFlingerFuzzer::process(const uint8_t *data, size_t size) {
    mFdp = new FuzzedDataProvider(data, size);
    invokeAudioTrack();
    invokeAudioRecord();
    invokeAudioEffect();
    invokeAudioSystem();
    invokeAudioInputDevice();
    invokeAudioOutputDevice();
    invokeAudioPatch();
    delete mFdp;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    AudioFlingerFuzzer audioFuzzer;
    audioFuzzer.process(data, size);
    return 0;
}
