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
#include <fuzzer/FuzzedDataProvider.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <Serializer.h>
#include <android-base/file.h>
#include <libxml/parser.h>
#include <libxml/xinclude.h>
#include <media/AudioPolicy.h>
#include <media/PatchBuilder.h>
#include <media/RecordingActivityTracker.h>

#include <AudioPolicyInterface.h>
#include <tests/AudioPolicyManagerTestClient.h>
#include <tests/AudioPolicyTestClient.h>
#include <tests/AudioPolicyTestManager.h>

using namespace android;

using AudioFormat = std::pair<audio_format_t, std::string>;

std::vector<AudioFormat> kAudioFormats = {
    AudioFormat(AUDIO_FORMAT_PCM_16_BIT, "AUDIO_FORMAT_PCM_16_BIT"),
    AudioFormat(AUDIO_FORMAT_PCM_8_BIT, "AUDIO_FORMAT_PCM_8_BIT"),
    AudioFormat(AUDIO_FORMAT_PCM_32_BIT, "AUDIO_FORMAT_PCM_32_BIT"),
    AudioFormat(AUDIO_FORMAT_PCM_8_24_BIT, "AUDIO_FORMAT_PCM_8_24_BIT"),
    AudioFormat(AUDIO_FORMAT_PCM_FLOAT, "AUDIO_FORMAT_PCM_FLOAT"),
    AudioFormat(AUDIO_FORMAT_PCM_24_BIT_PACKED, "AUDIO_FORMAT_PCM_24_BIT_PACKED"),
    AudioFormat(AUDIO_FORMAT_MP3, "AUDIO_FORMAT_MP3"),
    AudioFormat(AUDIO_FORMAT_AMR_NB, "AUDIO_FORMAT_AMR_NB"),
    AudioFormat(AUDIO_FORMAT_AMR_WB, "AUDIO_FORMAT_AMR_WB"),
    AudioFormat(AUDIO_FORMAT_AAC, "AUDIO_FORMAT_AAC"),
    AudioFormat(AUDIO_FORMAT_AAC_MAIN, "AUDIO_FORMAT_AAC_MAIN"),
    AudioFormat(AUDIO_FORMAT_AAC_LC, "AUDIO_FORMAT_AAC_LC"),
    AudioFormat(AUDIO_FORMAT_AAC_SSR, "AUDIO_FORMAT_AAC_SSR"),
    AudioFormat(AUDIO_FORMAT_AAC_LTP, "AUDIO_FORMAT_AAC_LTP"),
    AudioFormat(AUDIO_FORMAT_AAC_HE_V1, "AUDIO_FORMAT_AAC_HE_V1"),
    AudioFormat(AUDIO_FORMAT_AAC_SCALABLE, "AUDIO_FORMAT_AAC_SCALABLE"),
    AudioFormat(AUDIO_FORMAT_AAC_ERLC, "AUDIO_FORMAT_AAC_ERLC"),
    AudioFormat(AUDIO_FORMAT_AAC_LD, "AUDIO_FORMAT_AAC_LD"),
    AudioFormat(AUDIO_FORMAT_AAC_HE_V2, "AUDIO_FORMAT_AAC_HE_V2"),
    AudioFormat(AUDIO_FORMAT_AAC_ELD, "AUDIO_FORMAT_AAC_ELD"),
    AudioFormat(AUDIO_FORMAT_AAC_XHE, "AUDIO_FORMAT_AAC_XHE"),
    AudioFormat(AUDIO_FORMAT_HE_AAC_V1, "AUDIO_FORMAT_HE_AAC_V1"),
    AudioFormat(AUDIO_FORMAT_HE_AAC_V2, "AUDIO_FORMAT_HE_AAC_V2"),
    AudioFormat(AUDIO_FORMAT_VORBIS, "AUDIO_FORMAT_VORBIS"),
    AudioFormat(AUDIO_FORMAT_OPUS, "AUDIO_FORMAT_OPUS"),
    AudioFormat(AUDIO_FORMAT_AC3, "AUDIO_FORMAT_AC3"),
    AudioFormat(AUDIO_FORMAT_E_AC3, "AUDIO_FORMAT_E_AC3"),
    AudioFormat(AUDIO_FORMAT_E_AC3_JOC, "AUDIO_FORMAT_E_AC3_JOC"),
    AudioFormat(AUDIO_FORMAT_DTS, "AUDIO_FORMAT_DTS"),
    AudioFormat(AUDIO_FORMAT_DTS_HD, "AUDIO_FORMAT_DTS_HD"),
    AudioFormat(AUDIO_FORMAT_IEC61937, "AUDIO_FORMAT_IEC61937"),
    AudioFormat(AUDIO_FORMAT_DOLBY_TRUEHD, "AUDIO_FORMAT_DOLBY_TRUEHD"),
    AudioFormat(AUDIO_FORMAT_EVRC, "AUDIO_FORMAT_EVRC"),
    AudioFormat(AUDIO_FORMAT_EVRCB, "AUDIO_FORMAT_EVRCB"),
    AudioFormat(AUDIO_FORMAT_EVRCWB, "AUDIO_FORMAT_EVRCWB"),
    AudioFormat(AUDIO_FORMAT_EVRCNW, "AUDIO_FORMAT_EVRCNW"),
    AudioFormat(AUDIO_FORMAT_AAC_ADIF, "AUDIO_FORMAT_AAC_ADIF"),
    AudioFormat(AUDIO_FORMAT_WMA, "AUDIO_FORMAT_WMA"),
    AudioFormat(AUDIO_FORMAT_WMA_PRO, "AUDIO_FORMAT_WMA_PRO"),
    AudioFormat(AUDIO_FORMAT_AMR_WB_PLUS, "AUDIO_FORMAT_AMR_WB_PLUS"),
    AudioFormat(AUDIO_FORMAT_MP2, "AUDIO_FORMAT_MP2"),
    AudioFormat(AUDIO_FORMAT_QCELP, "AUDIO_FORMAT_QCELP"),
    AudioFormat(AUDIO_FORMAT_DSD, "AUDIO_FORMAT_DSD"),
    AudioFormat(AUDIO_FORMAT_FLAC, "AUDIO_FORMAT_FLAC"),
    AudioFormat(AUDIO_FORMAT_ALAC, "AUDIO_FORMAT_ALAC"),
    AudioFormat(AUDIO_FORMAT_APE, "AUDIO_FORMAT_APE"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS, "AUDIO_FORMAT_AAC_ADTS"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS_MAIN, "AUDIO_FORMAT_AAC_ADTS_MAIN"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS_LC, "AUDIO_FORMAT_AAC_ADTS_LC"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS_SSR, "AUDIO_FORMAT_AAC_ADTS_SSR"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS_LTP, "AUDIO_FORMAT_AAC_ADTS_LTP"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS_HE_V1, "AUDIO_FORMAT_AAC_ADTS_HE_V1"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS_SCALABLE, "AUDIO_FORMAT_AAC_ADTS_SCALABLE"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS_ERLC, "AUDIO_FORMAT_AAC_ADTS_ERLC"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS_LD, "AUDIO_FORMAT_AAC_ADTS_LD"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS_HE_V2, "AUDIO_FORMAT_AAC_ADTS_HE_V2"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS_ELD, "AUDIO_FORMAT_AAC_ADTS_ELD"),
    AudioFormat(AUDIO_FORMAT_AAC_ADTS_XHE, "AUDIO_FORMAT_AAC_ADTS_XHE"),
    AudioFormat(AUDIO_FORMAT_SBC, "AUDIO_FORMAT_SBC"),
    AudioFormat(AUDIO_FORMAT_APTX, "AUDIO_FORMAT_APTX"),
    AudioFormat(AUDIO_FORMAT_APTX_HD, "AUDIO_FORMAT_APTX_HD"),
    AudioFormat(AUDIO_FORMAT_AC4, "AUDIO_FORMAT_AC4"),
    AudioFormat(AUDIO_FORMAT_LDAC, "AUDIO_FORMAT_LDAC"),
    AudioFormat(AUDIO_FORMAT_MAT, "AUDIO_FORMAT_MAT"),
    AudioFormat(AUDIO_FORMAT_MAT_1_0, "AUDIO_FORMAT_MAT_1_0"),
    AudioFormat(AUDIO_FORMAT_MAT_2_0, "AUDIO_FORMAT_MAT_2_0"),
    AudioFormat(AUDIO_FORMAT_MAT_2_1, "AUDIO_FORMAT_MAT_2_1"),
    AudioFormat(AUDIO_FORMAT_AAC_LATM, "AUDIO_FORMAT_AAC_LATM"),
    AudioFormat(AUDIO_FORMAT_AAC_LATM_LC, "AUDIO_FORMAT_AAC_LATM_LC"),
    AudioFormat(AUDIO_FORMAT_AAC_LATM_HE_V1, "AUDIO_FORMAT_AAC_LATM_HE_V1"),
    AudioFormat(AUDIO_FORMAT_AAC_LATM_HE_V2, "AUDIO_FORMAT_AAC_LATM_HE_V2"),
    AudioFormat(AUDIO_FORMAT_CELT, "AUDIO_FORMAT_CELT"),
    AudioFormat(AUDIO_FORMAT_APTX_ADAPTIVE, "AUDIO_FORMAT_APTX_ADAPTIVE"),
    AudioFormat(AUDIO_FORMAT_LHDC, "AUDIO_FORMAT_LHDC"),
    AudioFormat(AUDIO_FORMAT_LHDC_LL, "AUDIO_FORMAT_LHDC_LL"),
    AudioFormat(AUDIO_FORMAT_APTX_TWSP, "AUDIO_FORMAT_APTX_TWSP"),
    AudioFormat(AUDIO_FORMAT_LC3, "AUDIO_FORMAT_LC3"),
};

using AudioChannelMask = std::pair<audio_channel_mask_t, std::string>;

std::vector<AudioChannelMask> kAudioChannelOutMasks = {
    AudioChannelMask(AUDIO_CHANNEL_OUT_FRONT_LEFT, "AUDIO_CHANNEL_OUT_FRONT_LEFT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_FRONT_RIGHT, "AUDIO_CHANNEL_OUT_FRONT_RIGHT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_FRONT_CENTER, "AUDIO_CHANNEL_OUT_FRONT_CENTER"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_LOW_FREQUENCY, "AUDIO_CHANNEL_OUT_LOW_FREQUENCY"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_BACK_LEFT, "AUDIO_CHANNEL_OUT_BACK_LEFT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_BACK_RIGHT, "AUDIO_CHANNEL_OUT_BACK_RIGHT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_FRONT_LEFT_OF_CENTER,
                     "AUDIO_CHANNEL_OUT_FRONT_LEFT_OF_CENTER"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_FRONT_RIGHT_OF_CENTER,
                     "AUDIO_CHANNEL_OUT_FRONT_RIGHT_OF_CENTER"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_BACK_CENTER, "AUDIO_CHANNEL_OUT_BACK_CENTER"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_SIDE_LEFT, "AUDIO_CHANNEL_OUT_SIDE_LEFT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_SIDE_RIGHT, "AUDIO_CHANNEL_OUT_SIDE_RIGHT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_TOP_CENTER, "AUDIO_CHANNEL_OUT_TOP_CENTER"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_TOP_FRONT_LEFT, "AUDIO_CHANNEL_OUT_TOP_FRONT_LEFT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_TOP_FRONT_CENTER, "AUDIO_CHANNEL_OUT_TOP_FRONT_CENTER"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_TOP_FRONT_RIGHT, "AUDIO_CHANNEL_OUT_TOP_FRONT_RIGHT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_TOP_BACK_LEFT, "AUDIO_CHANNEL_OUT_TOP_BACK_LEFT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_TOP_BACK_CENTER, "AUDIO_CHANNEL_OUT_TOP_BACK_CENTER"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_TOP_BACK_RIGHT, "AUDIO_CHANNEL_OUT_TOP_BACK_RIGHT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_TOP_SIDE_LEFT, "AUDIO_CHANNEL_OUT_TOP_SIDE_LEFT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_TOP_SIDE_RIGHT, "AUDIO_CHANNEL_OUT_TOP_SIDE_RIGHT"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_HAPTIC_A, "AUDIO_CHANNEL_OUT_HAPTIC_A"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_HAPTIC_B, "AUDIO_CHANNEL_OUT_HAPTIC_B"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_MONO, "AUDIO_CHANNEL_OUT_MONO"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_STEREO, "AUDIO_CHANNEL_OUT_STEREO"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_2POINT1, "AUDIO_CHANNEL_OUT_2POINT1"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_TRI, "AUDIO_CHANNEL_OUT_TRI"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_TRI_BACK, "AUDIO_CHANNEL_OUT_TRI_BACK"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_3POINT1, "AUDIO_CHANNEL_OUT_3POINT1"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_2POINT0POINT2, "AUDIO_CHANNEL_OUT_2POINT0POINT2"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_2POINT1POINT2, "AUDIO_CHANNEL_OUT_2POINT1POINT2"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_3POINT0POINT2, "AUDIO_CHANNEL_OUT_3POINT0POINT2"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_3POINT1POINT2, "AUDIO_CHANNEL_OUT_3POINT1POINT2"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_QUAD, "AUDIO_CHANNEL_OUT_QUAD"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_QUAD_SIDE, "AUDIO_CHANNEL_OUT_QUAD_SIDE"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_SURROUND, "AUDIO_CHANNEL_OUT_SURROUND"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_PENTA, "AUDIO_CHANNEL_OUT_PENTA"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_5POINT1, "AUDIO_CHANNEL_OUT_5POINT1"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_5POINT1_SIDE, "AUDIO_CHANNEL_OUT_5POINT1_SIDE"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_5POINT1POINT2, "AUDIO_CHANNEL_OUT_5POINT1POINT2"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_5POINT1POINT4, "AUDIO_CHANNEL_OUT_5POINT1POINT4"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_6POINT1, "AUDIO_CHANNEL_OUT_6POINT1"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_7POINT1, "AUDIO_CHANNEL_OUT_7POINT1"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_7POINT1POINT2, "AUDIO_CHANNEL_OUT_7POINT1POINT2"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_7POINT1POINT4, "AUDIO_CHANNEL_OUT_7POINT1POINT4"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_MONO_HAPTIC_A, "AUDIO_CHANNEL_OUT_MONO_HAPTIC_A"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_STEREO_HAPTIC_A, "AUDIO_CHANNEL_OUT_STEREO_HAPTIC_A"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_HAPTIC_AB, "AUDIO_CHANNEL_OUT_HAPTIC_AB"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_MONO_HAPTIC_AB, "AUDIO_CHANNEL_OUT_MONO_HAPTIC_AB"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_STEREO_HAPTIC_AB, "AUDIO_CHANNEL_OUT_STEREO_HAPTIC_AB"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_5POINT1_BACK, "AUDIO_CHANNEL_OUT_5POINT1_BACK"),
    AudioChannelMask(AUDIO_CHANNEL_OUT_QUAD_BACK, "AUDIO_CHANNEL_OUT_QUAD_BACK"),
};

std::vector<AudioChannelMask> kAudioChannelInMasks = {
    AudioChannelMask(AUDIO_CHANNEL_IN_LEFT, "AUDIO_CHANNEL_IN_LEFT"),
    AudioChannelMask(AUDIO_CHANNEL_IN_RIGHT, "AUDIO_CHANNEL_IN_RIGHT"),
    AudioChannelMask(AUDIO_CHANNEL_IN_FRONT, "AUDIO_CHANNEL_IN_FRONT"),
    AudioChannelMask(AUDIO_CHANNEL_IN_BACK, "AUDIO_CHANNEL_IN_BACK"),
    AudioChannelMask(AUDIO_CHANNEL_IN_LEFT_PROCESSED, "AUDIO_CHANNEL_IN_LEFT_PROCESSED"),
    AudioChannelMask(AUDIO_CHANNEL_IN_RIGHT_PROCESSED, "AUDIO_CHANNEL_IN_RIGHT_PROCESSED"),
    AudioChannelMask(AUDIO_CHANNEL_IN_FRONT_PROCESSED, "AUDIO_CHANNEL_IN_FRONT_PROCESSED"),
    AudioChannelMask(AUDIO_CHANNEL_IN_BACK_PROCESSED, "AUDIO_CHANNEL_IN_BACK_PROCESSED"),
    AudioChannelMask(AUDIO_CHANNEL_IN_PRESSURE, "AUDIO_CHANNEL_IN_PRESSURE"),
    AudioChannelMask(AUDIO_CHANNEL_IN_X_AXIS, "AUDIO_CHANNEL_IN_X_AXIS"),
    AudioChannelMask(AUDIO_CHANNEL_IN_Y_AXIS, "AUDIO_CHANNEL_IN_Y_AXIS"),
    AudioChannelMask(AUDIO_CHANNEL_IN_Z_AXIS, "AUDIO_CHANNEL_IN_Z_AXIS"),
    AudioChannelMask(AUDIO_CHANNEL_IN_VOICE_UPLINK, "AUDIO_CHANNEL_IN_VOICE_UPLINK"),
    AudioChannelMask(AUDIO_CHANNEL_IN_VOICE_DNLINK, "AUDIO_CHANNEL_IN_VOICE_DNLINK"),
    AudioChannelMask(AUDIO_CHANNEL_IN_BACK_LEFT, "AUDIO_CHANNEL_IN_BACK_LEFT"),
    AudioChannelMask(AUDIO_CHANNEL_IN_BACK_RIGHT, "AUDIO_CHANNEL_IN_BACK_RIGHT"),
    AudioChannelMask(AUDIO_CHANNEL_IN_CENTER, "AUDIO_CHANNEL_IN_CENTER"),
    AudioChannelMask(AUDIO_CHANNEL_IN_LOW_FREQUENCY, "AUDIO_CHANNEL_IN_LOW_FREQUENCY"),
    AudioChannelMask(AUDIO_CHANNEL_IN_TOP_LEFT, "AUDIO_CHANNEL_IN_TOP_LEFT"),
    AudioChannelMask(AUDIO_CHANNEL_IN_TOP_RIGHT, "AUDIO_CHANNEL_IN_TOP_RIGHT"),
    AudioChannelMask(AUDIO_CHANNEL_IN_MONO, "AUDIO_CHANNEL_IN_MONO"),
    AudioChannelMask(AUDIO_CHANNEL_IN_STEREO, "AUDIO_CHANNEL_IN_STEREO"),
    AudioChannelMask(AUDIO_CHANNEL_IN_FRONT_BACK, "AUDIO_CHANNEL_IN_FRONT_BACK"),
    AudioChannelMask(AUDIO_CHANNEL_IN_6, "AUDIO_CHANNEL_IN_6"),
    AudioChannelMask(AUDIO_CHANNEL_IN_2POINT0POINT2, "AUDIO_CHANNEL_IN_2POINT0POINT2"),
    AudioChannelMask(AUDIO_CHANNEL_IN_2POINT1POINT2, "AUDIO_CHANNEL_IN_2POINT1POINT2"),
    AudioChannelMask(AUDIO_CHANNEL_IN_3POINT0POINT2, "AUDIO_CHANNEL_IN_3POINT0POINT2"),
    AudioChannelMask(AUDIO_CHANNEL_IN_3POINT1POINT2, "AUDIO_CHANNEL_IN_3POINT1POINT2"),
    AudioChannelMask(AUDIO_CHANNEL_IN_5POINT1, "AUDIO_CHANNEL_IN_5POINT1"),
    AudioChannelMask(AUDIO_CHANNEL_IN_VOICE_UPLINK_MONO, "AUDIO_CHANNEL_IN_VOICE_UPLINK_MONO"),
    AudioChannelMask(AUDIO_CHANNEL_IN_VOICE_DNLINK_MONO, "AUDIO_CHANNEL_IN_VOICE_DNLINK_MONO"),
    AudioChannelMask(AUDIO_CHANNEL_IN_VOICE_CALL_MONO, "AUDIO_CHANNEL_IN_VOICE_CALL_MONO"),
};

using AudioOutputFlag = std::pair<audio_output_flags_t, std::string>;

std::vector<AudioOutputFlag> kAudioOutputFlags = {
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_NONE, "AUDIO_OUTPUT_FLAG_NONE"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_DIRECT, "AUDIO_OUTPUT_FLAG_DIRECT"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_PRIMARY, "AUDIO_OUTPUT_FLAG_PRIMARY"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_FAST, "AUDIO_OUTPUT_FLAG_FAST"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_DEEP_BUFFER, "AUDIO_OUTPUT_FLAG_DEEP_BUFFER"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD, "AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_NON_BLOCKING, "AUDIO_OUTPUT_FLAG_NON_BLOCKING"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_HW_AV_SYNC, "AUDIO_OUTPUT_FLAG_HW_AV_SYNC"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_TTS, "AUDIO_OUTPUT_FLAG_TTS"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_RAW, "AUDIO_OUTPUT_FLAG_RAW"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_SYNC, "AUDIO_OUTPUT_FLAG_SYNC"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_IEC958_NONAUDIO, "AUDIO_OUTPUT_FLAG_IEC958_NONAUDIO"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_DIRECT_PCM, "AUDIO_OUTPUT_FLAG_DIRECT_PCM"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_MMAP_NOIRQ, "AUDIO_OUTPUT_FLAG_MMAP_NOIRQ"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_VOIP_RX, "AUDIO_OUTPUT_FLAG_VOIP_RX"),
    AudioOutputFlag(AUDIO_OUTPUT_FLAG_INCALL_MUSIC, "AUDIO_OUTPUT_FLAG_INCALL_MUSIC"),
};

std::vector<audio_devices_t> kAudioDevices = {
    AUDIO_DEVICE_OUT_AUX_DIGITAL, AUDIO_DEVICE_OUT_STUB, AUDIO_DEVICE_IN_VOICE_CALL,
    AUDIO_DEVICE_IN_AUX_DIGITAL,  AUDIO_DEVICE_IN_STUB,
};

std::vector<int> kMixTypes = {MIX_TYPE_PLAYERS, MIX_TYPE_RECORDERS};

std::vector<int> kMixRouteFlags = {MIX_ROUTE_FLAG_RENDER, MIX_ROUTE_FLAG_LOOP_BACK,
                                   MIX_ROUTE_FLAG_LOOP_BACK_AND_RENDER, MIX_ROUTE_FLAG_ALL};

std::vector<audio_usage_t> kAudioUsages = {
    AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST, AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT,
    AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED, AUDIO_USAGE_NOTIFICATION_EVENT};

std::vector<audio_source_t> kAudioSources = {
    AUDIO_SOURCE_DEFAULT,           AUDIO_SOURCE_MIC,
    AUDIO_SOURCE_VOICE_UPLINK,      AUDIO_SOURCE_VOICE_DOWNLINK,
    AUDIO_SOURCE_VOICE_CALL,        AUDIO_SOURCE_CAMCORDER,
    AUDIO_SOURCE_VOICE_RECOGNITION, AUDIO_SOURCE_VOICE_COMMUNICATION,
    AUDIO_SOURCE_REMOTE_SUBMIX,     AUDIO_SOURCE_UNPROCESSED,
    AUDIO_SOURCE_VOICE_PERFORMANCE, AUDIO_SOURCE_ECHO_REFERENCE,
    AUDIO_SOURCE_FM_TUNER,          AUDIO_SOURCE_HOTWORD,
};

std::vector<audio_content_type_t> kAudioContentTypes = {
    AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_CONTENT_TYPE_SPEECH,       AUDIO_CONTENT_TYPE_MUSIC,
    AUDIO_CONTENT_TYPE_MOVIE,   AUDIO_CONTENT_TYPE_SONIFICATION,
};

std::vector<audio_flags_mask_t> kAudioFlagMasks = {
    AUDIO_FLAG_NONE,           AUDIO_FLAG_AUDIBILITY_ENFORCED,
    AUDIO_FLAG_SECURE,         AUDIO_FLAG_SCO,
    AUDIO_FLAG_BEACON,         AUDIO_FLAG_HW_AV_SYNC,
    AUDIO_FLAG_HW_HOTWORD,     AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY,
    AUDIO_FLAG_BYPASS_MUTE,    AUDIO_FLAG_LOW_LATENCY,
    AUDIO_FLAG_DEEP_BUFFER,    AUDIO_FLAG_NO_MEDIA_PROJECTION,
    AUDIO_FLAG_MUTE_HAPTIC,    AUDIO_FLAG_NO_SYSTEM_CAPTURE,
    AUDIO_FLAG_CAPTURE_PRIVATE};

std::vector<audio_policy_dev_state_t> kAudioPolicyDeviceStates = {
    AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
    AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
    AUDIO_POLICY_DEVICE_STATE_CNT,
};

template <typename T>
T getValueFromArray(FuzzedDataProvider *fdp, std::vector<T> arr) {
    // code
    return arr[fdp->ConsumeIntegralInRange<int32_t>(0, arr.size() - 1)];
}

class AudioPolicyManagerFuzzer {
   public:
    AudioPolicyManagerFuzzer(FuzzedDataProvider *fdp);
    virtual ~AudioPolicyManagerFuzzer();
    virtual bool initialize();
    virtual void SetUpManagerConfig();
    bool getOutputForAttr(audio_port_handle_t *selectedDeviceId, audio_format_t format,
                          audio_channel_mask_t channelMask, int sampleRate,
                          audio_output_flags_t flags = AUDIO_OUTPUT_FLAG_NONE,
                          audio_io_handle_t *output = nullptr,
                          audio_port_handle_t *portId = nullptr, audio_attributes_t attr = {});
    bool getInputForAttr(const audio_attributes_t &attr, audio_unique_id_t riid,
                         audio_port_handle_t *selectedDeviceId, audio_format_t format,
                         audio_channel_mask_t channelMask, int sampleRate,
                         audio_input_flags_t flags = AUDIO_INPUT_FLAG_NONE,
                         audio_port_handle_t *portId = nullptr);
    bool findDevicePort(audio_port_role_t role, audio_devices_t deviceType,
                        const std::string &address, audio_port *foundPort);
    static audio_port_handle_t getDeviceIdFromPatch(const struct audio_patch *patch);
    audio_patch createRandomPatch();
    void fuzzPatchCreation();
    virtual void process();

   protected:
    std::unique_ptr<AudioPolicyManagerTestClient> mClient;
    std::unique_ptr<AudioPolicyTestManager> mManager;
    FuzzedDataProvider *mFdp;
};

AudioPolicyManagerFuzzer::AudioPolicyManagerFuzzer(FuzzedDataProvider *fdp) {
    mClient.reset(new AudioPolicyManagerTestClient);
    mManager.reset(new AudioPolicyTestManager(mClient.get()));
    mFdp = fdp;
}

AudioPolicyManagerFuzzer::~AudioPolicyManagerFuzzer() {
    mManager.reset();
    mClient.reset();
    mFdp = nullptr;
}

bool AudioPolicyManagerFuzzer::initialize() {
    if (mFdp->remaining_bytes() < 1) {
        return false;
    }
    // init code
    SetUpManagerConfig();

    if (mManager->initialize() != NO_ERROR) {
        return false;
    }
    if (mManager->initCheck() != NO_ERROR) {
        return false;
    }
    return true;
}

void AudioPolicyManagerFuzzer::SetUpManagerConfig() { mManager->getConfig().setDefault(); }

bool AudioPolicyManagerFuzzer::getOutputForAttr(
    audio_port_handle_t *selectedDeviceId, audio_format_t format, audio_channel_mask_t channelMask,
    int sampleRate, audio_output_flags_t flags, audio_io_handle_t *output,
    audio_port_handle_t *portId, audio_attributes_t attr) {
    audio_io_handle_t localOutput;
    if (!output) output = &localOutput;
    *output = AUDIO_IO_HANDLE_NONE;
    audio_stream_type_t stream = AUDIO_STREAM_DEFAULT;
    audio_config_t config = AUDIO_CONFIG_INITIALIZER;
    config.sample_rate = sampleRate;
    config.channel_mask = channelMask;
    config.format = format;
    audio_port_handle_t localPortId;
    if (!portId) portId = &localPortId;
    *portId = AUDIO_PORT_HANDLE_NONE;
    AudioPolicyInterface::output_type_t outputType;

    if (mManager->getOutputForAttr(&attr, output, AUDIO_SESSION_NONE, &stream, 0 /*uid*/, &config,
                                   &flags, selectedDeviceId, portId, {}, &outputType) != OK) {
        return false;
    }
    if (*output == AUDIO_IO_HANDLE_NONE || *portId == AUDIO_PORT_HANDLE_NONE) {
        return false;
    }
    return true;
}

bool AudioPolicyManagerFuzzer::getInputForAttr(
    const audio_attributes_t &attr, audio_unique_id_t riid, audio_port_handle_t *selectedDeviceId,
    audio_format_t format, audio_channel_mask_t channelMask, int sampleRate,
    audio_input_flags_t flags, audio_port_handle_t *portId) {
    audio_io_handle_t input = AUDIO_PORT_HANDLE_NONE;
    audio_config_base_t config = AUDIO_CONFIG_BASE_INITIALIZER;
    config.sample_rate = sampleRate;
    config.channel_mask = channelMask;
    config.format = format;
    audio_port_handle_t localPortId;
    if (!portId) portId = &localPortId;
    *portId = AUDIO_PORT_HANDLE_NONE;
    AudioPolicyInterface::input_type_t inputType;

    if (mManager->getInputForAttr(&attr, &input, riid, AUDIO_SESSION_NONE, 0 /*uid*/, &config,
                                  flags, selectedDeviceId, &inputType, portId) != OK) {
        return false;
    }
    if (*portId == AUDIO_PORT_HANDLE_NONE) {
        return false;
    }
    return true;
}

bool AudioPolicyManagerFuzzer::findDevicePort(audio_port_role_t role, audio_devices_t deviceType,
                                              const std::string &address, audio_port *foundPort) {
    uint32_t numPorts = 0;
    uint32_t generation1;
    status_t ret;

    ret = mManager->listAudioPorts(role, AUDIO_PORT_TYPE_DEVICE, &numPorts, nullptr, &generation1);
    if (ret != NO_ERROR) {
        return false;
    }

    uint32_t generation2;
    struct audio_port ports[numPorts];
    ret = mManager->listAudioPorts(role, AUDIO_PORT_TYPE_DEVICE, &numPorts, ports, &generation2);
    if (ret != NO_ERROR) {
        return false;
    }

    for (const auto &port : ports) {
        if (port.role == role && port.ext.device.type == deviceType &&
            (strncmp(port.ext.device.address, address.c_str(), AUDIO_DEVICE_MAX_ADDRESS_LEN) ==
             0)) {
            if (foundPort) *foundPort = port;
            return true;
        }
    }
    return false;
}

audio_port_handle_t AudioPolicyManagerFuzzer::getDeviceIdFromPatch(
    const struct audio_patch *patch) {
    if (patch->num_sources != 0 && patch->num_sinks != 0) {
        if (patch->sources[0].type == AUDIO_PORT_TYPE_MIX) {
            return patch->sinks[0].id;
        } else {
            return patch->sources[0].id;
        }
    }
    return AUDIO_PORT_HANDLE_NONE;
}

audio_patch AudioPolicyManagerFuzzer::createRandomPatch() {
    audio_patch patch{};
    patch.id = mFdp->ConsumeIntegral<uint32_t>();
    patch.num_sources = mFdp->ConsumeIntegralInRange(0, AUDIO_PATCH_PORTS_MAX);
    for (int i = 0; i < patch.num_sources; ++i) {
        audio_port_config config{};
        std::vector<uint8_t> bytes = mFdp->ConsumeBytes<uint8_t>(sizeof(config));
        memcpy(reinterpret_cast<uint8_t *>(&config), &bytes[0], bytes.size());
        patch.sources[i] = config;
    }
    patch.num_sinks = mFdp->ConsumeIntegralInRange(0, AUDIO_PATCH_PORTS_MAX);
    for (int i = 0; i < patch.num_sinks; ++i) {
        audio_port_config config{};
        std::vector<uint8_t> bytes = mFdp->ConsumeBytes<uint8_t>(sizeof(config));
        memcpy(reinterpret_cast<uint8_t *>(&config), &bytes[0], bytes.size());
        patch.sinks[i] = config;
    }
    return patch;
}

void AudioPolicyManagerFuzzer::fuzzPatchCreation() {
    // Create audio patch from mix
    audio_patch_handle_t handle = AUDIO_PATCH_HANDLE_NONE;
    uid_t uid = mFdp->ConsumeIntegral<uint32_t>();
    if (mManager->getAvailableInputDevices().isEmpty()) {
        return;
    }
    PatchBuilder patchBuilder;
    patchBuilder.addSource(mManager->getAvailableInputDevices()[0])
        .addSink(mManager->getConfig().getDefaultOutputDevice());
    mManager->createAudioPatch(patchBuilder.patch(), &handle, uid);

    if (mFdp->remaining_bytes() < 1) {
        return;
    }
    // create a fuzzed patch
    handle = AUDIO_PATCH_HANDLE_NONE;
    audio_patch patch = createRandomPatch();
    uid = mFdp->ConsumeIntegral<uint32_t>();
    mManager->createAudioPatch(&patch, &handle, uid);
}

void AudioPolicyManagerFuzzer::process() {
    if (!initialize()) {
        return;
    }
    fuzzPatchCreation();
}

class AudioPolicyManagerFuzzerMsd : public AudioPolicyManagerFuzzer {
   public:
    AudioPolicyManagerFuzzerMsd(FuzzedDataProvider *fdp) : AudioPolicyManagerFuzzer(fdp) {}
    virtual ~AudioPolicyManagerFuzzerMsd();
    void process() override;

   protected:
    void SetUpManagerConfig() override;
    sp<DeviceDescriptor> mMsdOutputDevice;
    sp<DeviceDescriptor> mMsdInputDevice;
    std::vector<sp<AudioProfile>> outputProfiles;
    std::vector<sp<AudioProfile>> inputProfiles;
};

AudioPolicyManagerFuzzerMsd::~AudioPolicyManagerFuzzerMsd() {
    mMsdOutputDevice.clear();
    mMsdInputDevice.clear();
    AudioPolicyManagerFuzzer::~AudioPolicyManagerFuzzer();
}

void AudioPolicyManagerFuzzerMsd::SetUpManagerConfig() {
    AudioPolicyManagerFuzzer::SetUpManagerConfig();
    AudioPolicyConfig &config = mManager->getConfig();

    mMsdOutputDevice = new DeviceDescriptor(AUDIO_DEVICE_OUT_BUS);
    outputProfiles.push_back(
        new AudioProfile(AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO, 48000));
    mMsdOutputDevice->addAudioProfile(outputProfiles[0]);
    uint16_t numOutputProfiles = mFdp->ConsumeIntegral<uint16_t>();
    for (int i = 0; i < numOutputProfiles; ++i) {
        outputProfiles.push_back(
            new AudioProfile(getValueFromArray<AudioFormat>(mFdp, kAudioFormats).first,
                             getValueFromArray<AudioChannelMask>(mFdp, kAudioChannelOutMasks).first,
                             mFdp->ConsumeIntegral<uint32_t>()));
        mMsdOutputDevice->addAudioProfile(outputProfiles[i + 1]);
    }

    mMsdInputDevice = new DeviceDescriptor(AUDIO_DEVICE_IN_BUS);
    // Match output profile from AudioPolicyConfig::setDefault.
    inputProfiles.push_back(
        new AudioProfile(AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO, 44100));
    mMsdInputDevice->addAudioProfile(inputProfiles[0]);
    uint16_t numInputProfiles = mFdp->ConsumeIntegral<uint16_t>();
    for (int i = 0; i < numInputProfiles; ++i) {
        inputProfiles.push_back(
            new AudioProfile(getValueFromArray<AudioFormat>(mFdp, kAudioFormats).first,
                             getValueFromArray<AudioChannelMask>(mFdp, kAudioChannelInMasks).first,
                             mFdp->ConsumeIntegral<uint32_t>()));
        mMsdInputDevice->addAudioProfile(inputProfiles[i + 1]);
    }
    config.addDevice(mMsdOutputDevice);
    config.addDevice(mMsdInputDevice);

    sp<HwModule> msdModule = new HwModule(AUDIO_HARDWARE_MODULE_ID_MSD, 2 /*halVersionMajor*/);
    HwModuleCollection modules = config.getHwModules();
    modules.add(msdModule);
    config.setHwModules(modules);

    sp<OutputProfile> msdOutputProfile = new OutputProfile("msd input");
    for (int i = 0; i <= numOutputProfiles; ++i) {
        msdOutputProfile->addAudioProfile(outputProfiles[i]);
    }
    msdOutputProfile->addSupportedDevice(mMsdOutputDevice);
    msdModule->addOutputProfile(msdOutputProfile);
    sp<OutputProfile> msdCompressedOutputProfile = new OutputProfile("msd compressed input");
    for (int i = 0; i <= numOutputProfiles; ++i) {
        msdCompressedOutputProfile->addAudioProfile(outputProfiles[i]);
    }
    msdCompressedOutputProfile->setFlags(AUDIO_OUTPUT_FLAG_DIRECT |
                                         AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD |
                                         AUDIO_OUTPUT_FLAG_NON_BLOCKING);
    msdCompressedOutputProfile->addSupportedDevice(mMsdOutputDevice);
    msdModule->addOutputProfile(msdCompressedOutputProfile);

    sp<InputProfile> msdInputProfile = new InputProfile("msd output");
    for (int i = 0; i <= numInputProfiles; ++i) {
        msdInputProfile->addAudioProfile(inputProfiles[i]);
    }
    msdInputProfile->addSupportedDevice(mMsdInputDevice);
    msdModule->addInputProfile(msdInputProfile);

    // Add profiles with other encodings to the default device to test routing
    // of streams that are not supported by MSD.
    for (int i = 0; i <= numOutputProfiles; ++i) {
        config.getDefaultOutputDevice()->addAudioProfile(outputProfiles[i]);
    }
    sp<OutputProfile> primaryEncodedOutputProfile = new OutputProfile("encoded");
    for (int i = 0; i <= numOutputProfiles; ++i) {
        primaryEncodedOutputProfile->addAudioProfile(outputProfiles[i]);
    }
    primaryEncodedOutputProfile->setFlags(AUDIO_OUTPUT_FLAG_DIRECT);
    primaryEncodedOutputProfile->addSupportedDevice(config.getDefaultOutputDevice());
    config.getHwModules()
        .getModuleFromName(AUDIO_HARDWARE_MODULE_ID_PRIMARY)
        ->addOutputProfile(primaryEncodedOutputProfile);
}

void AudioPolicyManagerFuzzerMsd::process() {
    if (!initialize()) {
        return;
    }
    mManager->setForceUse(AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND,
                          AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS);
    fuzzPatchCreation();

    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_port_handle_t portId;
    for (int i = 0; i < outputProfiles.size(); ++i) {
        sp<AudioProfile> profile = outputProfiles[i];
        audio_format_t audioFormat = profile->getFormat();
        audio_channel_mask_t audioChannel = *profile->getChannels().begin();
        uint32_t sampleRate = *profile->getSampleRates().begin();
        for (int j = 0; j < kAudioOutputFlags.size(); ++j) {
            getOutputForAttr(&selectedDeviceId, audioFormat, audioChannel, sampleRate,
                             kAudioOutputFlags[j].first, nullptr, &portId);
            mManager->releaseOutput(portId);
        }
    }
}

class AudioPolicyManagerFuzzerWithConfigurationFile : public AudioPolicyManagerFuzzer {
   public:
    AudioPolicyManagerFuzzerWithConfigurationFile(FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzer(fdp){};
    virtual ~AudioPolicyManagerFuzzerWithConfigurationFile();

   protected:
    void SetUpManagerConfig() override;
    virtual std::string getConfigFile();
    void traverseAndFuzzXML(xmlDocPtr pDoc, xmlNodePtr curr);
    void fuzzXML(std::string xmlPath);

    static const std::string sExecutableDir;
    static const std::string sDefaultConfig;
    static const std::string sFuzzedConfig;
};

const std::string AudioPolicyManagerFuzzerWithConfigurationFile::sExecutableDir =
    base::GetExecutableDirectory() + "/";

const std::string AudioPolicyManagerFuzzerWithConfigurationFile::sDefaultConfig =
    sExecutableDir + "data/test_audio_policy_configuration.xml";

const std::string AudioPolicyManagerFuzzerWithConfigurationFile::sFuzzedConfig =
    sExecutableDir + "fuzzed.xml";

AudioPolicyManagerFuzzerWithConfigurationFile::~AudioPolicyManagerFuzzerWithConfigurationFile() {
    AudioPolicyManagerFuzzer::~AudioPolicyManagerFuzzer();
}

std::string AudioPolicyManagerFuzzerWithConfigurationFile::getConfigFile() {
    fuzzXML(sDefaultConfig);
    return sFuzzedConfig;
}

void AudioPolicyManagerFuzzerWithConfigurationFile::SetUpManagerConfig() {
    deserializeAudioPolicyFile(getConfigFile().c_str(), &mManager->getConfig());
}

void AudioPolicyManagerFuzzerWithConfigurationFile::traverseAndFuzzXML(xmlDocPtr pDoc,
                                                                       xmlNodePtr curr) {
    if (curr == nullptr) {
        return;
    }

    xmlAttr *attribute = curr->properties;
    while (attribute) {
        if (!xmlStrcmp(attribute->name, reinterpret_cast<const xmlChar *>("format"))) {
            std::string newFormat = getValueFromArray<AudioFormat>(mFdp, kAudioFormats).second;
            xmlSetProp(curr, attribute->name, reinterpret_cast<const xmlChar *>(newFormat.c_str()));
        }
        if (!xmlStrcmp(attribute->name, reinterpret_cast<const xmlChar *>("flags"))) {
            std::string newFlag =
                getValueFromArray<AudioOutputFlag>(mFdp, kAudioOutputFlags).second;
            xmlSetProp(curr, attribute->name, reinterpret_cast<const xmlChar *>(newFlag.c_str()));
        }
        if (!xmlStrcmp(attribute->name, reinterpret_cast<const xmlChar *>("samplingRates"))) {
            std::string newRate = std::to_string(mFdp->ConsumeIntegral<uint32_t>());
            xmlSetProp(curr, attribute->name, reinterpret_cast<const xmlChar *>(newRate.c_str()));
        }
        if (!xmlStrcmp(attribute->name, reinterpret_cast<const xmlChar *>("channelMasks"))) {
            std::string newMask;
            char *value =
                reinterpret_cast<char *>(xmlNodeListGetString(pDoc, attribute->children, 1));
            if (std::string(value).find(std::string("OUT")) != std::string::npos) {
                // OUT mask
                newMask = getValueFromArray<AudioChannelMask>(mFdp, kAudioChannelOutMasks).second;
            } else {
                // IN mask
                newMask = getValueFromArray<AudioChannelMask>(mFdp, kAudioChannelInMasks).second;
            }
            xmlSetProp(curr, attribute->name, reinterpret_cast<const xmlChar *>(newMask.c_str()));
            free(value);
        }
        attribute = attribute->next;
    }

    curr = curr->xmlChildrenNode;
    while (curr != nullptr) {
        traverseAndFuzzXML(pDoc, curr);
        curr = curr->next;
    }
}

void AudioPolicyManagerFuzzerWithConfigurationFile::fuzzXML(std::string xmlPath) {
    std::string outPath = sFuzzedConfig;

    // Load in the xml file from disk
    xmlDocPtr pDoc = xmlParseFile(xmlPath.c_str());
    xmlNodePtr root = xmlDocGetRootElement(pDoc);

    traverseAndFuzzXML(pDoc, root);

    // Save the document back out to disk.
    xmlSaveFileEnc(outPath.c_str(), pDoc, "UTF-8");
    xmlFreeDoc(pDoc);
}

using PolicyMixTuple = std::tuple<audio_usage_t, audio_source_t, uint32_t>;

class AudioPolicyManagerFuzzerDynamicPolicy : public AudioPolicyManagerFuzzerWithConfigurationFile {
   public:
    AudioPolicyManagerFuzzerDynamicPolicy(FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzerWithConfigurationFile(fdp){};
    virtual ~AudioPolicyManagerFuzzerDynamicPolicy();
    void process() override;

   protected:
    status_t addPolicyMix(int mixType, int mixFlag, audio_devices_t deviceType,
                          std::string mixAddress, const audio_config_t &audioConfig,
                          const std::vector<PolicyMixTuple> &rules);
    void clearPolicyMix();
    void registerPolicyMixes();
    void unregisterPolicyMixes();

    Vector<AudioMix> mAudioMixes;
    const std::string mMixAddress = "remote_submix_media";
};

AudioPolicyManagerFuzzerDynamicPolicy::~AudioPolicyManagerFuzzerDynamicPolicy() {
    clearPolicyMix();
    AudioPolicyManagerFuzzerWithConfigurationFile::~AudioPolicyManagerFuzzerWithConfigurationFile();
}

status_t AudioPolicyManagerFuzzerDynamicPolicy::addPolicyMix(
    int mixType, int mixFlag, audio_devices_t deviceType, std::string mixAddress,
    const audio_config_t &audioConfig, const std::vector<PolicyMixTuple> &rules) {
    Vector<AudioMixMatchCriterion> myMixMatchCriteria;

    for (const auto &rule : rules) {
        myMixMatchCriteria.add(
            AudioMixMatchCriterion(std::get<0>(rule), std::get<1>(rule), std::get<2>(rule)));
    }

    AudioMix myAudioMix(myMixMatchCriteria, mixType, audioConfig, mixFlag,
                        String8(mixAddress.c_str()), 0);
    myAudioMix.mDeviceType = deviceType;
    // Clear mAudioMix before add new one to make sure we don't add already existing mixes.
    mAudioMixes.clear();
    mAudioMixes.add(myAudioMix);

    // As the policy mixes registration may fail at some case,
    // caller need to check the returned status.
    status_t ret = mManager->registerPolicyMixes(mAudioMixes);
    return ret;
}

void AudioPolicyManagerFuzzerDynamicPolicy::clearPolicyMix() {
    if (mManager != nullptr) {
        mManager->unregisterPolicyMixes(mAudioMixes);
    }
    mAudioMixes.clear();
}

void AudioPolicyManagerFuzzerDynamicPolicy::registerPolicyMixes() {
    uint32_t numPolicies = mFdp->ConsumeIntegralInRange<uint32_t>(1, MAX_MIXES_PER_POLICY);

    for (int i = 0; i < numPolicies; ++i) {
        audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
        audioConfig.channel_mask =
            getValueFromArray<AudioChannelMask>(
                mFdp, mFdp->ConsumeBool() ? kAudioChannelInMasks : kAudioChannelOutMasks)
                .first;
        audioConfig.format = getValueFromArray<AudioFormat>(mFdp, kAudioFormats).first;
        audioConfig.sample_rate = mFdp->ConsumeIntegral<uint32_t>();
        addPolicyMix(getValueFromArray<int>(mFdp, kMixTypes),
                     getValueFromArray<int>(mFdp, kMixRouteFlags),
                     getValueFromArray<audio_devices_t>(mFdp, kAudioDevices), "", audioConfig,
                     std::vector<PolicyMixTuple>());
    }
}

void AudioPolicyManagerFuzzerDynamicPolicy::unregisterPolicyMixes() {
    mManager->unregisterPolicyMixes(mAudioMixes);
}

void AudioPolicyManagerFuzzerDynamicPolicy::process() {
    if (!initialize()) {
        return;
    }
    registerPolicyMixes();
    fuzzPatchCreation();
    unregisterPolicyMixes();
}

class AudioPolicyManagerFuzzerDPNoRemoteSubmixModule
    : public AudioPolicyManagerFuzzerDynamicPolicy {
   public:
    AudioPolicyManagerFuzzerDPNoRemoteSubmixModule(FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzerDynamicPolicy(fdp){};
    virtual ~AudioPolicyManagerFuzzerDPNoRemoteSubmixModule();

   protected:
    std::string getConfigFile() override;

    static const std::string sPrimaryOnlyConfig;
};

AudioPolicyManagerFuzzerDPNoRemoteSubmixModule::~AudioPolicyManagerFuzzerDPNoRemoteSubmixModule() {
    AudioPolicyManagerFuzzerDynamicPolicy::~AudioPolicyManagerFuzzerDynamicPolicy();
}

const std::string AudioPolicyManagerFuzzerDPNoRemoteSubmixModule::sPrimaryOnlyConfig =
    sExecutableDir + "data/test_audio_policy_primary_only_configuration.xml";

std::string AudioPolicyManagerFuzzerDPNoRemoteSubmixModule::getConfigFile() {
    fuzzXML(sPrimaryOnlyConfig);
    return sFuzzedConfig;
}

class AudioPolicyManagerFuzzerDPPlaybackReRouting : public AudioPolicyManagerFuzzerDynamicPolicy {
   public:
    AudioPolicyManagerFuzzerDPPlaybackReRouting(FuzzedDataProvider *fdp);
    virtual ~AudioPolicyManagerFuzzerDPPlaybackReRouting();
    void process() override;

   protected:
    bool initialize() override;
    void playBackReRouting();

    std::unique_ptr<RecordingActivityTracker> mTracker;

    std::vector<PolicyMixTuple> mUsageRules = {
        {AUDIO_USAGE_MEDIA, AUDIO_SOURCE_DEFAULT, RULE_MATCH_ATTRIBUTE_USAGE},
        {AUDIO_USAGE_ALARM, AUDIO_SOURCE_DEFAULT, RULE_MATCH_ATTRIBUTE_USAGE}};

    struct audio_port mInjectionPort;
    audio_port_handle_t mPortId = AUDIO_PORT_HANDLE_NONE;
    audio_config_t mAudioConfig;
};

AudioPolicyManagerFuzzerDPPlaybackReRouting::AudioPolicyManagerFuzzerDPPlaybackReRouting(
    FuzzedDataProvider *fdp)
    : AudioPolicyManagerFuzzerDynamicPolicy(fdp) {
    uint32_t numRules = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numRules; ++i) {
        PolicyMixTuple rule = {getValueFromArray<audio_usage_t>(mFdp, kAudioUsages),
                               getValueFromArray<audio_source_t>(mFdp, kAudioSources),
                               RULE_MATCH_ATTRIBUTE_USAGE};
        mUsageRules.push_back(rule);
    }
}

AudioPolicyManagerFuzzerDPPlaybackReRouting::~AudioPolicyManagerFuzzerDPPlaybackReRouting() {
    mManager->stopInput(mPortId);
    AudioPolicyManagerFuzzerDynamicPolicy::~AudioPolicyManagerFuzzerDynamicPolicy();
}

bool AudioPolicyManagerFuzzerDPPlaybackReRouting::initialize() {
    AudioPolicyManagerFuzzerDynamicPolicy::initialize();
    mTracker.reset(new RecordingActivityTracker());

    mAudioConfig = AUDIO_CONFIG_INITIALIZER;
    mAudioConfig.channel_mask =
        getValueFromArray<AudioChannelMask>(mFdp, kAudioChannelOutMasks).first;
    mAudioConfig.format = getValueFromArray<AudioFormat>(mFdp, kAudioFormats).first;
    mAudioConfig.sample_rate = mFdp->ConsumeIntegral<uint32_t>();
    status_t ret = addPolicyMix(getValueFromArray<int>(mFdp, kMixTypes),
                                getValueFromArray<int>(mFdp, kMixRouteFlags),
                                getValueFromArray<audio_devices_t>(mFdp, kAudioDevices),
                                mMixAddress, mAudioConfig, mUsageRules);
    if (ret != NO_ERROR) {
        return false;
    }

    struct audio_port extractionPort;
    findDevicePort(AUDIO_PORT_ROLE_SOURCE, getValueFromArray<audio_devices_t>(mFdp, kAudioDevices),
                   mMixAddress, &extractionPort);

    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_source_t source = getValueFromArray<audio_source_t>(mFdp, kAudioSources);
    audio_attributes_t attr = {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, source,
                               AUDIO_FLAG_NONE, ""};
    std::string tags = "addr=" + mMixAddress;
    strncpy(attr.tags, tags.c_str(), AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1);
    getInputForAttr(attr, mTracker->getRiid(), &selectedDeviceId, mAudioConfig.format,
                    mAudioConfig.channel_mask, mAudioConfig.sample_rate, AUDIO_INPUT_FLAG_NONE,
                    &mPortId);

    ret = mManager->startInput(mPortId);
    if (ret != NO_ERROR) {
        return false;
    }
    if (!findDevicePort(AUDIO_PORT_ROLE_SINK,
                        getValueFromArray<audio_devices_t>(mFdp, kAudioDevices), mMixAddress,
                        &mInjectionPort)) {
        return false;
    }

    return true;
}

void AudioPolicyManagerFuzzerDPPlaybackReRouting::playBackReRouting() {
    uint32_t numTestCases = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numTestCases; ++i) {
        audio_attributes_t attr;
        attr.content_type = getValueFromArray<audio_content_type_t>(mFdp, kAudioContentTypes);
        attr.usage = getValueFromArray<audio_usage_t>(mFdp, kAudioUsages);
        attr.source = getValueFromArray<audio_source_t>(mFdp, kAudioSources);
        attr.flags = getValueFromArray<audio_flags_mask_t>(mFdp, kAudioFlagMasks);
        std::string tags(mFdp->ConsumeBool() ? "" : "addr=remote_submix_media");
        strncpy(attr.tags, tags.c_str(), AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1);

        audio_port_handle_t playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
        getOutputForAttr(&playbackRoutedPortId, mAudioConfig.format, mAudioConfig.channel_mask,
                         mAudioConfig.sample_rate, AUDIO_OUTPUT_FLAG_NONE, nullptr /*output*/,
                         nullptr /*portId*/, attr);
    }
}

void AudioPolicyManagerFuzzerDPPlaybackReRouting::process() {
    if (!initialize()) {
        return;
    }
    playBackReRouting();
    registerPolicyMixes();
    fuzzPatchCreation();
    unregisterPolicyMixes();
}

class AudioPolicyManagerFuzzerDPMixRecordInjection : public AudioPolicyManagerFuzzerDynamicPolicy {
   public:
    AudioPolicyManagerFuzzerDPMixRecordInjection(FuzzedDataProvider *fdp);
    virtual ~AudioPolicyManagerFuzzerDPMixRecordInjection();
    void process() override;

   protected:
    bool initialize() override;
    void recordingInjection();

    std::unique_ptr<RecordingActivityTracker> mTracker;

    std::vector<PolicyMixTuple> mSourceRules = {
        {AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_CAMCORDER, RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET},
        {AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_MIC, RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET},
        {AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_VOICE_COMMUNICATION,
         RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET}};

    struct audio_port mExtractionPort;
    audio_port_handle_t mPortId = AUDIO_PORT_HANDLE_NONE;
    audio_config_t mAudioConfig;
};

AudioPolicyManagerFuzzerDPMixRecordInjection::AudioPolicyManagerFuzzerDPMixRecordInjection(
    FuzzedDataProvider *fdp)
    : AudioPolicyManagerFuzzerDynamicPolicy(fdp) {
    uint32_t numRules = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numRules; ++i) {
        PolicyMixTuple rule = {getValueFromArray<audio_usage_t>(mFdp, kAudioUsages),
                               getValueFromArray<audio_source_t>(mFdp, kAudioSources),
                               RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET};
        mSourceRules.push_back(rule);
    }
}

AudioPolicyManagerFuzzerDPMixRecordInjection::~AudioPolicyManagerFuzzerDPMixRecordInjection() {
    mManager->stopOutput(mPortId);
    AudioPolicyManagerFuzzerDynamicPolicy::~AudioPolicyManagerFuzzerDynamicPolicy();
}

bool AudioPolicyManagerFuzzerDPMixRecordInjection::initialize() {
    AudioPolicyManagerFuzzerDynamicPolicy::initialize();

    mTracker.reset(new RecordingActivityTracker());

    mAudioConfig = AUDIO_CONFIG_INITIALIZER;
    mAudioConfig.channel_mask =
        getValueFromArray<AudioChannelMask>(mFdp, kAudioChannelInMasks).first;
    mAudioConfig.format = getValueFromArray<AudioFormat>(mFdp, kAudioFormats).first;
    mAudioConfig.sample_rate = mFdp->ConsumeIntegral<uint32_t>();
    status_t ret = addPolicyMix(getValueFromArray<int>(mFdp, kMixTypes),
                                getValueFromArray<int>(mFdp, kMixRouteFlags),
                                getValueFromArray<audio_devices_t>(mFdp, kAudioDevices),
                                mMixAddress, mAudioConfig, mSourceRules);
    if (ret != NO_ERROR) {
        return false;
    }

    struct audio_port injectionPort;
    findDevicePort(AUDIO_PORT_ROLE_SINK, getValueFromArray<audio_devices_t>(mFdp, kAudioDevices),
                   mMixAddress, &injectionPort);

    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_usage_t usage = getValueFromArray<audio_usage_t>(mFdp, kAudioUsages);
    audio_attributes_t attr = {AUDIO_CONTENT_TYPE_UNKNOWN, usage, AUDIO_SOURCE_DEFAULT,
                               AUDIO_FLAG_NONE, ""};
    std::string tags = std::string("addr=") + mMixAddress;
    strncpy(attr.tags, tags.c_str(), AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1);
    getOutputForAttr(&selectedDeviceId, mAudioConfig.format, mAudioConfig.channel_mask,
                     mAudioConfig.sample_rate /*sampleRate*/, AUDIO_OUTPUT_FLAG_NONE,
                     nullptr /*output*/, &mPortId, attr);
    ret = mManager->startOutput(mPortId);
    if (ret != NO_ERROR) {
        return false;
    }
    getDeviceIdFromPatch(mClient->getLastAddedPatch());
    if (!findDevicePort(AUDIO_PORT_ROLE_SOURCE,
                        getValueFromArray<audio_devices_t>(mFdp, kAudioDevices), mMixAddress,
                        &mExtractionPort)) {
        return false;
    }

    return true;
}

void AudioPolicyManagerFuzzerDPMixRecordInjection::recordingInjection() {
    uint32_t numTestCases = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numTestCases; ++i) {
        audio_attributes_t attr;
        attr.content_type = getValueFromArray<audio_content_type_t>(mFdp, kAudioContentTypes);
        attr.usage = getValueFromArray<audio_usage_t>(mFdp, kAudioUsages);
        attr.source = getValueFromArray<audio_source_t>(mFdp, kAudioSources);
        attr.flags = getValueFromArray<audio_flags_mask_t>(mFdp, kAudioFlagMasks);
        std::string tags(mFdp->ConsumeBool() ? "" : "addr=remote_submix_media");
        strncpy(attr.tags, tags.c_str(), AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1);

        audio_port_handle_t captureRoutedPortId = AUDIO_PORT_HANDLE_NONE;
        audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
        getInputForAttr(attr, mTracker->getRiid(), &captureRoutedPortId, mAudioConfig.format,
                        mAudioConfig.channel_mask, mAudioConfig.sample_rate, AUDIO_INPUT_FLAG_NONE,
                        &portId);
    }
}

void AudioPolicyManagerFuzzerDPMixRecordInjection::process() {
    if (!initialize()) {
        return;
    }
    recordingInjection();
    registerPolicyMixes();
    fuzzPatchCreation();
    unregisterPolicyMixes();
}

using DeviceConnectionTestParams =
    std::tuple<audio_devices_t /*type*/, std::string /*name*/, std::string /*address*/>;

class AudioPolicyManagerFuzzerDeviceConnection
    : public AudioPolicyManagerFuzzerWithConfigurationFile {
   public:
    AudioPolicyManagerFuzzerDeviceConnection(FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzerWithConfigurationFile(fdp){};
    virtual ~AudioPolicyManagerFuzzerDeviceConnection();
    void process() override;

   protected:
    void setDeviceConnectionState();
    void explicitlyRoutingAfterConnection();
};

AudioPolicyManagerFuzzerDeviceConnection::~AudioPolicyManagerFuzzerDeviceConnection() {
    AudioPolicyManagerFuzzerWithConfigurationFile::~AudioPolicyManagerFuzzerWithConfigurationFile();
}

void AudioPolicyManagerFuzzerDeviceConnection::setDeviceConnectionState() {
    uint32_t numTestCases = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numTestCases; ++i) {
        const audio_devices_t type = getValueFromArray<audio_devices_t>(mFdp, kAudioDevices);
        const std::string name = mFdp->ConsumeRandomLengthString();
        const std::string address = mFdp->ConsumeRandomLengthString();
        mManager->setDeviceConnectionState(
            type, getValueFromArray<audio_policy_dev_state_t>(mFdp, kAudioPolicyDeviceStates),
            address.c_str(), name.c_str(),
            getValueFromArray<AudioFormat>(mFdp, kAudioFormats).first);
    }
}

void AudioPolicyManagerFuzzerDeviceConnection::explicitlyRoutingAfterConnection() {
    uint32_t numTestCases = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numTestCases; ++i) {
        const audio_devices_t type = getValueFromArray<audio_devices_t>(mFdp, kAudioDevices);
        const std::string name = mFdp->ConsumeRandomLengthString();
        const std::string address = mFdp->ConsumeRandomLengthString();
        mManager->setDeviceConnectionState(
            type, getValueFromArray<audio_policy_dev_state_t>(mFdp, kAudioPolicyDeviceStates),
            address.c_str(), name.c_str(),
            getValueFromArray<AudioFormat>(mFdp, kAudioFormats).first);

        audio_port devicePort;
        const audio_port_role_t role =
            audio_is_output_device(type) ? AUDIO_PORT_ROLE_SINK : AUDIO_PORT_ROLE_SOURCE;
        findDevicePort(role, type, address, &devicePort);

        audio_port_handle_t routedPortId = devicePort.id;
        // Try start input or output according to the device type
        if (audio_is_output_devices(type)) {
            getOutputForAttr(&routedPortId,
                             getValueFromArray<AudioFormat>(mFdp, kAudioFormats).first,
                             getValueFromArray<AudioChannelMask>(mFdp, kAudioChannelOutMasks).first,
                             mFdp->ConsumeIntegral<uint32_t>(), AUDIO_OUTPUT_FLAG_NONE);
        } else if (audio_is_input_device(type)) {
            RecordingActivityTracker tracker;
            getInputForAttr({}, tracker.getRiid(), &routedPortId,
                            getValueFromArray<AudioFormat>(mFdp, kAudioFormats).first,
                            getValueFromArray<AudioChannelMask>(mFdp, kAudioChannelInMasks).first,
                            mFdp->ConsumeIntegral<uint32_t>(), AUDIO_INPUT_FLAG_NONE);
        }
    }
}

void AudioPolicyManagerFuzzerDeviceConnection::process() {
    if (!initialize()) {
        return;
    }

    setDeviceConnectionState();
    explicitlyRoutingAfterConnection();
    fuzzPatchCreation();
}

class AudioPolicyManagerTVFuzzer : public AudioPolicyManagerFuzzerWithConfigurationFile {
   public:
    AudioPolicyManagerTVFuzzer(FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzerWithConfigurationFile(fdp){};
    virtual ~AudioPolicyManagerTVFuzzer();
    void process() override;

   protected:
    std::string getConfigFile();
    void testHDMIPortSelection(audio_output_flags_t flags);

    static const std::string sTvConfig;
};

const std::string AudioPolicyManagerTVFuzzer::sTvConfig =
    AudioPolicyManagerTVFuzzer::sExecutableDir + "data/test_tv_apm_configuration.xml";

AudioPolicyManagerTVFuzzer::~AudioPolicyManagerTVFuzzer() {
    AudioPolicyManagerFuzzerWithConfigurationFile::~AudioPolicyManagerFuzzerWithConfigurationFile();
}

std::string AudioPolicyManagerTVFuzzer::getConfigFile() {
    fuzzXML(sTvConfig);
    return sFuzzedConfig;
}

void AudioPolicyManagerTVFuzzer::testHDMIPortSelection(audio_output_flags_t flags) {
    audio_devices_t audioDevice = getValueFromArray<audio_devices_t>(mFdp, kAudioDevices);
    audio_format_t audioFormat = getValueFromArray<AudioFormat>(mFdp, kAudioFormats).first;
    status_t ret = mManager->setDeviceConnectionState(
        audioDevice, AUDIO_POLICY_DEVICE_STATE_AVAILABLE, "" /*address*/, "" /*name*/, audioFormat);
    if (ret != NO_ERROR) {
        return;
    }
    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    getOutputForAttr(&selectedDeviceId, getValueFromArray<AudioFormat>(mFdp, kAudioFormats).first,
                     getValueFromArray<AudioChannelMask>(mFdp, kAudioChannelOutMasks).first,
                     mFdp->ConsumeIntegral<uint32_t>(), flags, &output, &portId);
    sp<SwAudioOutputDescriptor> outDesc = mManager->getOutputs().valueFor(output);
    if (outDesc.get() == nullptr) {
        return;
    }
    audio_port port = {};
    outDesc->toAudioPort(&port);
    mManager->releaseOutput(portId);
    mManager->setDeviceConnectionState(audioDevice, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                       "" /*address*/, "" /*name*/, audioFormat);
}

void AudioPolicyManagerTVFuzzer::process() {
    if (!initialize()) {
        return;
    }

    testHDMIPortSelection(getValueFromArray<AudioOutputFlag>(mFdp, kAudioOutputFlags).first);
    fuzzPatchCreation();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    while (fdp.remaining_bytes() > 0) {
        AudioPolicyManagerFuzzer audioPolicyManagerFuzzer(&fdp);
        audioPolicyManagerFuzzer.process();

        AudioPolicyManagerFuzzerMsd audioPolicyManagerFuzzerMsd(&fdp);
        audioPolicyManagerFuzzerMsd.process();

        AudioPolicyManagerFuzzerWithConfigurationFile audioPolicyManagerFuzzerWithConfigurationFile(
            &fdp);
        audioPolicyManagerFuzzerWithConfigurationFile.process();

        AudioPolicyManagerFuzzerDynamicPolicy audioPolicyManagerFuzzerDynamicPolicy(&fdp);
        audioPolicyManagerFuzzerDynamicPolicy.process();

        AudioPolicyManagerFuzzerDPNoRemoteSubmixModule
            audioPolicyManagerFuzzerDPNoRemoteSubmixModule(&fdp);
        audioPolicyManagerFuzzerDPNoRemoteSubmixModule.process();

        AudioPolicyManagerFuzzerDPPlaybackReRouting audioPolicyManagerFuzzerDPPlaybackReRouting(
            &fdp);
        audioPolicyManagerFuzzerDPPlaybackReRouting.process();

        AudioPolicyManagerFuzzerDPMixRecordInjection audioPolicyManagerFuzzerDPMixRecordInjection(
            &fdp);
        audioPolicyManagerFuzzerDPMixRecordInjection.process();

        AudioPolicyManagerFuzzerDeviceConnection audioPolicyManagerFuzzerDeviceConnection(&fdp);
        audioPolicyManagerFuzzerDeviceConnection.process();

        AudioPolicyManagerTVFuzzer audioPolicyManagerTVFuzzer(&fdp);
        audioPolicyManagerTVFuzzer.process();
    }
    return 0;
}
