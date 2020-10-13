/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <AudioRecordTest.hpp>

#include <string>
#include <vector>

#include <media/AudioSystem.h>
#include <system/audio_effects/effect_agc.h>
#include <system/audio_effects/effect_ns.h>
#include <system/audio_effects/effect_bassboost.h>
#include <utils/Errors.h>


#include <gtest/gtest.h>

#include "Helper.hpp"

using namespace android;

static const effect_uuid_t FX_IID_VOLUME_ =
    { 0x09e8ede0, 0xddde, 0x11db, 0xb4f6, { 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } };
const effect_uuid_t *const FX_IID_VOLUME = &FX_IID_VOLUME_;

static const effect_uuid_t ANDROID_FX_IID_VOLUME_ =
    { 0x119341a0, 0x8469, 0x11df, 0x81f9, { 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } };
const effect_uuid_t *const ANDROID_FX_IID_VOLUME = &ANDROID_FX_IID_VOLUME_;

static const int VOLUME_PARAM_SIZE_MAX =
        sizeof(effect_param_t) + (3 * sizeof(int16_t)) + (2 * sizeof(int32_t));
static const int32_t VOLUME_PARAM_LEVEL = 0;

static const effect_uuid_t NXP_SL_IID_BASSBOOST_ =
    { 0x8631f300, 0x72e2, 0x11df, 0xb57e, { 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } };
const effect_uuid_t * const NXP_SL_IID_BASSBOOST =  &NXP_SL_IID_BASSBOOST_;

static const effect_uuid_t ANDROID_FX_IID_AGC_ =
    { 0xaa8130e0, 0x66fc, 0x11e0, 0xbad0, { 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } };
const effect_uuid_t * const ANDROID_FX_IID_AGC =  &ANDROID_FX_IID_AGC_;

static const int AGC_PARAM_SIZE_MAX = sizeof(effect_param_t) + (2 * sizeof(int16_t)) + sizeof(bool);
static const int BASSBOOST_PARAM_SIZE_MAX = sizeof(effect_param_t) + 2 * sizeof(int32_t);

static const int gDefaultInputEffectPriority = -1;
static const int gDefaultOutputEffectPriority = 0;

static const String16 gOpPackageName = String16("AudioSourceEffectTest");


static bool isEffectAddedOnTrack(const effect_uuid_t * uuid,
                                 const std::unique_ptr<AudioTrackTest> &audioTrack) {
    // Check effect on our output audio session by trying to take the control using lower
    // than the default's one
    // NOTE: default output effects are created with priority 0
    //       default input effects are create with priority -1
    sp<AudioEffect> postProcEffect = new AudioEffect(gOpPackageName);
    postProcEffect->set(NULL, uuid, gDefaultOutputEffectPriority - 1 , NULL, NULL,
                        audioTrack->getSessionId(), audioTrack->getOutput(), {}, false);

    EXPECT_NE(postProcEffect, nullptr);
    return (postProcEffect != nullptr) &&
            (postProcEffect->initCheck() == ALREADY_EXISTS);
}

static bool isAgcEffectAddedOnRecord(const std::unique_ptr<AudioRecordTest> &audioRecord) {
    // Check effect on our output audio session by trying to take the control using lower
    // than the default's one
    // NOTE: default output effects are created with priority 0
    //       default input effects are create with priority -1
    sp<AudioEffect> preProcEffect = new AudioEffect(gOpPackageName);
    preProcEffect->set(FX_IID_AGC, NULL, gDefaultInputEffectPriority - 1, NULL, NULL,
                       audioRecord->getSessionId(), audioRecord->getInput());

    EXPECT_NE(preProcEffect, nullptr);
    return (preProcEffect != nullptr) &&
            (preProcEffect->initCheck() == ALREADY_EXISTS);
}

static bool isAgcEffectDefaultOnRecord(const std::unique_ptr<AudioRecordTest> &audioRecord) {
    // Ensure NS has been added by default for our input audio session.
    effect_descriptor_t *descriptors =
            new effect_descriptor_t[AudioEffect::kMaxPreProcessing];
    uint32_t numEffects = AudioEffect::kMaxPreProcessing;
    status_t ret = AudioEffect::queryDefaultPreProcessing(
                audioRecord->getSessionId(), descriptors, &numEffects);
    // If no effects requested, the session is even not registered and queryDefaultPreProcessing
    // will not recognize the capture and reply BAD_DATA
    if (ret != OK) {
        return false;
    }
    for (int i = 0; i < numEffects; i++) {
        if (memcmp(&descriptors[i].type, FX_IID_AGC, sizeof(effect_uuid_t)) == 0) {
            return true;
        }
    }
    return false;
}

static bool checkVolumeEffectParameters(const std::unique_ptr<AudioTrackTest> &audioTrack) {
    sp<AudioEffect> postProcEffect = new AudioEffect(gOpPackageName);
    postProcEffect->set(FX_IID_VOLUME, NULL, 10, NULL, NULL, audioTrack->getSessionId(),
                        audioTrack->getOutput());
    status_t ret;
    EXPECT_NE(postProcEffect, nullptr);
    if (postProcEffect != nullptr) {
        ret = postProcEffect->initCheck();
        EXPECT_EQ(OK, ret) << "Failed to initcheck postproc effect ret=" << ret;
    }
    if (postProcEffect == nullptr || ret != OK) {
        return false;
    }
    int errorCount = 0;
    // Set/Get parameter on pre/proc processing effects.
    for(int16_t volume = -8000; volume < -1000; volume+=1000) {
        ret = Helper::setEffectParameter(postProcEffect, VOLUME_PARAM_LEVEL,
                                         VOLUME_PARAM_SIZE_MAX, &volume, sizeof(volume));
        EXPECT_EQ(OK, ret) << "Failed to set param on postproc effect ret=" << ret;
        errorCount += (ret != OK) ? 1 : 0;
        int16_t readVolume;
        ret = Helper::getEffectParameter(postProcEffect, VOLUME_PARAM_LEVEL,
                                         VOLUME_PARAM_SIZE_MAX, &readVolume, sizeof(volume));
        EXPECT_EQ(OK, ret) << "Failed to get param on postproc effect ret=" << ret;
        errorCount += (ret != OK) ? 1 : 0;
        EXPECT_EQ(volume, readVolume) << "Wrong param value returned";
        errorCount += (volume != readVolume) ? 1 : 0;
    }
    postProcEffect.clear();
    return errorCount == 0;
}

static bool checkBBEffectParameters(const std::unique_ptr<AudioTrackTest> &audioTrack) {
    // Take the control on default effects by creating effect with higher Prio.
    sp<AudioEffect> postProcEffect = new AudioEffect(gOpPackageName);
    postProcEffect->set(SL_IID_BASSBOOST, NXP_SL_IID_BASSBOOST, gDefaultOutputEffectPriority + 1,
                        NULL, NULL, audioTrack->getSessionId(), audioTrack->getOutput());
    status_t ret;
    EXPECT_NE(postProcEffect, nullptr);
    if (postProcEffect != nullptr) {
        ret = postProcEffect->initCheck();
        EXPECT_EQ(OK, ret) << "Failed to initcheck postproc effect ret=" << ret;
    }
    if (postProcEffect == nullptr || ret != OK) {
        return false;
    }
    int errorCount = 0;
    // Set/Get parameter on pre/proc processing effects.
    for(int16_t strength = 0; strength < 1000; strength+=100) {
        ret = Helper::setEffectParameter(postProcEffect, BASSBOOST_PARAM_STRENGTH,
                                         BASSBOOST_PARAM_SIZE_MAX, &strength, sizeof(strength));
        EXPECT_EQ(OK, ret) << "Failed to set param on postproc effect ret=" << ret;
        errorCount += (ret != OK) ? 1 : 0;

        int16_t readStrength;
        ret = Helper::getEffectParameter(postProcEffect, BASSBOOST_PARAM_STRENGTH,
                                         BASSBOOST_PARAM_SIZE_MAX, &readStrength,
                                         sizeof(strength));
        EXPECT_EQ(OK, ret) << "Failed to get param on postproc effect ret=" << ret;
        errorCount += (ret != OK) ? 1 : 0;
        EXPECT_EQ(strength, readStrength) << "Wrong param value returned";
        errorCount += (strength != readStrength) ? 1 : 0;
    }
    postProcEffect.clear();
    return errorCount == 0;
}

static bool checkAgcEffectParameters(const std::unique_ptr<AudioRecordTest> &audioRecord) {
    // Take the control on default effects by creating effect with higher Prio.
    sp<AudioEffect> preProcEffect = new AudioEffect(gOpPackageName);
    preProcEffect->set(FX_IID_AGC, NULL, gDefaultOutputEffectPriority + 1, NULL, NULL,
                        audioRecord->getSessionId(), audioRecord->getInput());

    EXPECT_NE(preProcEffect, nullptr);
    status_t ret;
    if (preProcEffect != nullptr) {
        ret = preProcEffect->initCheck();
        EXPECT_EQ(OK, ret) << "Failed to initcheck preProcEffect effect ret=" << ret;
    }
    if (preProcEffect == nullptr || ret != OK) {
        return false;
    }
    int errorCount = 0;
    for(int16_t level = -1000; level < 0; level+=100) {
        ret = Helper::setEffectParameter(preProcEffect, AGC_PARAM_TARGET_LEVEL,
                                         AGC_PARAM_SIZE_MAX, &level, sizeof(level));
        EXPECT_EQ(OK, ret) << "Failed to set param on postproc effect ret=" << ret;
        errorCount += (ret != OK) ? 1 : 0;
        int16_t readLevel;
        ret = Helper::getEffectParameter(preProcEffect, AGC_PARAM_TARGET_LEVEL,
                                         AGC_PARAM_SIZE_MAX, &readLevel, sizeof(readLevel));
        EXPECT_EQ(OK, ret) << "Failed to get param on postproc effect ret=" << ret;
        errorCount += (ret != OK) ? 1 : 0;
        EXPECT_EQ(level, readLevel) << "Wrong param value returned";
        errorCount += (level != readLevel) ? 1 : 0;
    }
    preProcEffect.clear();
    return errorCount == 0;
}

TEST(DefaultEffectTest, UsingDefaultEffectApiForPlayback)
{
    status_t ret;

    audio_attributes_t attributes = {
        .content_type = AUDIO_CONTENT_TYPE_MUSIC, .usage = AUDIO_USAGE_MEDIA,
        .tags = "car_audio_type=3"};
    audio_port expectedSinkPort { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
                .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_MEDIA"};
    audio_port forceUseSpeakerExpectedSinkPort { .role = AUDIO_PORT_ROLE_SINK,
                .type = AUDIO_PORT_TYPE_DEVICE,
                .ext.device.type = AUDIO_DEVICE_OUT_SPEAKER, .ext.device.address = "SPEAKER"};

    char bassboostTypeStr[EFFECT_STRING_LEN_MAX];
    char bassboostUuidStr[EFFECT_STRING_LEN_MAX];
    AudioEffect::guidToString(NXP_SL_IID_BASSBOOST, bassboostUuidStr,
                                       EFFECT_STRING_LEN_MAX);
    AudioEffect::guidToString(SL_IID_BASSBOOST, bassboostTypeStr, EFFECT_STRING_LEN_MAX);

    audio_port sinkPort {};
    audio_port sinkPortForceUseSpeaker {};

    ret = AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA, AUDIO_POLICY_FORCE_NO_BT_A2DP);
    EXPECT_EQ(OK, ret) << "setForceUse failed";

    auto checkDevices = [&]() {
        ASSERT_EQ(OK, Helper::findPort(expectedSinkPort, sinkPort))
                << "Could not find port: " << expectedSinkPort.ext.device.address;

        ret = Helper::findPort(forceUseSpeakerExpectedSinkPort, sinkPortForceUseSpeaker);
        ASSERT_EQ(OK, ret) << "Could not find port :"
                                    << forceUseSpeakerExpectedSinkPort.ext.device.address;
    };

    checkDevices();

    // Start playback
    std::unique_ptr<AudioTrackTest> audioTrack = std::make_unique<AudioTrackTest>(attributes);
    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  toString(attributes);

    audio_port_handle_t playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
              << "Failed to start Playback for attributes: "
              <<  toString(attributes);

    EXPECT_TRUE(audioTrack->waitForDeviceCb(expectedSinkPort.id))
            << "Timeout waiting for Device Callback";

    // Check Patch
    EXPECT_TRUE(Helper::checkPatch(audioTrack->getOutput(), sinkPort.id));

    EXPECT_FALSE(isEffectAddedOnTrack(NXP_SL_IID_BASSBOOST, audioTrack))
            << "BB not defined as default, but was found on session";

    audioTrack->stop();
    audioTrack.reset();

    // Now set BB as default effect for our usage
    audio_unique_id_t bassboostDefaultId;
    ret = AudioEffect::addStreamDefaultEffect(
                bassboostTypeStr, gOpPackageName, bassboostUuidStr, gDefaultOutputEffectPriority,
                AUDIO_USAGE_MEDIA, &bassboostDefaultId);
    EXPECT_EQ(OK, ret) << "addStreamDefaultEffect BB for usage media";

    audioTrack = std::make_unique<AudioTrackTest>(attributes);
    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  toString(attributes);

    playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
            << "Failed to start Playback for attributes: "
            <<  toString(attributes);

    EXPECT_TRUE(audioTrack->waitForDeviceCb(expectedSinkPort.id))
            << "Timeout waiting for Device Callback";

    // Check Patch
    EXPECT_TRUE(Helper::checkPatch(audioTrack->getOutput(), sinkPort.id));

    EXPECT_TRUE(isEffectAddedOnTrack(NXP_SL_IID_BASSBOOST, audioTrack))
            << "BB defined as default, but NOT found on session";


    EXPECT_TRUE(checkBBEffectParameters(audioTrack));

    // Now moving output to speaker and ensure effects are following our output
    ret = AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA, AUDIO_POLICY_FORCE_SPEAKER);
    EXPECT_EQ(OK, ret) << "setForceUse failed";
    EXPECT_TRUE(audioTrack->waitForDeviceCb(sinkPortForceUseSpeaker.id))
            << "Timeout waiting for Device Callback";

    // Check Patch
    EXPECT_TRUE(Helper::checkPatch(audioTrack->getOutput(), sinkPortForceUseSpeaker.id));
    EXPECT_TRUE(isEffectAddedOnTrack(NXP_SL_IID_BASSBOOST, audioTrack))
            << "BB defined as default, but NOT found on session";
    EXPECT_TRUE(checkBBEffectParameters(audioTrack));

    sleep(1);

    ret = AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA, AUDIO_POLICY_FORCE_NO_BT_A2DP);
    EXPECT_EQ(OK, ret) << "setForceUse failed";
    EXPECT_TRUE(audioTrack->waitForDeviceCb(sinkPort.id))
            << "Timeout waiting for Device Callback";

    EXPECT_TRUE(Helper::checkPatch(audioTrack->getOutput(), sinkPort.id));
    EXPECT_TRUE(isEffectAddedOnTrack(NXP_SL_IID_BASSBOOST, audioTrack))
            << "Expected default effects from XML file not added";
    EXPECT_TRUE(checkBBEffectParameters(audioTrack));

    sleep(1);

    audioTrack->stop();
    audioTrack.reset();

    // Remove default effect
    ret = AudioEffect::removeStreamDefaultEffect(bassboostDefaultId);
    EXPECT_EQ(OK, ret) << "removeStreamDefaultEffect for Media usage failed";

     // Start new track and ensure BB is not added by default anymore
    audioTrack = std::make_unique<AudioTrackTest>(attributes);
    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  toString(attributes);

    playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
            << "Failed to start Playback for attributes: "
            <<  toString(attributes);

    EXPECT_TRUE(audioTrack->waitForDeviceCb(expectedSinkPort.id))
            << "Timeout waiting for Device Callback";

    // Check Patch
    EXPECT_TRUE(Helper::checkPatch(audioTrack->getOutput(), sinkPort.id));

    EXPECT_FALSE(isEffectAddedOnTrack(NXP_SL_IID_BASSBOOST, audioTrack))
            << "BB NOT defined as default, but found on session";
    audioTrack->stop();
}

TEST(DefaultEffectTest, RemoveDefaultOutputEffectWhileActiveTrack)
{
    status_t ret;

    audio_attributes_t attributes = {
        .content_type = AUDIO_CONTENT_TYPE_MUSIC, .usage = AUDIO_USAGE_MEDIA,
        .tags = "car_audio_type=3"};
    audio_port expectedSinkPort { .role = AUDIO_PORT_ROLE_SINK, .type = AUDIO_PORT_TYPE_DEVICE,
                .ext.device.type = AUDIO_DEVICE_OUT_BUS, .ext.device.address = "BUS00_MEDIA"};
    audio_port forceUseSpeakerExpectedSinkPort { .role = AUDIO_PORT_ROLE_SINK,
                .type = AUDIO_PORT_TYPE_DEVICE,
                .ext.device.type = AUDIO_DEVICE_OUT_SPEAKER, .ext.device.address = "SPEAKER"};

    char bassboostTypeStr[EFFECT_STRING_LEN_MAX];
    char bassboostUuidStr[EFFECT_STRING_LEN_MAX];
    AudioEffect::guidToString(NXP_SL_IID_BASSBOOST, bassboostUuidStr,
                                       EFFECT_STRING_LEN_MAX);
    AudioEffect::guidToString(SL_IID_BASSBOOST, bassboostTypeStr, EFFECT_STRING_LEN_MAX);

    audio_port sinkPort {};
    audio_port sinkPortForceUseSpeaker {};

    ret = AudioSystem::setForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA, AUDIO_POLICY_FORCE_NO_BT_A2DP);
    EXPECT_EQ(OK, ret) << "setForceUse failed";

    auto checkDevices = [&]() {
        ASSERT_EQ(OK, Helper::findPort(expectedSinkPort, sinkPort))
                << "Could not find port: " << expectedSinkPort.ext.device.address;

        ret = Helper::findPort(forceUseSpeakerExpectedSinkPort, sinkPortForceUseSpeaker);
        ASSERT_EQ(OK, ret) << "Could not find port :"
                                    << forceUseSpeakerExpectedSinkPort.ext.device.address;
    };

    checkDevices();

    // Start playback
    std::unique_ptr<AudioTrackTest> audioTrack = std::make_unique<AudioTrackTest>(attributes);
    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  toString(attributes);

    audio_port_handle_t playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
              << "Failed to start Playback for attributes: "
              <<  toString(attributes);

    EXPECT_TRUE(audioTrack->waitForDeviceCb(expectedSinkPort.id))
            << "Timeout waiting for Device Callback";

    // Check Patch
    EXPECT_TRUE(Helper::checkPatch(audioTrack->getOutput(), sinkPort.id));

    EXPECT_FALSE(isEffectAddedOnTrack(NXP_SL_IID_BASSBOOST, audioTrack))
            << "BB not defined as default, but was found on session";

    audioTrack->stop();
    audioTrack.reset();

    // Now set BB as default effect for our usage
    audio_unique_id_t bassboostDefaultId;
    ret = AudioEffect::addStreamDefaultEffect(
                bassboostTypeStr, gOpPackageName, bassboostUuidStr, gDefaultOutputEffectPriority,
                AUDIO_USAGE_MEDIA, &bassboostDefaultId);
    EXPECT_EQ(OK, ret) << "addStreamDefaultEffect BB for usage media";

    audioTrack = std::make_unique<AudioTrackTest>(attributes);
    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  toString(attributes);

    playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
            << "Failed to start Playback for attributes: "
            <<  toString(attributes);

    EXPECT_TRUE(audioTrack->waitForDeviceCb(expectedSinkPort.id))
            << "Timeout waiting for Device Callback";

    // Check Patch
    EXPECT_TRUE(Helper::checkPatch(audioTrack->getOutput(), sinkPort.id));

    EXPECT_TRUE(isEffectAddedOnTrack(NXP_SL_IID_BASSBOOST, audioTrack))
            << "BB defined as default, but NOT found on session";
    EXPECT_TRUE(checkBBEffectParameters(audioTrack));

    // Remove default effect
    ret = AudioEffect::removeStreamDefaultEffect(bassboostDefaultId);
    EXPECT_EQ(OK, ret) << "removeStreamDefaultEffect for Media usage failed";
    // TODO(b/71814300): Remove from any streams the effect was attached to.
//    EXPECT_FALSE(isEffectAddedOnTrack(NXP_SL_IID_BASSBOOST, audioTrack))
//            << "BB removed from default, but found on session";

    audioTrack->stop();
    audioTrack.reset();

    // Start new track and ensure BB is not added by default anymore
    audioTrack = std::make_unique<AudioTrackTest>(attributes);
    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  toString(attributes);

    playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
            << "Failed to start Playback for attributes: "
            <<  toString(attributes);

    EXPECT_TRUE(audioTrack->waitForDeviceCb(expectedSinkPort.id))
            << "Timeout waiting for Device Callback";

    // Check Patch
    EXPECT_TRUE(Helper::checkPatch(audioTrack->getOutput(), sinkPort.id));

    EXPECT_FALSE(isEffectAddedOnTrack(NXP_SL_IID_BASSBOOST, audioTrack))
            << "BB NOT defined as default, but found on session";
    audioTrack->stop();
}

using UsingAudioEffectXmlParams =
std::tuple<const audio_attributes_t, bool /* expected use effect from XML */>;

class UsingAudioEffectXmlForPlayback : public ::testing::TestWithParam<UsingAudioEffectXmlParams> {
};

TEST_P(UsingAudioEffectXmlForPlayback, UsingAudioEffectXmlForPlayback)
{
    audio_attributes_t attributes = std::get<0>(GetParam());
    bool expectedByDefault =  std::get<1>(GetParam());
    std::unique_ptr<AudioTrackTest> audioTrack = std::make_unique<AudioTrackTest>(attributes);

    // Virtual source MUST be explicitely or dynamically routed...
    if (attributes.usage == AUDIO_USAGE_VIRTUAL_SOURCE) {
        audioTrack.reset();
        audio_port speakerSinkPort { .role = AUDIO_PORT_ROLE_SINK,
                    .type = AUDIO_PORT_TYPE_DEVICE,
                    .ext.device.type = AUDIO_DEVICE_OUT_SPEAKER, .ext.device.address = "SPEAKER"};

        audio_port sinkPort {};
        ASSERT_EQ(OK, Helper::findPort(speakerSinkPort, sinkPort))
                << "Could not find port: " << speakerSinkPort.ext.device.address;

        audioTrack = std::make_unique<AudioTrackTest>(sinkPort.id);
    }


    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  toString(attributes);

    audio_port_handle_t playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
              << "Failed to start Playback for attributes: "
              <<  toString(attributes);

    EXPECT_EQ(isEffectAddedOnTrack(ANDROID_FX_IID_VOLUME, audioTrack), expectedByDefault)
            << " effect unexpected for " << toString(attributes);

    audioTrack->stop();
}

static const std::vector<UsingAudioEffectXmlParams> gPostProcDefaultXmlParams = {
    { attributes_initializer(AUDIO_USAGE_UNKNOWN), true }, // stream defaut = music
    { attributes_initializer(AUDIO_USAGE_MEDIA), true }, // matching stream = music
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION), true }, // matching stream = voice_call
    { attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING), true }, // matching stream = voice_call
    { attributes_initializer(AUDIO_USAGE_ALARM), false },
    { attributes_initializer(AUDIO_USAGE_NOTIFICATION), false },
    { attributes_initializer(AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE), false },
    { attributes_initializer(AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST), false },
    { attributes_initializer(AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT), false },
    { attributes_initializer(AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED), false },
    { attributes_initializer(AUDIO_USAGE_NOTIFICATION_EVENT), false },
    { attributes_initializer(AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY), true }, // stream defaut = music
    { attributes_initializer(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE), true },
    { attributes_initializer(AUDIO_USAGE_ASSISTANCE_SONIFICATION), true }, // matching stream = system
    { attributes_initializer(AUDIO_USAGE_GAME), true }, // matching stream = music
    { attributes_initializer(AUDIO_USAGE_VIRTUAL_SOURCE), true }, // stream defaut = music
    { attributes_initializer(AUDIO_USAGE_ASSISTANT), true } // stream defaut = music
};

INSTANTIATE_TEST_CASE_P(
        DefaultEffectTest,
        UsingAudioEffectXmlForPlayback,
        ::testing::ValuesIn(gPostProcDefaultXmlParams)
        );

class UsingAudioEffectXmlForRecord : public ::testing::TestWithParam<UsingAudioEffectXmlParams> {
};

TEST_P(UsingAudioEffectXmlForRecord, UsingAudioEffectXmlForRecord)
{
    char agcTypeStr[EFFECT_STRING_LEN_MAX];
    char agcUuidStr[EFFECT_STRING_LEN_MAX];
    AudioEffect::guidToString(ANDROID_FX_IID_AGC, agcUuidStr, EFFECT_STRING_LEN_MAX);
    AudioEffect::guidToString(FX_IID_AGC, agcTypeStr, EFFECT_STRING_LEN_MAX);

    audio_attributes_t attr = std::get<0>(GetParam());
    bool expectedByDefault =  std::get<1>(GetParam());

    std::unique_ptr<AudioRecordTest> audioRecord = std::make_unique<AudioRecordTest>(attr);
    ASSERT_EQ(OK, audioRecord->createAudioRecord())
            << ", Failed to create AudioRecord for: " << toString(attr);

    audio_port_handle_t captureRoutedPortId;
    status_t ret = audioRecord->record(captureRoutedPortId);
    ASSERT_EQ(ret, OK) << "failed to start recording";

    EXPECT_TRUE(audioRecord->waitForDeviceCb()) << "Timeout waiting for Device Callback";
    captureRoutedPortId = audioRecord->getRoutedDeviceId();

    std::cerr << "audioRecord session " << audioRecord->getSessionId() << std::endl;
    EXPECT_EQ(isAgcEffectDefaultOnRecord(audioRecord), expectedByDefault);
    EXPECT_EQ(isAgcEffectAddedOnRecord(audioRecord), expectedByDefault);

    audioRecord->stop();
    audioRecord.reset();
}

static inline audio_attributes_t attributes_initializer(audio_source_t source)
{
    audio_attributes_t attributes = AUDIO_ATTRIBUTES_INITIALIZER;
    attributes.source = source;
    return attributes;
}

static const std::vector<UsingAudioEffectXmlParams> gPreProcDefaultXmlParams = {
    { attributes_initializer(AUDIO_SOURCE_DEFAULT), false },
    { attributes_initializer(AUDIO_SOURCE_MIC), false },
    { attributes_initializer(AUDIO_SOURCE_VOICE_UPLINK), false },
    { attributes_initializer(AUDIO_SOURCE_VOICE_DOWNLINK), false },
    { attributes_initializer(AUDIO_SOURCE_VOICE_CALL), false },
    { attributes_initializer(AUDIO_SOURCE_CAMCORDER), false },
    { attributes_initializer(AUDIO_SOURCE_VOICE_RECOGNITION), false },
    { attributes_initializer(AUDIO_SOURCE_VOICE_COMMUNICATION), false },
    { attributes_initializer(AUDIO_SOURCE_REMOTE_SUBMIX), false },
    { attributes_initializer(AUDIO_SOURCE_UNPROCESSED), false },
    { attributes_initializer(AUDIO_SOURCE_VOICE_PERFORMANCE), false },
    { attributes_initializer(AUDIO_SOURCE_ECHO_REFERENCE), false },
    { attributes_initializer(AUDIO_SOURCE_FM_TUNER), true },

};

INSTANTIATE_TEST_CASE_P(
        DefaultEffectTest,
        UsingAudioEffectXmlForRecord,
        ::testing::ValuesIn(gPreProcDefaultXmlParams)
        );

TEST(DefaultEffectTest, UsingDefaultEffectApiForRecord)
{
    char agcTypeStr[EFFECT_STRING_LEN_MAX];
    char agcUuidStr[EFFECT_STRING_LEN_MAX];
    AudioEffect::guidToString(ANDROID_FX_IID_AGC, agcUuidStr, EFFECT_STRING_LEN_MAX);
    AudioEffect::guidToString(FX_IID_AGC, agcTypeStr, EFFECT_STRING_LEN_MAX);

    audio_source_t source = AUDIO_SOURCE_CAMCORDER;
    audio_attributes_t attr =
        {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, source, AUDIO_FLAG_NONE, ""};
    std::unique_ptr<AudioRecordTest> audioRecord = std::make_unique<AudioRecordTest>(attr);
    ASSERT_EQ(OK, audioRecord->createAudioRecord())
            << ", Failed to create AudioRecord for: " << toString(attr);

    audio_port_handle_t captureRoutedPortId;
    status_t ret = audioRecord->record(captureRoutedPortId);
    ASSERT_EQ(ret, OK) << "failed to start the extraction";

    EXPECT_TRUE(audioRecord->waitForDeviceCb()) << "Timeout waiting for Device Callback";
    captureRoutedPortId = audioRecord->getRoutedDeviceId();

    EXPECT_FALSE(isAgcEffectDefaultOnRecord(audioRecord));
    EXPECT_FALSE(isAgcEffectAddedOnRecord(audioRecord));

    audioRecord->stop();
    audioRecord.reset();

    audio_unique_id_t agcDefaultId;
    ret = AudioEffect::addSourceDefaultEffect(
                agcTypeStr, gOpPackageName, agcUuidStr, gDefaultInputEffectPriority,
                AUDIO_SOURCE_CAMCORDER, &agcDefaultId);
    EXPECT_EQ(OK, ret) << "addSourceDefaultEffect for AUDIO_SOURCE_CAMCORDER failed";

    audioRecord = std::make_unique<AudioRecordTest>(attr);
    ASSERT_EQ(OK, audioRecord->createAudioRecord())
            << ", Failed to create AudioRecord for: " << toString(attr);

    captureRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ret = audioRecord->record(captureRoutedPortId);
    ASSERT_EQ(ret, OK) << "failed to start the extraction";

    EXPECT_TRUE(audioRecord->waitForDeviceCb()) << "Timeout waiting for Device Callback";

    EXPECT_TRUE(isAgcEffectDefaultOnRecord(audioRecord));
    EXPECT_TRUE(isAgcEffectAddedOnRecord(audioRecord));
    EXPECT_TRUE(checkAgcEffectParameters(audioRecord));

    audioRecord->stop();
    audioRecord.reset();

    // Remove default effect
    ret = AudioEffect::removeSourceDefaultEffect(agcDefaultId);
    EXPECT_EQ(OK, ret) << "removeSourceDefaultEffect for AUDIO_SOURCE_CAMCORDER failed";

    audioRecord = std::make_unique<AudioRecordTest>(attr);
    ASSERT_EQ(OK, audioRecord->createAudioRecord())
            << ", Failed to create AudioRecord for: " << toString(attr);

    captureRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ret = audioRecord->record(captureRoutedPortId);
    ASSERT_EQ(ret, OK) << "failed to start the extraction";

    EXPECT_TRUE(audioRecord->waitForDeviceCb()) << "Timeout waiting for Device Callback";

    EXPECT_FALSE(isAgcEffectDefaultOnRecord(audioRecord));
    EXPECT_FALSE(isAgcEffectAddedOnRecord(audioRecord));

    audioRecord->stop();
}

TEST(DefaultEffectTest, RemoveDefaultInputEffectWhileRecordTrack)
{
    char agcTypeStr[EFFECT_STRING_LEN_MAX];
    char agcUuidStr[EFFECT_STRING_LEN_MAX];
    AudioEffect::guidToString(ANDROID_FX_IID_AGC, agcUuidStr, EFFECT_STRING_LEN_MAX);
    AudioEffect::guidToString(FX_IID_AGC, agcTypeStr, EFFECT_STRING_LEN_MAX);

    audio_source_t source = AUDIO_SOURCE_CAMCORDER;
    audio_attributes_t attr =
        {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, source, AUDIO_FLAG_NONE, ""};
    std::unique_ptr<AudioRecordTest> audioRecord = std::make_unique<AudioRecordTest>(attr);
    ASSERT_EQ(OK, audioRecord->createAudioRecord())
            << ", Failed to create AudioRecord for: " << toString(attr);

    audio_port_handle_t captureRoutedPortId;
    status_t ret = audioRecord->record(captureRoutedPortId);
    ASSERT_EQ(ret, OK) << "failed to start the extraction";

    EXPECT_TRUE(audioRecord->waitForDeviceCb()) << "Timeout waiting for Device Callback";
    captureRoutedPortId = audioRecord->getRoutedDeviceId();

    EXPECT_FALSE(isAgcEffectDefaultOnRecord(audioRecord));
    EXPECT_FALSE(isAgcEffectAddedOnRecord(audioRecord));

    audioRecord->stop();
    audioRecord.reset();

    audio_unique_id_t agcDefaultId;
    ret = AudioEffect::addSourceDefaultEffect(
                agcTypeStr, gOpPackageName, agcUuidStr, gDefaultInputEffectPriority,
                AUDIO_SOURCE_CAMCORDER, &agcDefaultId);
    EXPECT_EQ(OK, ret) << "addSourceDefaultEffect for AUDIO_SOURCE_CAMCORDER failed";

    audioRecord = std::make_unique<AudioRecordTest>(attr);
    ASSERT_EQ(OK, audioRecord->createAudioRecord())
            << ", Failed to create AudioRecord for: " << toString(attr);

    captureRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ret = audioRecord->record(captureRoutedPortId);
    ASSERT_EQ(ret, OK) << "failed to start the extraction";

    EXPECT_TRUE(audioRecord->waitForDeviceCb()) << "Timeout waiting for Device Callback";

    EXPECT_TRUE(isAgcEffectDefaultOnRecord(audioRecord));
    EXPECT_TRUE(isAgcEffectAddedOnRecord(audioRecord));
    EXPECT_TRUE(checkAgcEffectParameters(audioRecord));

    // Remove default effect
    ret = AudioEffect::removeSourceDefaultEffect(agcDefaultId);
    EXPECT_EQ(OK, ret) << "removeSourceDefaultEffect for AUDIO_SOURCE_CAMCORDER failed";
    // TODO(b/71814300): Remove from any sources the effect was attached to.
    // EXPECT_FALSE(isAgcEffectDefaultOnRecord(audioRecord));
    // EXPECT_FALSE(isAgcEffectAddedOnRecord(audioRecord));

    audioRecord->stop();
    audioRecord.reset();

    audioRecord = std::make_unique<AudioRecordTest>(attr);
    ASSERT_EQ(OK, audioRecord->createAudioRecord())
            << ", Failed to create AudioRecord for: " << toString(attr);

    captureRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ret = audioRecord->record(captureRoutedPortId);
    ASSERT_EQ(ret, OK) << "failed to start the extraction";

    EXPECT_TRUE(audioRecord->waitForDeviceCb()) << "Timeout waiting for Device Callback";

    EXPECT_FALSE(isAgcEffectDefaultOnRecord(audioRecord));
    EXPECT_FALSE(isAgcEffectAddedOnRecord(audioRecord));

    audioRecord->stop();
}
