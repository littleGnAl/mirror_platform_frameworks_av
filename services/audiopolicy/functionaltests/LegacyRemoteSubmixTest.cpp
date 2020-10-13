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

#include "Helper.hpp"

#include <gtest/gtest.h>

using namespace android;

using UsageAndRules = std::vector<std::pair<audio_usage_t, uint32_t>>;
using RemoteSubmixTestParams = std::tuple<const audio_attributes_t>;

class LegacyPlaybackReRoutingTest :
        public ::testing::TestWithParam<RemoteSubmixTestParams>
{
public:
    void SetUp() override
    {
        status_t ret;

        Vector<AudioMixMatchCriterion> myMixMatchCriteria;

        for(const auto &usage: mUsageRules) {
            myMixMatchCriteria.add(AudioMixMatchCriterion(
                                       usage.first, AUDIO_SOURCE_DEFAULT, usage.second));
        }
        audio_config_t config = AUDIO_CONFIG_INITIALIZER;
        config.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
        config.format = AUDIO_FORMAT_PCM_16_BIT;
        config.sample_rate = 48000;


        // Ensure extraction source port has been connected
        std::cerr << "- Ensure extraction source port has been connected--------"  << std::endl;
        audio_port expectedPort {
            .role = AUDIO_PORT_ROLE_SOURCE,
            .type = AUDIO_PORT_TYPE_DEVICE,
            .ext.device.type = AUDIO_DEVICE_IN_REMOTE_SUBMIX,
        };
        strncpy(expectedPort.ext.device.address, mLegacyAddress.c_str(), AUDIO_DEVICE_MAX_ADDRESS_LEN);

        ret = Helper::findPort(expectedPort.role, expectedPort.type, expectedPort.ext.device.type,
                       mLegacyAddress, mExtractionPort);
        ASSERT_EQ(ret, OK)
                << "Could not find extraction port" << Helper::dumpPort(expectedPort);
        std::cerr << "Extraction Port found. " << Helper::dumpPort(mExtractionPort) << std::endl;

        // 3 - Launch the capture
        std::cerr << "- Launch the capture--------"  << std::endl;
        audio_source_t source = AUDIO_SOURCE_REMOTE_SUBMIX;
        audio_attributes_t attr =
            {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, source, AUDIO_FLAG_NONE, ""};
        mAudioRecord = std::make_unique<AudioRecordTest>(attr);
        ASSERT_EQ(OK, mAudioRecord->createAudioRecord())
                << ", Failed to create AudioRecord for: " << toString(attr);

        audio_port_handle_t captureRoutedPortId;
        ret = mAudioRecord->record(captureRoutedPortId);
        ASSERT_EQ(ret, OK) << "failed to start the extraction";

        EXPECT_TRUE(mAudioRecord->waitForDeviceCb()) << "Timeout waiting for Device Callback";
        captureRoutedPortId = mAudioRecord->getRoutedDeviceId();

        ASSERT_EQ(mExtractionPort.id, captureRoutedPortId)
                << "Capture NOT routed on expected port: expecting "
                << Helper::dumpPort(mExtractionPort.id)
                << ", got port:" << Helper::dumpPort(captureRoutedPortId);

        // Ensure extraction injection sink port has been connected
        std::cerr << "- Ensure injection sink port has been connected--------"  << std::endl;
        audio_port expectedSinkPort {
            .role = AUDIO_PORT_ROLE_SINK,
            .type = AUDIO_PORT_TYPE_DEVICE,
            .ext.device.type = AUDIO_DEVICE_OUT_REMOTE_SUBMIX,
        };
        strncpy(expectedSinkPort.ext.device.address, mLegacyAddress.c_str(),
                AUDIO_DEVICE_MAX_ADDRESS_LEN);

        ret = Helper::findPort(expectedSinkPort.role, expectedSinkPort.type,
                               expectedSinkPort.ext.device.type, mLegacyAddress, mInjectionPort);
        ASSERT_EQ(ret, OK) << "Could not find " << Helper::dumpPort(expectedSinkPort);

        std::cerr << "Injection Port found. " << Helper::dumpPort(mInjectionPort) << std::endl;
    }

    void TearDown() override
    {
        status_t ret ;

        // Stop the capture and ensure injection point has been disconnected
        if (mAudioRecord != nullptr) {
            mAudioRecord->stop();
        }
        audio_port port;
        ret = Helper::findPort(mInjectionPort.role, mInjectionPort.type,
                               mInjectionPort.ext.device.type, mLegacyAddress, port);
        EXPECT_NE(ret, NO_ERROR) << "Injection port NOT disconnected: "
                                 << Helper::dumpPort(mInjectionPort);
    }

public:
    Vector<AudioMix> mAudioMixes;
    std::string mLegacyAddress {"0"};
    audio_port mExtractionPort;
    audio_port mInjectionPort;
    std::unique_ptr<AudioRecordTest> mAudioRecord;
    std::vector<std::pair<audio_usage_t, uint32_t>> mUsageRules = {
        {AUDIO_USAGE_MEDIA, RULE_MATCH_ATTRIBUTE_USAGE},
        {AUDIO_USAGE_ALARM, RULE_MATCH_ATTRIBUTE_USAGE}
    };
};

TEST_P(LegacyPlaybackReRoutingTest, playbackReRouting)
{
    const audio_attributes_t attr = std::get<0>(GetParam());
    const audio_usage_t usage = attr.usage;

    std::unique_ptr<AudioTrackTest> audioTrack = std::make_unique<AudioTrackTest>(attr);
    ASSERT_EQ(OK, audioTrack->createTrack()) << "Failed to create AudioTrack with tags: "
            << attr.tags << " for usage: " << toString(usage);

    audio_port_handle_t playbackRoutedPortId;
    EXPECT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
              << "Failed to start AudioTrack with tags: " << attr.tags << " for usage: "
              << toString(usage);

    EXPECT_TRUE(audioTrack->waitForDeviceCb(playbackRoutedPortId)) << "Device callback timeout";
    playbackRoutedPortId = audioTrack->getRoutedDeviceId();

    if ((std::find_if(begin(mUsageRules), end(mUsageRules), [&usage](const auto &usageRule) {
                      return (usageRule.first == usage) &&
                      (usageRule.second == RULE_MATCH_ATTRIBUTE_USAGE);})
            != end(mUsageRules)) ||
            ((strncmp(attr.tags, "addr=", strlen("addr=")) == 0) &&
            (strncmp(attr.tags + strlen("addr="), mLegacyAddress.c_str(),
                     AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - strlen("addr=") - 1) == 0))) {
        EXPECT_EQ(mInjectionPort.id, playbackRoutedPortId)
                << "Injection with tags: " << attr.tags << " for usage: "
                << toString(usage)
                << " NOT routed on expected port: expecting " << Helper::dumpPort(mInjectionPort)
                << ", got port:" << Helper::dumpPort(playbackRoutedPortId);
    } else {
        EXPECT_NE(mInjectionPort.id, playbackRoutedPortId)
                << "Injection with tags: " << attr.tags << " for usage: "
                << toString(usage)
                << " routed on injection port: expecting " << mInjectionPort.id
                << ", got port:" << playbackRoutedPortId;
    }
    // Necessary to avoid a race condition leading to removing an active client.
    while (!audioTrack->hasStarted()) {
        usleep(50);
    }
    audioTrack->stop();
}

INSTANTIATE_TEST_CASE_P(
        PlaybackReroutingUsageMatch,
        LegacyPlaybackReRoutingTest,
        ::testing::Values(
            RemoteSubmixTestParams(attributes_initializer(AUDIO_USAGE_MEDIA)),
            RemoteSubmixTestParams(attributes_initializer(AUDIO_USAGE_ALARM))
            )
        );
