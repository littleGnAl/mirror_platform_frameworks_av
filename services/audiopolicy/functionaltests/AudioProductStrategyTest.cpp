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

#include <gtest/gtest.h>

#include "AudioTestParams.hpp"

#include "Helper.hpp"

using namespace android;

static void playbackFollowingProductStrategy(
        const product_strategy_t strategy, audio_port &routedDevicePort,
        const audio_port_handle_t expectedPort = AUDIO_PORT_HANDLE_NONE)
{
    std::unique_ptr<AudioTrackTest> audioTrack = std::make_unique<AudioTrackTest>(strategy);
    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for strategy:"
            <<  Helper::dumpProductStrategy(strategy, true);

    audio_port_handle_t playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
              << "Failed to start Playback for strategy: "
              <<  Helper::dumpProductStrategy(strategy, true);

    EXPECT_TRUE(audioTrack->waitForDeviceCb(expectedPort)) << "Timeout waiting for Device Callback";

    // Check routed port
    playbackRoutedPortId = audioTrack->getRoutedDeviceId();
    EXPECT_EQ(NO_ERROR, Helper::getPortById(playbackRoutedPortId, routedDevicePort))
            << "Failed to identify port for strategy: "
            <<  Helper::dumpProductStrategy(strategy, true)
            << " routed on port " << playbackRoutedPortId;

    // Check Patch
    // If no expected routed port, just ensure, the routed device and the track are really
    // connected through an audio patch
    audio_port_handle_t expectedRoutedPortId = expectedPort != AUDIO_PORT_HANDLE_NONE ?
                expectedPort : playbackRoutedPortId;
    EXPECT_TRUE(Helper::checkPatch(audioTrack->getOutput(), expectedRoutedPortId))
            << "No patch found involving mix port " << audioTrack->getOutput()
            << " and device port " << expectedRoutedPortId;

    audioTrack->stop();
}

static void playbackForAttributes(const audio_attributes_t attributes, audio_port &routedDevicePort,
                                  const audio_port_handle_t expectedPort = AUDIO_PORT_HANDLE_NONE)
{
    std::unique_ptr<AudioTrackTest> audioTrack = std::make_unique<AudioTrackTest>(attributes);
    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for attributes: " <<  toString(attributes);

    audio_port_handle_t playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
              << "Failed to start Playback for attributes: "
              <<  toString(attributes);

    EXPECT_TRUE(audioTrack->waitForDeviceCb(expectedPort)) << "Timeout waiting for Device Callback";

    // Check routed port
    playbackRoutedPortId = audioTrack->getRoutedDeviceId();
    EXPECT_EQ(NO_ERROR, Helper::getPortById(playbackRoutedPortId, routedDevicePort))
            << "Failed to identify port for playback by attributes: "
            <<  toString(attributes)
            << " routed on port " << playbackRoutedPortId;

    // Check Patch
    // If no expected routed port, just ensure, the routed device and the track are really
    // connected through an audio patch
    audio_port_handle_t expectedRoutedPortId = expectedPort != AUDIO_PORT_HANDLE_NONE ?
                expectedPort : playbackRoutedPortId;
    EXPECT_TRUE(Helper::checkPatch(audioTrack->getOutput(), expectedRoutedPortId))
            << "No patch found involving mix port " << audioTrack->getOutput()
            << " and device port " << expectedRoutedPortId;

    audioTrack->stop();
}

static void playbackForStream(audio_stream_type_t stream, audio_port &routedDevicePort,
                              const audio_port_handle_t expectedPort = AUDIO_PORT_HANDLE_NONE)
{
    std::unique_ptr<AudioTrackTest> audioTrack = std::make_unique<AudioTrackTest>(stream);
    ASSERT_EQ(OK, audioTrack->createTrack())
            << "Failed to create AudioTrack for stream: " <<  toString(stream);

    audio_port_handle_t playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(OK, audioTrack->playSine(playbackRoutedPortId))
              << "Failed to start Playback for stream: "
              <<  toString(stream);

    EXPECT_TRUE(audioTrack->waitForDeviceCb(expectedPort)) << "Timeout waiting for Device Callback";

    // Check routed port
    playbackRoutedPortId = audioTrack->getRoutedDeviceId();
    EXPECT_EQ(NO_ERROR, Helper::getPortById(playbackRoutedPortId, routedDevicePort))
            << "Failed to identify port for playback by stream: "
            <<  toString(stream)
            << " routed on port " << playbackRoutedPortId;

    // Check Patch
    // If no expected routed port, just ensure, the routed device and the track are really
    // connected through an audio patch
    audio_port_handle_t expectedRoutedPortId = expectedPort != AUDIO_PORT_HANDLE_NONE ?
                expectedPort : playbackRoutedPortId;
    EXPECT_TRUE(Helper::checkPatch(audioTrack->getOutput(), expectedRoutedPortId))
            << "No patch found involving mix port " << audioTrack->getOutput()
            << " and device port " << expectedRoutedPortId;

    audioTrack->stop();
}

TEST(AudioProductStrategiesTest, PlayByStrategy)
{
    status_t ret;
    AudioProductStrategyVector strategies;
    ret = AudioSystem::listAudioProductStrategies(strategies);
    ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::listAudioProductStrategies failed with error: "
                             << ret;

    for (const auto &strategy : strategies) {
        if (!Helper::isPublicStrategy(strategy)) {
            continue;
        }
        /// IMPORTANT NOTE: prevent contamination of previous running strategy
        Helper::waitEndOfActiveStreams();

        audio_port routedDevicePort;
        playbackFollowingProductStrategy(strategy.getId(), routedDevicePort);

        std::cerr << "AudioProductStrategy :"
                  <<  Helper::dumpProductStrategy(strategy.getId(), true)
                  << " was routed on " << Helper::dumpPort(routedDevicePort) << std::endl;
    }
}

TEST(AudioProductStrategiesTest, PlayByAttributes)
{
    status_t ret;
    AudioProductStrategyVector strategies;
    ret = AudioSystem::listAudioProductStrategies(strategies);
    ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::listAudioProductStrategies failed with error: "
                             << ret;

    for (const auto &strategy : strategies) {
        if (!Helper::isPublicStrategy(strategy)) {
            continue;
        }
        /// IMPORTANT NOTE: prevent contamination of previous running strategy
        Helper::waitEndOfActiveStreams();

        audio_port expectedRoutedPort;
        playbackFollowingProductStrategy(strategy.getId(), expectedRoutedPort);

        for (const auto &attribute : strategy.getAudioAttributes()) {
            audio_port routedDevicePortForAttr;

            playbackForAttributes(attribute.getAttributes(), routedDevicePortForAttr,
                                  expectedRoutedPort.id);

            EXPECT_EQ(routedDevicePortForAttr.id, expectedRoutedPort.id)
                << "AudioProductStrategy :"
                <<  Helper::dumpProductStrategy(strategy.getId(), true)
                 << " for attributes " << toString(attribute.getAttributes())
                << " was routed on " << Helper::dumpPort(routedDevicePortForAttr)
                << " expecting to be routed on" << Helper::dumpPort(expectedRoutedPort);
        }
    }
}

TEST(AudioProductStrategiesTest, PlayByLegacyStreamType)
{
    status_t ret;
    AudioProductStrategyVector strategies;
    ret = AudioSystem::listAudioProductStrategies(strategies);
    ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::listAudioProductStrategies failed with error: "
                             << ret;

    for (const auto &strategy : strategies) {
        if (!Helper::isPublicStrategy(strategy)) {
            continue;
        }
        /// IMPORTANT NOTE: prevent contamination of previous running strategy
        Helper::waitEndOfActiveStreams();

        audio_port expectedRoutedPort;
        playbackFollowingProductStrategy(strategy.getId(), expectedRoutedPort);

        for (const auto &attribute : strategy.getAudioAttributes()) {
            auto stream = attribute.getStreamType();
            audio_port routedDevicePortForAttr;

            if (stream == AUDIO_STREAM_DEFAULT) {
                // No specific stream type defined for strategy, playback by legacy stream type
                // does not make sense
                continue;
            }
            playbackForStream(stream, routedDevicePortForAttr, expectedRoutedPort.id);

            EXPECT_EQ(routedDevicePortForAttr.id, expectedRoutedPort.id)
                << "AudioProductStrategy : "
                <<  Helper::dumpProductStrategy(strategy.getId(), true)
                 << " for stream " << toString(stream)
                << " was routed on " << Helper::dumpPort(routedDevicePortForAttr)
                << " expecting to be routed on" << Helper::dumpPort(expectedRoutedPort);
        }
    }
}

class AudioProductStrategyTest : public ::testing::TestWithParam<AudioProductStrategyTestParams>
{
public:
    void SetUp() override
    {
        status_t ret;
        ret = AudioSystem::listAudioProductStrategies(mStrategies);
        ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::listAudioProductStrategies failed with error: "
                                 << ret;
        // The highest impacting delay if the SONIFICATION_RESPECTFUL_AFTER_MUSIC_DELAY (5s!!!)
        int activeCount = 0;
        for (audio_stream_type_t stream = AUDIO_STREAM_DEFAULT; stream < AUDIO_STREAM_PUBLIC_CNT;
             stream = (audio_stream_type_t) (stream + 1)) {
            bool isActive = false;
            ret = AudioSystem::isStreamActive(stream, &isActive, 0);
            if (isActive) {
                activeCount += 1;
            }
        }
        if (activeCount != 0) {
            usleep((SONIFICATION_RESPECTFUL_AFTER_MUSIC_DELAY + 500) * 1000);
        }
    }

    AudioProductStrategyVector mStrategies;
};

TEST_P(AudioProductStrategyTest, DeviceSelection)
{
    status_t ret;
    std::string name = std::get<0>(GetParam());
    audio_devices_t type = std::get<1>(GetParam());
    std::string address = std::get<2>(GetParam());

    audio_port expectedPort {};
    expectedPort.role = audio_is_output_device(type) ? AUDIO_PORT_ROLE_SINK :
                                                       AUDIO_PORT_ROLE_SOURCE;
    expectedPort.type = AUDIO_PORT_TYPE_DEVICE;
    expectedPort.ext.device.type = type;
    strncpy(expectedPort.ext.device.address, address.c_str(), AUDIO_DEVICE_MAX_ADDRESS_LEN);

    audio_port expectedRoutedPort;
    ret = Helper::findPort(expectedPort.role, expectedPort.type, expectedPort.ext.device.type,
                           expectedPort.ext.device.address, expectedRoutedPort);

    ASSERT_EQ(ret, NO_ERROR) << "Could not find port for device type "
                                      << Helper::toString(type).c_str()
                                      << " and address:" << address;

    auto iter = std::find_if(begin(mStrategies), end(mStrategies), [&name](const auto &strategy) {
        return strategy.getName() == name; });
    ASSERT_NE(iter, end(mStrategies)) << "Invalid strategy " << name;

    auto strategy = *iter;
    audio_port routedDeviceAudioPort;
    playbackFollowingProductStrategy(strategy.getId(), routedDeviceAudioPort,
                                     expectedRoutedPort.id);

    EXPECT_EQ(routedDeviceAudioPort.id, expectedRoutedPort.id)
            << "strategy " << name << " was routed on " << Helper::dumpPort(routedDeviceAudioPort)
            << " expecting to be routed on" << Helper::dumpPort(expectedRoutedPort);

    audio_port_handle_t routedDevicePort = AUDIO_PORT_HANDLE_NONE;
    Helper::playbackOnExplicitDevice(expectedRoutedPort, routedDevicePort);
    EXPECT_EQ(expectedRoutedPort.id, routedDevicePort)
            << "Explicit Routing for strategy " << name << " failed\n"
            << "Routed on " << Helper::dumpPort(routedDevicePort) << "\n"
            << "Expecting " << Helper::dumpPort(expectedRoutedPort);
}

INSTANTIATE_TEST_CASE_P(
        AudioProductStrategyDeviceSelection,
        AudioProductStrategyTest,
        ::testing::ValuesIn(AudioTestParams::getAudioProductStrategyTestParams())
        );

class ConcurrencyTest : public ::testing::TestWithParam<ConcurrencyTestParams> {};

TEST_P(ConcurrencyTest, Concurrency)
{
    std::string name1 = std::get<0>(GetParam());
    audio_devices_t type1 = std::get<1>(GetParam());
    std::string address1 = std::get<2>(GetParam());
    product_strategy_t strategy1 = PRODUCT_STRATEGY_NONE;
    audio_port expectedRoutedPort1;

    std::string name2 = std::get<3>(GetParam());
    audio_devices_t type2 = std::get<4>(GetParam());
    std::string address2 = std::get<5>(GetParam());
    product_strategy_t strategy2 = PRODUCT_STRATEGY_NONE;
    audio_port expectedRoutedPort2;

    if (!name1.empty()) {
        strategy1 = Helper::getStrategyByName(name1);
        ASSERT_NE(PRODUCT_STRATEGY_NONE, strategy1) << "Invalid strategy " << name1;
    }
    Helper::getPort(type1, address1, expectedRoutedPort1);

    if (!name2.empty()) {
        strategy2 = Helper::getStrategyByName(name2);
        ASSERT_NE(PRODUCT_STRATEGY_NONE, strategy2) << "Invalid strategy " << name2;
    }
    Helper::getPort(type2, address2, expectedRoutedPort2);

    // Launch track1
    std::unique_ptr<AudioTrackTest> audioTrack1;
    Helper::launchPlayer(audioTrack1, strategy1, AUDIO_STREAM_MUSIC, expectedRoutedPort1.id,
                         expectedRoutedPort1.id);
    // Launch track2
    std::unique_ptr<AudioTrackTest> audioTrack2;
    Helper::launchPlayer(audioTrack2, strategy2, AUDIO_STREAM_MUSIC, expectedRoutedPort2.id,
                         expectedRoutedPort2.id);

    if (audioTrack1 != nullptr)
        audioTrack1->stop();
    if (audioTrack2 != nullptr)
        audioTrack2->stop();
}

INSTANTIATE_TEST_CASE_P(
        ConcurrencyTestCases,
        ConcurrencyTest,
        ::testing::ValuesIn(AudioTestParams::getConcurrencyTestParamsTestParams())
        );
