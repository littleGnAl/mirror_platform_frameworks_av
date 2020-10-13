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
#include "AudioVolumeTest.hpp"

#include "Helper.hpp"

using namespace android;

static int resetVolumeIndex(int indexMin, int indexMax)
{
    return (indexMax + indexMin) / 2;
}

static void incrementVolumeIndex(int &index, int indexMin, int indexMax)
{
    index = (index + 1 > indexMax) ? resetVolumeIndex(indexMin, indexMax) : ++index;
}

class AttributeVolumeTest : public ::testing::TestWithParam<AttributeVolumeTestParams>
{
public:
    void SetUp() override
    {
        status_t ret;
        ret = AudioSystem::listAudioProductStrategies(mStrategies);
        ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::listAudioProductStrategies failed with error: "
                                 << ret;

        ret = AudioSystem::listAudioVolumeGroups(mVolumeGroups);
        ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::listAudioProductStrategies failed with error: "
                                 << ret;

        for (const auto &group : mVolumeGroups) {
            std::cout <<  "Group Id=" << group.getId() << " Name=" << group.getName() << std::endl;

            for (const auto &attr : group.getAudioAttributes()) {
                int indexMin;
                int indexMax;
                int index;
                ret = AudioSystem::getMinVolumeIndexForAttributes(attr, indexMin);
                ASSERT_EQ(ret, NO_ERROR) << "getMinVolumeIndexForAttributes failed with error: "
                                         << ret;
                ret = AudioSystem::getMaxVolumeIndexForAttributes(attr, indexMax);
                ASSERT_EQ(ret, NO_ERROR) << "getMaxVolumeIndexForAttributes failed with error: "
                                         << ret;
                ret = AudioSystem::getVolumeIndexForAttributes(attr, index, mDevice);
                ASSERT_EQ(ret, NO_ERROR) << "getVolumeIndexForAttributes failed with error: "
                                         << ret;
                index = resetVolumeIndex(indexMin, indexMax);

                for (const auto &attributes : group.getAudioAttributes()) {
                    ret = AudioSystem::setVolumeIndexForAttributes(attributes, index, mDevice);
                    EXPECT_EQ(ret, NO_ERROR) << "setVolume failed with error: " << ret;
                }
            }
        }
    }

    AudioProductStrategyVector mStrategies;
    AudioVolumeGroupVector mVolumeGroups;
    audio_devices_t mDevice = AUDIO_DEVICE_OUT_SPEAKER;
};

TEST_P(AttributeVolumeTest, UnkownAudioAttributes)
{
    audio_attributes_t attributes = std::get<0>(GetParam());
    std::string expectedGroup = std::get<1>(GetParam());

    status_t ret;
    int indexMin;
    int indexMax;
    int indexForAttr;
    ret = AudioSystem::getMinVolumeIndexForAttributes(attributes, indexMin);
    EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexMinForAttributes failed for "
                             <<  toString(attributes);

    ret = AudioSystem::getMaxVolumeIndexForAttributes(attributes, indexMax);
    ASSERT_EQ(ret, NO_ERROR) << "getMaxVolumeIndexForAttributes failed with error: " << ret;

    ret = AudioSystem::getVolumeIndexForAttributes(attributes, indexForAttr, mDevice);
    ASSERT_EQ(ret, NO_ERROR) << "getVolumeIndexForAttributes failed with error: " << ret;

    incrementVolumeIndex(indexForAttr, indexMin, indexMax);

    ret = AudioSystem::setVolumeIndexForAttributes(attributes, indexForAttr, mDevice);

    for (const auto &group : mVolumeGroups) {
        std::cout <<  "Group Id=" << group.getId() << " Name=" << group.getName() << std::endl;

        for (const auto &attr : group.getAudioAttributes()) {
            if (attr == defaultAttr) {
                // Attributes are not valid, cannot use new API
                continue;
            }
            int index;
            ret = AudioSystem::getVolumeIndexForAttributes(attr, index, mDevice);
            ASSERT_EQ(ret, NO_ERROR) << "getVolumeIndexForAttributes failed with error: " << ret;

            if (group.getName() == expectedGroup) {
                EXPECT_EQ(indexForAttr, index) <<  "Excpected Group "
                                                << group.getName() << " has not same volume index.";
            } else {
                EXPECT_NE(indexForAttr, index) <<  "Group Id=" << group.getId() << " Name="
                                                << group.getName() << " has same volume index.";
            }
        }
//        for (const auto &stream : group.getStreamTypes()) {
//            ASSERT_NE(stream, AUDIO_STREAM_DEFAULT);
//            if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
//                std::cerr << "Group " << group.getName() << " has non-public stream, "
//                             "AudioSystem will prevent us to set the volume" << std::endl;
//                continue;
//            }
//            int index;
//            ret = AudioSystem::getStreamVolumeIndex(stream, &index, mDevice);
//            ASSERT_EQ(ret, NO_ERROR) << "getVolumeIndexForStream failed with error: " << ret;

//            if (group.getName() == expectedGroup) {
//                EXPECT_EQ(indexForAttr, index) <<  "Excpected Group "
//                                                << group.getName() << " has not same volume index.";
//            } else {
//                EXPECT_NE(indexForAttr, index) <<  "Group Id=" << group.getId() << " Name="
//                                                << group.getName() << " has same volume index.";
//            }
//        }
    }
}

/**
 * @brief INSTANTIATE_TEST_CASE_P
 * Unhandled attributes from product strategies shall follow the default strategy, which is media
 * in this test configuration and as a result media volume group.
 */
INSTANTIATE_TEST_CASE_P(
        AttributeVolume,
        AttributeVolumeTest,
        ::testing::ValuesIn(AudioTestParams::getUnknownAttributesVolumeTestParams())
        );

TEST(StreamTypeVolumeTest, VolumeSetByStreamTypeOrAttributes)
{
    status_t ret;
    for (audio_stream_type_t stream = AUDIO_STREAM_DEFAULT; stream < AUDIO_STREAM_PUBLIC_CNT;
         stream = (audio_stream_type_t) (stream + 1)) {

        int index = 5;
        audio_devices_t device = AUDIO_DEVICE_OUT_SPEAKER;

        audio_attributes_t attributes = AudioSystem::streamTypeToAttributes(stream);
        product_strategy_t strategyId;
        ret = AudioSystem::getProductStrategyFromAudioAttributes(attributes, strategyId);
        ASSERT_EQ(ret, NO_ERROR) << "Failed to retrieve strategies for stream";

        AudioProductStrategy *strategy = nullptr;
        AudioProductStrategyVector strategies;
        ret = AudioSystem::listAudioProductStrategies(strategies);
        ASSERT_EQ(ret, NO_ERROR) << "Failed to retrieve strategies";
        for (AudioProductStrategy &ps : strategies) {
            if (ps.getId() == strategyId) {
                strategy = &ps;
                break;
            }
        }
        ASSERT_NE(strategy, nullptr) << "Invalid strategy for id " << strategyId;
        auto attribute = strategy->getAudioAttributes().front().getAttributes();
        int indexMin = 0;
        ret = AudioSystem::getMinVolumeIndexForAttributes(attribute, indexMin);
        EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexMinForAttributes failed for "
                                 <<  Helper::dumpProductStrategy(strategyId, true);
        int indexMax = 0;
        ret = AudioSystem::getMaxVolumeIndexForAttributes(attribute, indexMax);
        EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexMaxForAttributes failed for "
                                 <<  Helper::dumpProductStrategy(strategyId, true);

        index = resetVolumeIndex(indexMin, indexMax);
        device = AUDIO_DEVICE_OUT_SPEAKER;
        ret = AudioSystem::setVolumeIndexForAttributes(attribute, index, device);
        EXPECT_EQ(ret, NO_ERROR) << "setVolumeIndexForAttributes failed for "
                                 <<  Helper::dumpProductStrategy(strategyId, true);

        int indexRead = 0;
        ret = AudioSystem::getVolumeIndexForAttributes(attribute, indexRead, device);
        EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexForAttributes failed for "
                                 <<  Helper::dumpProductStrategy(strategyId, true);

        EXPECT_EQ(index, indexRead) << "getVolumeIndexForAttributes wrong value for "
                                    <<  Helper::dumpProductStrategy(strategyId, true)
                                     << " expected " << index << ", got " << indexRead;

    }
}

using StrategyPlaybackVolumeTestParams =
    std::tuple<const std::string /*strategyName*/,
               const AudioProductStrategy /*strategy*/>;

class AudioProductStrategiesPlaybackVolumeTest :
        public ::testing::TestWithParam<StrategyPlaybackVolumeTestParams>
{
public:
    void SetUp() override
    {
        status_t ret;
        ret = AudioSystem::listAudioVolumeGroups(mVolumeGroups);
        ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::listAudioProductStrategies failed with error: "
                                 << ret;
        int index = 1;

        for (const auto &group : mVolumeGroups) {
            for (const auto &attributes : group.getAudioAttributes()) {
                ret = AudioSystem::setVolumeIndexForAttributes(attributes, index, mDevice);
                EXPECT_EQ(ret, NO_ERROR) << "setVolumeIndexForAttributes failed for "
                                         <<  toString(attributes);
                int indexRead = 0;
                ret = AudioSystem::getVolumeIndexForAttributes(attributes, indexRead, mDevice);
                EXPECT_EQ(ret, NO_ERROR) << "getStreamVolumeIndex failed for "
                                         <<  toString(attributes);

                EXPECT_EQ(index, indexRead) << "getVolumeIndexForAttributes wrong value for "
                                            <<  toString(attributes)
                                             << " expected " << index << ", got " << indexRead;
            }
        }
    }

    AudioProductStrategyVector mStrategies;
    AudioVolumeGroupVector mVolumeGroups;
    audio_devices_t mDevice = AUDIO_DEVICE_OUT_SPEAKER;
};

TEST_P(AudioProductStrategiesPlaybackVolumeTest, PlaybackVolumeSetByAttributes)
{
    status_t ret;

    std::string name = std::get<0>(GetParam());
    auto strategy = std::get<1>(GetParam());

    auto attribute = strategy.getAudioAttributes().front().getAttributes();
    ASSERT_TRUE(attribute != defaultAttr) << "Strategy " << name << " has no valid attributes";
    auto group = strategy.getAudioAttributes().front().getGroupId();

    audio_devices_t device = AUDIO_DEVICE_OUT_SPEAKER;
    int indexRead = 0;
    StreamTypeVector volumeStreams;
    std::vector<audio_attributes_t> volumeAttributes;

    if (group == VOLUME_GROUP_NONE) {
        EXPECT_EQ(AudioSystem::getVolumeGroupFromAudioAttributes(attribute, group), NO_ERROR);
    }
    volumeStreams = Helper::getVolumeGroupsStreams(group);
    volumeAttributes = Helper::getVolumeGroupsAttributes(group);

    bool shallVolumeIndexMatch[AUDIO_STREAM_PUBLIC_CNT];
    for (audio_stream_type_t stream = AUDIO_STREAM_DEFAULT; stream < AUDIO_STREAM_PUBLIC_CNT;
         stream = (audio_stream_type_t) (stream + 1)) {

        auto attributes = AudioSystem::streamTypeToAttributes(stream);
        volume_group_t groupId;
        EXPECT_EQ(AudioSystem::getVolumeGroupFromAudioAttributes(attributes, groupId), NO_ERROR);

        std::cout << "Stream " << toString(stream) << " attributes "
                  << toString(attributes) << " groupdId " << groupId << std::endl;
        shallVolumeIndexMatch[stream] = (group == groupId);
    }

    int indexMin = 0;
    ret = AudioSystem::getMinVolumeIndexForAttributes(attribute, indexMin);
    EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexMinForAttributes failed for "
                             <<  Helper::dumpProductStrategy(strategy.getId(), true);
    int indexMax = 0;
    ret = AudioSystem::getMaxVolumeIndexForAttributes(attribute, indexMax);
    EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexMaxForAttributes failed for "
                             <<  Helper::dumpProductStrategy(strategy.getId(), true);

    int index = resetVolumeIndex(indexMin, indexMax);

    // All attributes have their own volume curves, but if one of the attributes member of the
    // group is active, the curve followed will be the one of the highest priority active
    // member.
    // Without playback, all attributes are expected not to have the same volume index
    incrementVolumeIndex(index, indexMin, indexMax);
    ret = AudioSystem::setVolumeIndexForAttributes(attribute, index, device);
    EXPECT_EQ(ret, NO_ERROR) << "setVolumeIndexForAttributes failed for "
                             <<  Helper::dumpProductStrategy(strategy.getId(), true);

    indexRead = 0;
    ret = AudioSystem::getVolumeIndexForAttributes(attribute, indexRead, device);
    EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexForAttributes failed for "
                             <<  Helper::dumpProductStrategy(strategy.getId(), true);
    EXPECT_EQ(index, indexRead) << "getVolumeIndexForAttributes wrong value for "
                                <<  Helper::dumpProductStrategy(strategy.getId(), true)
                                 << " expected " << index << ", got " << indexRead;

    for (auto &volumeAttribute : volumeAttributes) {
        volume_group_t vg;
        EXPECT_EQ(AudioSystem::getVolumeGroupFromAudioAttributes(volumeAttribute, vg), NO_ERROR);
        EXPECT_EQ(vg, group)
                << " attributes " << toString(volumeAttribute)
                << " shall belongs to group " << group;

        ret = AudioSystem::getVolumeIndexForAttributes(volumeAttribute, indexRead, device);
        EXPECT_EQ(ret, NO_ERROR)
                << "GroupDefinedByAttributes: getVolumeIndexForAttributes failed for "
                <<  Helper::dumpProductStrategy(strategy.getId(), true);

        EXPECT_EQ(index, indexRead)
                << "GroupDefinedByAttributes: getVolumeIndexForAttributes wrong value for "
                <<  Helper::dumpProductStrategy(strategy.getId(), true)
                << " and attributes " << toString(volumeAttribute)
                << " Gains shall match (same volume group) expected "
                << index << ", got " << indexRead;
    }
//    // Now get volume by stream type
//    for (audio_stream_type_t stream = AUDIO_STREAM_DEFAULT; stream < AUDIO_STREAM_PUBLIC_CNT;
//         stream = (audio_stream_type_t) (stream + 1)) {

//        indexRead = 0;
//        ret = AudioSystem::getStreamVolumeIndex(stream, &indexRead, device);
//        EXPECT_EQ(ret, NO_ERROR) << "getStreamVolumeIndex failed for "
//                                 <<  toString(stream);

//        if (shallVolumeIndexMatch[stream]) {
//            EXPECT_EQ(index, indexRead)
//                    << "GroupDefinedByAttributes: getStreamVolumeIndex shall work for "
//                    <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                     << " and stream " <<  toString(stream)
//                     << ", expected " << index << ", got " << indexRead;
//        } else {
//            EXPECT_NE(index, indexRead)
//                    << "GroupDefinedByAttributes: getStreamVolumeIndex shall not work for "
//                    <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                     << " and stream " <<  toString(stream)
//                     << ", expected " << index << ", got " << indexRead;
//        }
//    }
    // No playback running, set volume by attributes
    for (const auto &volumeAttribute : volumeAttributes) {
        incrementVolumeIndex(index, indexMin, indexMax);
        ret = AudioSystem::setVolumeIndexForAttributes(volumeAttribute, index, device);
        EXPECT_EQ(ret, NO_ERROR) << "setVolumeIndexForAttributes failed for "
                                 <<  Helper::dumpProductStrategy(strategy.getId(), true);

        indexRead = 0;
        ret = AudioSystem::getVolumeIndexForAttributes(volumeAttribute, indexRead, device);
        EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexForAttributes failed for "
                                 <<  Helper::dumpProductStrategy(strategy.getId(), true);
        EXPECT_EQ(index, indexRead) << "getVolumeIndexForAttributes wrong value for "
                                    <<  Helper::dumpProductStrategy(strategy.getId(), true)
                                     << " expected " << index << ", got " << indexRead;

//        // Now get volume by stream type
//        for (audio_stream_type_t stream = AUDIO_STREAM_DEFAULT; stream < AUDIO_STREAM_PUBLIC_CNT;
//             stream = (audio_stream_type_t) (stream + 1)) {

//            indexRead = 0;
//            ret = AudioSystem::getStreamVolumeIndex(stream, &indexRead, device);
//            EXPECT_EQ(ret, NO_ERROR) << "getStreamVolumeIndex failed for "
//                                     <<  toString(stream);

//            if (shallVolumeIndexMatch[stream]) {
//                EXPECT_EQ(index, indexRead) << "getStreamVolumeIndex shall work for "
//                                            <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                                            << " and stream " <<  toString(stream)
//                                            << ", expected " << index << ", got " << indexRead;
//            } else {
//                EXPECT_NE(index, indexRead) << "getStreamVolumeIndex shall not work for "
//                                            <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                                            << " and stream " <<  toString(stream)
//                                            << ", expected " << index << ", got " << indexRead;
//            }
//        }
    }

    /// IMPORTANT NOTE:
    // Before launching a playback, check TTS stream belongs to the tested strategy,
    // wait no other stream active before launching it otherwise apm::startSource may fail since
    // prohibited on platform without dedicated output and if any stream is active
    if (std::find(begin(volumeStreams), end(volumeStreams),
                  AUDIO_STREAM_TTS) != end(volumeStreams)) {
        Helper::waitEndOfActiveStreams();
    }
    // Launch Playback
    std::unique_ptr<AudioTrackTest> audioTrack;
    Helper::launchPlayer(audioTrack, strategy.getId(), AUDIO_STREAM_MUSIC, AUDIO_PORT_HANDLE_NONE,
                         AUDIO_PORT_HANDLE_NONE);

    indexRead = 0;
    ret = AudioSystem::getVolumeIndexForAttributes(attribute, indexRead, device);
    EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexForAttributes failed for "
                             <<  Helper::dumpProductStrategy(strategy.getId(), true);
    EXPECT_EQ(index, indexRead) << "getVolumeIndexForAttributes wrong value for "
                                <<  Helper::dumpProductStrategy(strategy.getId(), true)
                                << " expected " << index << ", got " << indexRead;

    incrementVolumeIndex(index, indexMin, indexMax);
    ret = AudioSystem::setVolumeIndexForAttributes(attribute, index, device);
    EXPECT_EQ(ret, NO_ERROR) << "setVolumeIndexForAttributes failed for "
                             <<  Helper::dumpProductStrategy(strategy.getId(), true);

    indexRead = 0;
    ret = AudioSystem::getVolumeIndexForAttributes(attribute, indexRead, device);
    EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexForAttributes failed for "
                             <<  Helper::dumpProductStrategy(strategy.getId(), true);
    EXPECT_EQ(index, indexRead) << "getVolumeIndexForAttributes wrong value for "
                                <<  Helper::dumpProductStrategy(strategy.getId(), true)
                                << " expected " << index << ", got " << indexRead;

    // Depending of Volume Group, legacy API shall work or not
    // Case 1: strategy belongs to group: shall not work on any stream that belongs to other
    // strategy outside this group
    // Case 2: legacy API shall not work for any stream except the one associated to this
    // strategy

//    for (audio_stream_type_t stream = AUDIO_STREAM_DEFAULT; stream < AUDIO_STREAM_PUBLIC_CNT;
//         stream = (audio_stream_type_t) (stream + 1)) {

//        indexRead = 0;
//        ret = AudioSystem::getStreamVolumeIndex(stream, &indexRead, device);
//        EXPECT_EQ(ret, NO_ERROR) << "getStreamVolumeIndex failed for "
//                                 <<  toString(stream);

//        if (shallVolumeIndexMatch[stream]) {
//            EXPECT_EQ(index, indexRead) << "getStreamVolumeIndex shall work for "
//                                        <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                                        << " and stream" <<  toString(stream)
//                                        << ", expected " << index << ", got " << indexRead;
//        } else {
//            EXPECT_NE(index, indexRead) << "getStreamVolumeIndex shall not work for "
//                                        <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                                        << " and stream" <<  toString(stream)
//                                        << ", expected " << index << ", got " << indexRead;
//        }
//    }

//    // Set volume by stream type loop
//    for (const auto &stream : volumeStreams) {
//        // Set by stream type
//        incrementVolumeIndex(index, indexMin, indexMax);
//        ret = AudioSystem::setStreamVolumeIndex(stream, index, device);
//        EXPECT_EQ(ret, NO_ERROR) << "setStreamVolumeIndex failed for "
//                                 <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                                 << " with stream " << toString(stream);

//        // As the product strategy belongs to a group, all the streams following this product
//        // strategy will follow the same volume curves
//        // Read by stream type
//        for (const auto &groupStream : volumeStreams) {
//            indexRead = 0;
//            ret = AudioSystem::getStreamVolumeIndex(groupStream, &indexRead, device);
//            EXPECT_EQ(ret, NO_ERROR) << "getStreamVolumeIndex failed for "
//                                     <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                                     << " with stream " << toString(groupStream);
//            EXPECT_EQ(index, indexRead) << "getStreamVolumeIndex wrong value for "
//                                        <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                                        << " and stream " << toString(groupStream)
//                                        << " expected " << index << ", got " << indexRead;
//        }

//        // get volume by attribute
//        for (const auto &volumeAttribute : volumeAttributes) {
//            indexRead = 0;
//            ret = AudioSystem::getVolumeIndexForAttributes(volumeAttribute, indexRead, device);
//            EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexForAttributes failed for "
//                                     <<  Helper::dumpProductStrategy(strategy.getId(), true);

//            EXPECT_EQ(index, indexRead)
//                    << "getVolumeIndexForAttributes wrong value for "
//                    <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                    << " while setting by stream " << toString(stream)
//                    << " expected " << index << ", got " << indexRead;
//        }
//    }

    // Set volume by attribute loop
    for (const auto &volumeAttribute : volumeAttributes) {

        incrementVolumeIndex(index, indexMin, indexMax);
        audio_devices_t device = AUDIO_DEVICE_OUT_SPEAKER;
        ret = AudioSystem::setVolumeIndexForAttributes(volumeAttribute, index, device);
        EXPECT_EQ(ret, NO_ERROR) << "setVolumeIndexForAttributes failed for "
                                 <<  Helper::dumpProductStrategy(strategy.getId(), true);

        int indexRead = 0;
        ret = AudioSystem::getVolumeIndexForAttributes(volumeAttribute, indexRead, device);
        EXPECT_EQ(ret, NO_ERROR) << "getVolumeIndexForAttributes failed for "
                                 <<  Helper::dumpProductStrategy(strategy.getId(), true);
        EXPECT_EQ(index, indexRead) << "getVolumeIndexForAttributes wrong value for "
                                    <<  Helper::dumpProductStrategy(strategy.getId(), true)
                                    << " expected " << index << ", got " << indexRead;

//        // Now get volume by stream type
//        for (audio_stream_type_t stream = AUDIO_STREAM_DEFAULT; stream < AUDIO_STREAM_PUBLIC_CNT;
//             stream = (audio_stream_type_t) (stream + 1)) {

//            indexRead = 0;
//            ret = AudioSystem::getStreamVolumeIndex(stream, &indexRead, device);
//            EXPECT_EQ(ret, NO_ERROR) << "getStreamVolumeIndex failed for "
//                                     <<  toString(stream);

//            if (shallVolumeIndexMatch[stream]) {
//                EXPECT_EQ(index, indexRead)
//                        << "getStreamVolumeIndex shall work for "
//                        <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                        << " and stream " <<  toString(stream)
//                        << ", expected " << index << ", got " << indexRead;
//            } else {
//                EXPECT_NE(index, indexRead)
//                        << "getStreamVolumeIndex shall not work for "
//                        <<  Helper::dumpProductStrategy(strategy.getId(), true)
//                        << " and stream " <<  toString(stream)
//                        << ", expected " << index << ", got " << indexRead;
//            }
//        }
    }
    audioTrack->stop();
}

static
const std::vector<StrategyPlaybackVolumeTestParams> getStrategyPlaybackVolumeTestParams()
{
    std::vector<StrategyPlaybackVolumeTestParams> testParams;
    AudioProductStrategyVector strategies;
    AudioSystem::listAudioProductStrategies(strategies);
    for (const auto &strategy : strategies) {
        if (Helper::isPublicStrategy(strategy)) {
            testParams.push_back({strategy.getName(), strategy});
        }
    }
    return testParams;
}

/**
 * @brief INSTANTIATE_TEST_CASE_P
 * Important Note: behavior of setStreamVolumeIndex will be different if the stream belongs to
 * a product strategy which is attached to a group.
 * A group inform of a common volume behavior, so changing on one stream will affect all the other
 * stream type following the product strategy member of the volume group
 */
INSTANTIATE_TEST_CASE_P(
        AudioProductStrategiesPlaybackVolume,
        AudioProductStrategiesPlaybackVolumeTest,
        ::testing::ValuesIn(getStrategyPlaybackVolumeTestParams())
        );

TEST(AudioVolumeGroupCbTest, SetVolumePerAttributesAndStream)
{
    audio_devices_t device = AUDIO_DEVICE_OUT_SPEAKER;

    AudioVolumeGroupVector groups;
    status_t ret = AudioSystem::listAudioVolumeGroups(groups);
    ASSERT_EQ(ret, NO_ERROR) << "AudioSystem::listAudioVolumeGroups failed with error: "
                             << ret;

    AudioVolumeTest volumeTest = {};
    ASSERT_EQ(volumeTest.registerAudioSystemCb(), NO_ERROR)
            << "Failed to register Volume Cb to AudioSystem with error:  " << ret;

    for (const auto &group : groups) {
        std::cout <<  "Group Id=" << group.getId() << " Name=" << group.getName() << std::endl;

        for (const auto &attr : group.getAudioAttributes()) {

            // Empty attributes prevents from using new volumes APIs.
            if (attr == defaultAttr) {
                std::cerr << "Cannot run test on group=" << group.getName()
                          << " without valid attributes" << std::endl;
                continue;
            }
            int indexMin;
            int indexMax;
            int index;
            ret = AudioSystem::getMinVolumeIndexForAttributes(attr, indexMin);
            ASSERT_EQ(ret, NO_ERROR) << "getMinVolumeIndexForAttributes failed with error: " << ret;

            ret = AudioSystem::getMaxVolumeIndexForAttributes(attr, indexMax);
            ASSERT_EQ(ret, NO_ERROR) << "getMaxVolumeIndexForAttributes failed with error: " << ret;

            ret = AudioSystem::getVolumeIndexForAttributes(attr, index, device);
            ASSERT_EQ(ret, NO_ERROR) << "getVolumeIndexForAttributes failed with error: " << ret;

            int volumeIndex = resetVolumeIndex(indexMin, indexMax);

            for (const auto &attributes : group.getAudioAttributes()) {

                ret = volumeTest.setVolumeForAttributes(volumeIndex, attributes, group.getId());
                EXPECT_EQ(ret, NO_ERROR) << "setVolume failed with error: " << ret;
                incrementVolumeIndex(volumeIndex, indexMin, indexMax);
            }
//            for (const auto &stream : group.getStreamTypes()) {
//                ASSERT_NE(stream, AUDIO_STREAM_DEFAULT)
//                        << "AUDIO_STREAM_DEFAULT does not make sense for using legacy volume API";
//                incrementVolumeIndex(volumeIndex, indexMin, indexMax);
//                ret = volumeTest.setStreamVolume(volumeIndex, stream, group.getId());
//                EXPECT_EQ(ret, NO_ERROR) << "setStreamVolumeIndex failed for group "
//                                         << group.getName()
//                                         << " and stream " << toString(stream)
//                                         << " with error: " << ret;
//            }
        }
    }
    ASSERT_EQ(volumeTest.unregisterAudioSystemCb(), NO_ERROR)
            << "Failed to unregister Volume Cb to AudioSystem with error:  " << ret;
}
