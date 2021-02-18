/*
 * Copyright 2021 The Android Open Source Project
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

#include <array>
#include <climits>
#include <cstdlib>
#include <gtest/gtest.h>
#include <log/log.h>
#include <hardware/audio_effect.h>
#include <random>
#include <system/audio.h>
#include <vector>

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;
constexpr effect_uuid_t kEffectUuids[] = {
        // NXP SW BassBoost
        {0x8631f300, 0x72e2, 0x11df, 0xb57e, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Virtualizer
        {0x1d4033c0, 0x8557, 0x11df, 0x9f2d, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Equalizer
        {0xce772f20, 0x847d, 0x11df, 0xbb17, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW Volume
        {0x119341a0, 0x8469, 0x11df, 0x81f9, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
};

constexpr size_t kNumEffectUuids = std::size(kEffectUuids);

constexpr audio_channel_mask_t kChMasks[] = {
        AUDIO_CHANNEL_OUT_MONO,          AUDIO_CHANNEL_OUT_STEREO,
        AUDIO_CHANNEL_OUT_2POINT1,       AUDIO_CHANNEL_OUT_2POINT0POINT2,
        AUDIO_CHANNEL_OUT_QUAD,          AUDIO_CHANNEL_OUT_QUAD_BACK,
        AUDIO_CHANNEL_OUT_QUAD_SIDE,     AUDIO_CHANNEL_OUT_SURROUND,
        AUDIO_CHANNEL_INDEX_MASK_4,      AUDIO_CHANNEL_OUT_2POINT1POINT2,
        AUDIO_CHANNEL_OUT_3POINT0POINT2, AUDIO_CHANNEL_OUT_PENTA,
        AUDIO_CHANNEL_INDEX_MASK_5,      AUDIO_CHANNEL_OUT_3POINT1POINT2,
        AUDIO_CHANNEL_OUT_5POINT1,       AUDIO_CHANNEL_OUT_5POINT1_BACK,
        AUDIO_CHANNEL_OUT_5POINT1_SIDE,  AUDIO_CHANNEL_INDEX_MASK_6,
        AUDIO_CHANNEL_OUT_6POINT1,       AUDIO_CHANNEL_INDEX_MASK_7,
        AUDIO_CHANNEL_OUT_5POINT1POINT2, AUDIO_CHANNEL_OUT_7POINT1,
        AUDIO_CHANNEL_INDEX_MASK_8,      AUDIO_CHANNEL_INDEX_MASK_9,
        AUDIO_CHANNEL_INDEX_MASK_10,     AUDIO_CHANNEL_INDEX_MASK_11,
        AUDIO_CHANNEL_INDEX_MASK_12,     AUDIO_CHANNEL_INDEX_MASK_13,
        AUDIO_CHANNEL_INDEX_MASK_14,     AUDIO_CHANNEL_INDEX_MASK_15,
        AUDIO_CHANNEL_INDEX_MASK_16,     AUDIO_CHANNEL_INDEX_MASK_17,
        AUDIO_CHANNEL_INDEX_MASK_18,     AUDIO_CHANNEL_INDEX_MASK_19,
        AUDIO_CHANNEL_INDEX_MASK_20,     AUDIO_CHANNEL_INDEX_MASK_21,
        AUDIO_CHANNEL_INDEX_MASK_22,     AUDIO_CHANNEL_INDEX_MASK_23,
        AUDIO_CHANNEL_INDEX_MASK_24,
};

constexpr size_t kNumChMasks = std::size(kChMasks);

constexpr size_t kSampleRates[] = {8000,  11025, 12000, 16000, 22050,  24000, 32000,
                                   44100, 48000, 88200, 96000, 176400, 192000};

constexpr size_t kNumSampleRates = std::size(kSampleRates);

constexpr size_t kFrameCounts[] = {4, 2048};

constexpr size_t kNumFrameCounts = std::size(kFrameCounts);

typedef std::tuple<int, int, int, int> testParam;

class EffectBundleTest : public ::testing::TestWithParam<testParam> {
  public:
    void SetUp() override {
        mChMask = kChMasks[std::get<0>(GetParam())];
        mSampleRate = kSampleRates[std::get<1>(GetParam())];
        mFrameCount = kFrameCounts[std::get<2>(GetParam())];
        const effect_uuid_t uuid = kEffectUuids[std::get<3>(GetParam())];
        // std::cout << "chMask: " << mChMask << " sampleRate: " << mSampleRate
        //          << "frameCount : " << mFrameCount << "\n ";

        ASSERT_NO_FATAL_FAILURE(createEffect(&uuid, mChMask, mSampleRate));
    }

    void TearDown() override { ASSERT_NO_FATAL_FAILURE(releaseEffect()); }

    effect_handle_t mEffectHandle = nullptr;
    void createEffect(const effect_uuid_t* uuid, size_t chMask, size_t sampleRate);
    void releaseEffect();
    void process(size_t chMask);
    size_t mChMask = AUDIO_CHANNEL_INDEX_MASK_1;
    size_t mSampleRate = 8000;
    size_t mFrameCount = 1024;
};

void EffectBundleTest::createEffect(const effect_uuid_t* uuid, size_t chMask, size_t sampleRate) {
    int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(uuid, 1, 1, &mEffectHandle);
    ASSERT_EQ(status, 0) << "create_effect returned an error " << status << "\n";

    effect_config_t config{};
    config.inputCfg.samplingRate = config.outputCfg.samplingRate = sampleRate;
    config.inputCfg.channels = config.outputCfg.channels = chMask;
    config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_FLOAT;

    int reply = 0;
    uint32_t replySize = sizeof(reply);
    status = (*mEffectHandle)
                     ->command(mEffectHandle, EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t),
                               &config, &replySize, &reply);
    ASSERT_EQ(status, 0) << "command returned an error " << status << "\n";

    status = (*mEffectHandle)
                     ->command(mEffectHandle, EFFECT_CMD_ENABLE, 0, nullptr, &replySize, &reply);
    ASSERT_EQ(status, 0) << "command enable returned an error " << status << "\n";
}

void EffectBundleTest::releaseEffect() {
    int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(mEffectHandle);
    ASSERT_EQ(status, 0) << "release_effect returned an error " << status << "\n";
}

void EffectBundleTest::process(size_t chMask) {
    const size_t channelCount = audio_channel_count_from_out_mask(chMask);
    // Initialize input buffer with deterministic pseudo-random values
    std::minstd_rand gen(chMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    std::vector<float> input(mFrameCount * channelCount);
    for (auto& in : input) {
        in = dis(gen);
    }

    std::vector<float> output(mFrameCount * channelCount);
    audio_buffer_t inBuffer = {.frameCount = mFrameCount, .f32 = input.data()};
    audio_buffer_t outBuffer = {.frameCount = mFrameCount, .f32 = output.data()};
    int status = (*mEffectHandle)->process(mEffectHandle, &inBuffer, &outBuffer);
    ASSERT_EQ(status, 0) << "process returned an error " << status << "\n";
}

TEST_P(EffectBundleTest, SimpleProcessTest) {
    ASSERT_NO_FATAL_FAILURE(process(mChMask));
}

INSTANTIATE_TEST_SUITE_P(EffectBundleTestAll, EffectBundleTest,
                         ::testing::Combine(::testing::Range(1, (int)kNumChMasks),
                                            ::testing::Range(0, (int)kNumSampleRates),
                                            ::testing::Range(0, (int)kNumFrameCounts),
                                            ::testing::Range(0, (int)kNumEffectUuids)));
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
