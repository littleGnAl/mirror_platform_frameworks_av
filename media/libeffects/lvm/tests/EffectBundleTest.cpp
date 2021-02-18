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
#include <audio_utils/channels.h>
#include <audio_utils/primitives.h>
#include <climits>
#include <cstdlib>
#include <gtest/gtest.h>
#include <hardware/audio_effect.h>
#include <log/log.h>
#include <random>
#include <system/audio.h>
#include <vector>

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;

// TODO increase to 90.308998 to be consistent with lvmtest
constexpr float kSNRThreshold = 64.0f;

// TODO check if this threshold can be reduced to 1
constexpr int16_t kMaxDiffThreshold = 12;

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

constexpr size_t kLoopCounts[] = {1, 4};

constexpr size_t kNumLoopCounts = std::size(kLoopCounts);

class EffectBundleHelper {
  public:
    EffectBundleHelper(const effect_uuid_t* uuid, size_t chMask, size_t sampleRate,
                       size_t frameCount, size_t loopCount)
        : mUuid(uuid),
          mChMask(chMask),
          mSampleRate(sampleRate),
          mFrameCount(frameCount),
          mLoopCount(loopCount) {
        mChannelCount = audio_channel_count_from_out_mask(mChMask);
    }
    void createEffect();
    void releaseEffect();
    void configEffect();
    void process(float* input, float* output);

  private:
    const effect_uuid_t* mUuid;
    size_t mChMask;
    size_t mChannelCount;
    size_t mSampleRate;
    size_t mFrameCount;
    size_t mLoopCount;
    effect_handle_t mEffectHandle;
};

void EffectBundleHelper::createEffect() {
    int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(mUuid, 1, 1, &mEffectHandle);
    ASSERT_EQ(status, 0) << "create_effect returned an error " << status << "\n";
}

void EffectBundleHelper::releaseEffect() {
    int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(mEffectHandle);
    ASSERT_EQ(status, 0) << "release_effect returned an error " << status << "\n";
}

void EffectBundleHelper::configEffect() {
    effect_config_t config{};
    config.inputCfg.samplingRate = config.outputCfg.samplingRate = mSampleRate;
    config.inputCfg.channels = config.outputCfg.channels = mChMask;
    config.inputCfg.format = config.outputCfg.format = AUDIO_FORMAT_PCM_FLOAT;

    int reply = 0;
    uint32_t replySize = sizeof(reply);
    int status = (*mEffectHandle)
                         ->command(mEffectHandle, EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t),
                                   &config, &replySize, &reply);
    ASSERT_EQ(status, 0) << "command returned an error " << status << "\n";
    ASSERT_EQ(reply, 0) << "command reply non zero " << reply << "\n";

    status = (*mEffectHandle)
                     ->command(mEffectHandle, EFFECT_CMD_ENABLE, 0, nullptr, &replySize, &reply);
    ASSERT_EQ(status, 0) << "command enable returned an error " << status << "\n";
    ASSERT_EQ(reply, 0) << "command reply non zero " << reply << "\n";
}

void EffectBundleHelper::process(float* input, float* output) {
    audio_buffer_t inBuffer = {.frameCount = mFrameCount, .f32 = input};
    audio_buffer_t outBuffer = {.frameCount = mFrameCount, .f32 = output};
    for (int i = 0; i < mLoopCount; i++) {
        inBuffer.f32 += i * mFrameCount;
        outBuffer.f32 += i * mFrameCount;
        int status = (*mEffectHandle)->process(mEffectHandle, &inBuffer, &outBuffer);
        ASSERT_EQ(status, 0) << "process returned an error " << status << "\n";
    }
}

typedef std::tuple<int, int, int, int, int> SingleEffectTestParam;
class SingleEffectTest : public ::testing::TestWithParam<SingleEffectTestParam> {
  public:
    void SetUp() override {
        mChMask = kChMasks[std::get<0>(GetParam())];
        mSampleRate = kSampleRates[std::get<1>(GetParam())];
        mFrameCount = kFrameCounts[std::get<2>(GetParam())];
        mLoopCount = kLoopCounts[std::get<3>(GetParam())];
        mUuid = &kEffectUuids[std::get<4>(GetParam())];

        mChannelCount = audio_channel_count_from_out_mask(mChMask);
    }

    void TearDown() override {}

    const effect_uuid_t* mUuid;
    size_t mChMask;
    size_t mChannelCount;
    size_t mSampleRate;
    size_t mFrameCount;
    size_t mLoopCount;
};

TEST_P(SingleEffectTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message()
                 << "chMask: " << mChMask << " sampleRate: " << mSampleRate
                 << " frameCount: " << mFrameCount << " loopCount: " << mLoopCount);

    EffectBundleHelper effect(mUuid, mChMask, mSampleRate, mFrameCount, mLoopCount);

    ASSERT_NO_FATAL_FAILURE(effect.createEffect());
    ASSERT_NO_FATAL_FAILURE(effect.configEffect());

    // Initialize input buffer with deterministic pseudo-random values
    std::vector<float> input(mFrameCount * mLoopCount * mChannelCount);
    std::vector<float> output(mFrameCount * mLoopCount * mChannelCount);
    std::minstd_rand gen(mChMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    for (auto& in : input) {
        in = dis(gen);
    }
    ASSERT_NO_FATAL_FAILURE(effect.process(input.data(), output.data()));
    ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());
}

// TODO(b/131240940) Test single channel once effects are updated to process mono data
INSTANTIATE_TEST_SUITE_P(EffectBundleTestAll, SingleEffectTest,
                         ::testing::Combine(::testing::Range(1, (int)kNumChMasks),
                                            ::testing::Range(0, (int)kNumSampleRates),
                                            ::testing::Range(0, (int)kNumFrameCounts),
                                            ::testing::Range(0, (int)kNumLoopCounts),
                                            ::testing::Range(0, (int)kNumEffectUuids)));

typedef std::tuple<int, int, int, int> SingleEffectComparisonTestParam;
class SingleEffectComparisonTest
    : public ::testing::TestWithParam<SingleEffectComparisonTestParam> {
  public:
    void SetUp() override {
        mSampleRate = kSampleRates[std::get<0>(GetParam())];
        mFrameCount = kFrameCounts[std::get<1>(GetParam())];
        mLoopCount = kLoopCounts[std::get<2>(GetParam())];
        mUuid = &kEffectUuids[std::get<3>(GetParam())];
    }

    void TearDown() override {}

    const effect_uuid_t* mUuid;
    size_t mSampleRate;
    size_t mFrameCount;
    size_t mLoopCount;
};

template <typename T>
T computeMaxDiff(T* ref, T* tst, size_t count) {
    T maxDiff{};

    for (size_t i = 0; i < count; ++i) {
        const T diff(std::abs(tst[i] - ref[i]));
        if (diff > maxDiff) maxDiff = diff;
    }
    return maxDiff;
}

template <typename T>
float computeSnr(T* ref, T* tst, size_t count) {
    float signal{};
    float noise{};

    for (size_t i = 0; i < count; ++i) {
        const float value(ref[i]);
        const float diff(tst[i] - value);
        signal += value * value;
        noise += diff * diff;
    }
    // Initialized to a value greater than kSNRThreshold to handle
    // cases where ref and tst match exactly
    float snr = kSNRThreshold + 1.0f;
    if (signal > 0.0f && noise > 0.0f) {
        snr = 10.f * log(signal / noise);
    }
    return snr;
}
TEST_P(SingleEffectComparisonTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message() << " sampleRate: " << mSampleRate << " frameCount: "
                                    << mFrameCount << " loopCount: " << mLoopCount);

    // Initialize input buffer with deterministic pseudo-random values
    std::vector<float> stereoInput(mFrameCount * mLoopCount * FCC_2);

    std::minstd_rand gen(mSampleRate);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    for (auto& in : stereoInput) {
        in = dis(gen);
    }

    // Apply effect on stereo channels
    EffectBundleHelper stereoEffect(mUuid, AUDIO_CHANNEL_OUT_STEREO, mSampleRate, mFrameCount,
                                    mLoopCount);

    ASSERT_NO_FATAL_FAILURE(stereoEffect.createEffect());
    ASSERT_NO_FATAL_FAILURE(stereoEffect.configEffect());

    std::vector<float> stereoOutput(mFrameCount * mLoopCount * FCC_2);
    ASSERT_NO_FATAL_FAILURE(stereoEffect.process(stereoInput.data(), stereoOutput.data()));
    ASSERT_NO_FATAL_FAILURE(stereoEffect.releaseEffect());

    // Convert stereo float data to stereo int16_t to be used as reference
    std::vector<int16_t> stereoRefI16(mFrameCount * mLoopCount * FCC_2);
    memcpy_to_i16_from_float(stereoRefI16.data(), stereoOutput.data(), mFrameCount * FCC_2);

    for (size_t chMask : kChMasks) {
        // TODO(b/131240940) Test single channel once effects are updated to process mono data
        if (chMask == AUDIO_CHANNEL_OUT_MONO) continue;
        size_t channelCount = audio_channel_count_from_out_mask(chMask);
        EffectBundleHelper testEffect(mUuid, chMask, mSampleRate, mFrameCount, mLoopCount);

        ASSERT_NO_FATAL_FAILURE(testEffect.createEffect());
        ASSERT_NO_FATAL_FAILURE(testEffect.configEffect());

        std::vector<float> testInput(mFrameCount * mLoopCount * channelCount);
        adjust_channels(stereoInput.data(), FCC_2, testInput.data(), channelCount, sizeof(float),
                        mFrameCount * sizeof(float) * FCC_2);

        std::vector<float> testOutput(mFrameCount * mLoopCount * channelCount);
        ASSERT_NO_FATAL_FAILURE(testEffect.process(testInput.data(), testOutput.data()));
        ASSERT_NO_FATAL_FAILURE(testEffect.releaseEffect());

        // Extract first two channels
        std::vector<float> stereoTestOutput(mFrameCount * mLoopCount * FCC_2);
        adjust_channels(testOutput.data(), channelCount, stereoTestOutput.data(), FCC_2,
                        sizeof(float), mFrameCount * sizeof(float) * channelCount);

        // Convert the test data to int16_t
        std::vector<int16_t> stereoTestI16(mFrameCount * mLoopCount * FCC_2);
        memcpy_to_i16_from_float(stereoTestI16.data(), stereoTestOutput.data(),
                                 mFrameCount * FCC_2);

        if (mUuid != &kEffectUuids[0]) {
            // Maximum difference must not be greater than the threshold
            // TODO check if this can be changed to a memcmp
            int16_t maxDiff = computeMaxDiff<int16_t>(stereoRefI16.data(), stereoTestI16.data(),
                                                      mFrameCount * FCC_2);
            ASSERT_LE(maxDiff, kMaxDiffThreshold)
                    << "Maximum differece " << maxDiff << " is greater than " << kMaxDiffThreshold
                    << "\n";

        } else {
            // SNR must be above the threshold
            float snr = computeSnr<int16_t>(stereoRefI16.data(), stereoTestI16.data(),
                                            mFrameCount * FCC_2);
            ASSERT_GT(snr, kSNRThreshold)
                    << "SNR " << snr << "is lower than " << kSNRThreshold << "\n";
        }
    }
}

INSTANTIATE_TEST_SUITE_P(EffectBundleTestAll, SingleEffectComparisonTest,
                         ::testing::Combine(::testing::Range(0, (int)kNumSampleRates),
                                            ::testing::Range(0, (int)kNumFrameCounts),
                                            ::testing::Range(0, (int)kNumLoopCounts),
                                            ::testing::Range(0, (int)kNumEffectUuids)));

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
