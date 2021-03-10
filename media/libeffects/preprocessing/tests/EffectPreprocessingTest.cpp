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

#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <tuple>
#include <vector>

#include <audio_effects/effect_aec.h>
#include <audio_effects/effect_agc.h>
#include <audio_effects/effect_agc2.h>
#include <audio_effects/effect_ns.h>
#include <log/log.h>

#include "EffectTestHelper.h"
using namespace android;

constexpr effect_uuid_t kEffectUuids[] = {
        {0xaa8130e0, 0x66fc, 0x11e0, 0xbad0, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // agc uuid
        {0x89f38e65, 0xd4d2, 0x4d64, 0xad0e, {0x2b, 0x3e, 0x79, 0x9e, 0xa8, 0x86}},  // agc2 uuid
        {0xbb392ec0, 0x8d4d, 0x11e0, 0xa896, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // aec uuid
        {0xc06c8400, 0x8e06, 0x11e0, 0x9cb6, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // ns  uuid
};

constexpr size_t kNumEffectUuids = std::size(kEffectUuids);

static std::tuple<int, int, int> kEffectParams(0, 0, 0);

// TODO: Only 5 sample values are taken from the acceptable range
constexpr size_t kMaxNumValuesInParams = 5;

constexpr int kAGCTargetLevels[] = {0, -300, -500, -1000, -3100};

constexpr size_t kNumAGCTargetLevels = std::size(kAGCTargetLevels);

constexpr int kAGCCompLevels[] = {0, -300, -500, -1000, -9000};

constexpr size_t kNumAGCCompLevels = std::size(kAGCCompLevels);

constexpr size_t kAGC2Gains[] = {0, 3, 10, 20, 49};

constexpr size_t kNumAGC2Gains = std::size(kAGC2Gains);

constexpr size_t kAGC2Levels[] = {0, 1};

constexpr size_t kNumAGC2Levels = std::size(kAGC2Levels);

constexpr size_t kAGC2SaturationMargins[] = {0, 3, 10, 20, 100};

constexpr size_t kNumAGC2SaturationMargins = std::size(kAGC2SaturationMargins);

constexpr size_t kNSLevels[] = {0, 1, 2, 3};

constexpr size_t kNumNSLevels = std::size(kNSLevels);

// Update these, if the order of effects in kEffectUuids is updated
static bool isAGCEffect(const effect_uuid_t* uuid) {
    return uuid == &kEffectUuids[0];
}
static bool isAGC2Effect(const effect_uuid_t* uuid) {
    return uuid == &kEffectUuids[1];
}
bool isAECEffect(const effect_uuid_t* uuid) {
    return uuid == &kEffectUuids[2];
}
static bool isNSEffect(const effect_uuid_t* uuid) {
    return uuid == &kEffectUuids[3];
}

int16_t preProcGetShortVal(float paramValue) {
    return static_cast<int16_t>(paramValue * std::numeric_limits<int16_t>::max());
}

typedef std::tuple<int, int, int, int, int, int, int> SingleEffectTestParam;
class SingleEffectTest : public ::testing::TestWithParam<SingleEffectTestParam> {
  public:
    SingleEffectTest()
        : mSampleRate(EffectTestHelper::kSampleRates[std::get<1>(GetParam())]),
          mFrameCount(mSampleRate * EffectTestHelper::kTenMilliSecVal),
          mLoopCount(EffectTestHelper::kLoopCounts[std::get<2>(GetParam())]),
          mTotalFrameCount(mFrameCount * mLoopCount),
          mUuid(&kEffectUuids[std::get<3>(GetParam())]),
          mChMask(EffectTestHelper::kChMasks[std::get<0>(GetParam())]),
          mChannelCount(audio_channel_count_from_in_mask(mChMask)),
          mIdxValueOfParam1(std::get<4>(GetParam())),
          mIdxValueOfParam2(std::get<5>(GetParam())),
          mIdxValueOfParam3(std::get<6>(GetParam())) {}

    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    const size_t mTotalFrameCount;
    const effect_uuid_t* mUuid;
    const size_t mChMask;
    const size_t mChannelCount;
    const size_t mIdxValueOfParam1;
    const size_t mIdxValueOfParam2;
    const size_t mIdxValueOfParam3;
};

// Tests applying a single effect
TEST_P(SingleEffectTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message()
                 << " chMask: " << mChMask << " sampleRate: " << mSampleRate
                 << " loopCount: " << mLoopCount << " idxValue1 " << mIdxValueOfParam1
                 << " idxValue2 " << mIdxValueOfParam2 << " idxValue3 " << mIdxValueOfParam3);

    EffectTestHelper effect(mUuid, mChMask, mSampleRate, mLoopCount);

    ASSERT_NO_FATAL_FAILURE(effect.createEffect());
    ASSERT_NO_FATAL_FAILURE(effect.setConfig());
    if (isAGCEffect(mUuid)) {
        std::get<0>(kEffectParams) = kAGCTargetLevels[mIdxValueOfParam1 % kNumAGCTargetLevels];
        std::get<1>(kEffectParams) = kAGCCompLevels[mIdxValueOfParam2 % kNumAGCCompLevels];
        ASSERT_NO_FATAL_FAILURE(
                effect.setParam(AGC_PARAM_TARGET_LEVEL, std::get<0>(kEffectParams)));
        ASSERT_NO_FATAL_FAILURE(effect.setParam(AGC_PARAM_COMP_GAIN, std::get<1>(kEffectParams)));
    } else if (isAGC2Effect(mUuid)) {
        std::get<0>(kEffectParams) = kAGC2Gains[mIdxValueOfParam1 % kNumAGC2Gains];
        std::get<1>(kEffectParams) = kAGC2Levels[mIdxValueOfParam2 % kNumAGC2Levels];
        std::get<2>(kEffectParams) =
                kAGC2SaturationMargins[mIdxValueOfParam3 % kNumAGC2SaturationMargins];
        ASSERT_NO_FATAL_FAILURE(
                effect.setParam(AGC2_PARAM_FIXED_DIGITAL_GAIN, std::get<0>(kEffectParams)));
        ASSERT_NO_FATAL_FAILURE(
                effect.setParam(AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR, std::get<1>(kEffectParams)));
        ASSERT_NO_FATAL_FAILURE(effect.setParam(AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN,
                                                std::get<2>(kEffectParams)));
    } else if (isNSEffect(mUuid)) {
        std::get<0>(kEffectParams) = kNSLevels[mIdxValueOfParam1 % kNumNSLevels];
        ASSERT_NO_FATAL_FAILURE(effect.setParam(NS_PARAM_LEVEL, std::get<0>(kEffectParams)));
    }

    // Initialize input buffer with deterministic pseudo-random values
    std::vector<int16_t> input(mTotalFrameCount * mChannelCount);
    std::vector<int16_t> output(mTotalFrameCount * mChannelCount);
    std::vector<int16_t> farInput(mTotalFrameCount * mChannelCount);
    std::minstd_rand gen(mChMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    for (auto& in : input) {
        in = preProcGetShortVal(dis(gen));
    }
    if (isAECEffect(mUuid)) {
        for (auto& farIn : farInput) {
            farIn = preProcGetShortVal(dis(gen));
        }
    }
    ASSERT_NO_FATAL_FAILURE(effect.process(input.data(), output.data()));
    if (isAECEffect(mUuid))
        ASSERT_NO_FATAL_FAILURE(effect.process_reverse(farInput.data(), output.data()));
    ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());
}

INSTANTIATE_TEST_SUITE_P(
        PreProcTestAll, SingleEffectTest,
        ::testing::Combine(::testing::Range(0, (int)EffectTestHelper::kNumChMasks),
                           ::testing::Range(0, (int)EffectTestHelper::kNumSampleRates),
                           ::testing::Range(0, (int)EffectTestHelper::kNumLoopCounts),
                           ::testing::Range(0, (int)kNumEffectUuids),
                           ::testing::Range(0, (int)kMaxNumValuesInParams),
                           ::testing::Range(0, (int)kMaxNumValuesInParams),
                           ::testing::Range(0, (int)kMaxNumValuesInParams)));

typedef std::tuple<int, int, int, int, int, int> SingleEffectComparisonTestParam;
class SingleEffectComparisonTest
    : public ::testing::TestWithParam<SingleEffectComparisonTestParam> {
  public:
    SingleEffectComparisonTest()
        : mSampleRate(EffectTestHelper::kSampleRates[std::get<0>(GetParam())]),
          mFrameCount(mSampleRate * EffectTestHelper::kTenMilliSecVal),
          mLoopCount(EffectTestHelper::kLoopCounts[std::get<1>(GetParam())]),
          mTotalFrameCount(mFrameCount * mLoopCount),
          mUuid(&kEffectUuids[std::get<2>(GetParam())]),
          mIdxValueOfParam1(std::get<3>(GetParam())),
          mIdxValueOfParam2(std::get<4>(GetParam())),
          mIdxValueOfParam3(std::get<5>(GetParam())) {}

    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    const size_t mTotalFrameCount;
    const effect_uuid_t* mUuid;
    const size_t mIdxValueOfParam1;
    const size_t mIdxValueOfParam2;
    const size_t mIdxValueOfParam3;
};

// Compares first two channels in multi-channel output to stereo output when same effect is applied
TEST_P(SingleEffectComparisonTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message()
                 << " sampleRate: " << mSampleRate << " loopCount: " << mLoopCount << " idxValue1 "
                 << mIdxValueOfParam1 << " idxValue2 " << mIdxValueOfParam2 << " idxValue3 "
                 << mIdxValueOfParam3);

    // Initialize mono input buffer with deterministic pseudo-random values
    std::vector<int16_t> monoInput(mTotalFrameCount);
    std::vector<int16_t> monoFarInput(mTotalFrameCount);

    std::minstd_rand gen(mSampleRate);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    for (auto& in : monoInput) {
        in = preProcGetShortVal(dis(gen));
    }
    if (isAECEffect(mUuid)) {
        for (auto& farIn : monoFarInput) {
            farIn = preProcGetShortVal(dis(gen));
        }
    }

    // Apply effect on mono channel
    EffectTestHelper monoEffect(mUuid, AUDIO_CHANNEL_INDEX_MASK_1, mSampleRate, mLoopCount);

    ASSERT_NO_FATAL_FAILURE(monoEffect.createEffect());
    ASSERT_NO_FATAL_FAILURE(monoEffect.setConfig());
    if (isAGCEffect(mUuid)) {
        std::get<0>(kEffectParams) = kAGCTargetLevels[mIdxValueOfParam1 % kNumAGCTargetLevels];
        std::get<1>(kEffectParams) = kAGCCompLevels[mIdxValueOfParam2 % kNumAGCCompLevels];
        ASSERT_NO_FATAL_FAILURE(
                monoEffect.setParam(AGC_PARAM_TARGET_LEVEL, std::get<0>(kEffectParams)));
        ASSERT_NO_FATAL_FAILURE(
                monoEffect.setParam(AGC_PARAM_COMP_GAIN, std::get<1>(kEffectParams)));
    } else if (isAGC2Effect(mUuid)) {
        std::get<0>(kEffectParams) = kAGC2Gains[mIdxValueOfParam1 % kNumAGC2Gains];
        std::get<1>(kEffectParams) = kAGC2Levels[mIdxValueOfParam2 % kNumAGC2Levels];
        std::get<2>(kEffectParams) =
                kAGC2SaturationMargins[mIdxValueOfParam3 % kNumAGC2SaturationMargins];
        ASSERT_NO_FATAL_FAILURE(
                monoEffect.setParam(AGC2_PARAM_FIXED_DIGITAL_GAIN, std::get<0>(kEffectParams)));
        ASSERT_NO_FATAL_FAILURE(monoEffect.setParam(AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR,
                                                    std::get<1>(kEffectParams)));
        ASSERT_NO_FATAL_FAILURE(monoEffect.setParam(AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN,
                                                    std::get<2>(kEffectParams)));
    } else if (isNSEffect(mUuid)) {
        std::get<0>(kEffectParams) = kNSLevels[mIdxValueOfParam1 % kNumNSLevels];
        ASSERT_NO_FATAL_FAILURE(monoEffect.setParam(NS_PARAM_LEVEL, std::get<0>(kEffectParams)));
    }

    std::vector<int16_t> monoOutput(mTotalFrameCount);
    ASSERT_NO_FATAL_FAILURE(monoEffect.process(monoInput.data(), monoOutput.data()));
    if (isAECEffect(mUuid))
        ASSERT_NO_FATAL_FAILURE(monoEffect.process_reverse(monoFarInput.data(), monoOutput.data()));
    ASSERT_NO_FATAL_FAILURE(monoEffect.releaseEffect());

    for (size_t chMask : EffectTestHelper::kChMasks) {
        size_t channelCount = audio_channel_count_from_in_mask(chMask);

        EffectTestHelper testEffect(mUuid, chMask, mSampleRate, mLoopCount);

        ASSERT_NO_FATAL_FAILURE(testEffect.createEffect());
        ASSERT_NO_FATAL_FAILURE(testEffect.setConfig());
        if (isAGCEffect(mUuid)) {
            std::get<0>(kEffectParams) = kAGCTargetLevels[mIdxValueOfParam1 % kNumAGCTargetLevels];
            std::get<1>(kEffectParams) = kAGCCompLevels[mIdxValueOfParam2 % kNumAGCCompLevels];
            ASSERT_NO_FATAL_FAILURE(
                    testEffect.setParam(AGC_PARAM_TARGET_LEVEL, std::get<0>(kEffectParams)));
            ASSERT_NO_FATAL_FAILURE(
                    testEffect.setParam(AGC_PARAM_COMP_GAIN, std::get<1>(kEffectParams)));
        } else if (isAGC2Effect(mUuid)) {
            std::get<0>(kEffectParams) = kAGC2Gains[mIdxValueOfParam1 % kNumAGC2Gains];
            std::get<1>(kEffectParams) = kAGC2Levels[mIdxValueOfParam2 % kNumAGC2Levels];
            std::get<2>(kEffectParams) =
                    kAGC2SaturationMargins[mIdxValueOfParam3 % kNumAGC2SaturationMargins];
            ASSERT_NO_FATAL_FAILURE(
                    testEffect.setParam(AGC2_PARAM_FIXED_DIGITAL_GAIN, std::get<0>(kEffectParams)));
            ASSERT_NO_FATAL_FAILURE(testEffect.setParam(AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR,
                                                        std::get<1>(kEffectParams)));
            ASSERT_NO_FATAL_FAILURE(testEffect.setParam(
                    AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN, std::get<2>(kEffectParams)));
        } else if (isNSEffect(mUuid)) {
            std::get<0>(kEffectParams) = kNSLevels[mIdxValueOfParam1 % kNumNSLevels];
            ASSERT_NO_FATAL_FAILURE(
                    testEffect.setParam(NS_PARAM_LEVEL, std::get<0>(kEffectParams)));
        }

        std::vector<int16_t> testInput(mTotalFrameCount * channelCount);
        std::vector<int16_t> testFarInput(mTotalFrameCount * channelCount);

        // Repeat mono channel data to all the channels
        // adjust_channels() zero fills channels > 2, hence can't be used here
        for (size_t i = 0; i < mTotalFrameCount; ++i) {
            auto* fpInput = &testInput[i * channelCount];
            std::fill(fpInput, fpInput + channelCount, monoInput[i]);
        }
        if (isAECEffect(mUuid)) {
            for (size_t i = 0; i < mTotalFrameCount; ++i) {
                auto* fpFarInput = &testFarInput[i * channelCount];
                std::fill(fpFarInput, fpFarInput + channelCount, monoFarInput[i]);
            }
        }

        std::vector<int16_t> testOutput(mTotalFrameCount * channelCount);
        ASSERT_NO_FATAL_FAILURE(testEffect.process(testInput.data(), testOutput.data()));
        if (isAECEffect(mUuid))
            ASSERT_NO_FATAL_FAILURE(
                    testEffect.process_reverse(testFarInput.data(), testOutput.data()));
        ASSERT_NO_FATAL_FAILURE(testEffect.releaseEffect());

        // Adjust the test output to mono channel
        std::vector<int16_t> monoTestOutput(mTotalFrameCount);
        adjust_channels(testOutput.data(), channelCount, monoTestOutput.data(), FCC_1,
                        sizeof(int16_t), mTotalFrameCount * sizeof(int16_t) * channelCount);

        ASSERT_EQ(0, memcmp(monoOutput.data(), monoTestOutput.data(),
                            mTotalFrameCount * sizeof(int16_t)))
                << "Mono channel do not match with reference output \n";
    }
}

INSTANTIATE_TEST_SUITE_P(
        PreProcTestAll, SingleEffectComparisonTest,
        ::testing::Combine(::testing::Range(0, (int)EffectTestHelper::kNumSampleRates),
                           ::testing::Range(0, (int)EffectTestHelper::kNumLoopCounts),
                           ::testing::Range(0, (int)kNumEffectUuids),
                           ::testing::Range(0, (int)kMaxNumValuesInParams),
                           ::testing::Range(0, (int)kMaxNumValuesInParams),
                           ::testing::Range(0, (int)kMaxNumValuesInParams)));

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
