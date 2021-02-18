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
#include <audio_effects/effect_presetreverb.h>
#include <vector>
#include <VectorArithmetic.h>

extern audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM;

// Corresponds to SNR for 1 bit difference between two int16_t signals
constexpr float kSNRThreshold = 90.308998;

// TODO: Auxiliary effects to be enabled after true mono support is implemented.
constexpr effect_uuid_t kEffectUuids[] = {
        // NXP SW insert environmental reverb
        {0xc7a511a0, 0xa3bb, 0x11df, 0x860e, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW insert preset reverb
        {0x172cdf00, 0xa3bc, 0x11df, 0xa72f, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW auxiliary environmental reverb
        // {0x4a387fc0, 0x8ab3, 0x11df, 0x8bad, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
        // NXP SW auxiliary preset reverb
        // {0xf29a1400, 0xa3bb, 0x11df, 0x8ddc, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},
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

constexpr int kPresets[] = {
        REVERB_PRESET_NONE,      REVERB_PRESET_SMALLROOM,  REVERB_PRESET_MEDIUMROOM,
        REVERB_PRESET_LARGEROOM, REVERB_PRESET_MEDIUMHALL, REVERB_PRESET_LARGEHALL,
        REVERB_PRESET_PLATE,
};

constexpr size_t kNumPresets = std::size(kPresets);

constexpr size_t kSampleRates[] = {8000,  11025, 12000, 16000, 22050,  24000, 32000,
                                   44100, 48000, 88200, 96000, 176400, 192000};

constexpr size_t kNumSampleRates = std::size(kSampleRates);

constexpr size_t kFrameCounts[] = {4, 2048};

constexpr size_t kNumFrameCounts = std::size(kFrameCounts);

constexpr size_t kLoopCounts[] = {1, 4};

constexpr size_t kNumLoopCounts = std::size(kLoopCounts);

template <typename T>
float computeSnr(const T* ref, const T* tst, size_t count) {
    double signal{};
    double noise{};

    for (size_t i = 0; i < count; ++i) {
        const double value(ref[i]);
        const double diff(tst[i] - value);
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

class EffectReverbHelper {
  public:
    EffectReverbHelper(const effect_uuid_t* uuid, size_t chMask, size_t sampleRate,
                       size_t frameCount, size_t loopCount)
        : mUuid(uuid),
          mChMask(chMask),
          mChannelCount(audio_channel_count_from_out_mask(mChMask)),
          mSampleRate(sampleRate),
          mFrameCount(frameCount),
          mLoopCount(loopCount) {}

    void createEffect();
    void releaseEffect();
    void configEffect();
    void process(float* input, float* output);
    void reverbSetConfigParam(uint32_t paramType, uint32_t paramValue);

  private:
    const effect_uuid_t* mUuid;
    const size_t mChMask;
    const size_t mChannelCount;
    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    effect_handle_t mEffectHandle{};
};

void EffectReverbHelper::createEffect() {
    int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.create_effect(mUuid, 1, 1, &mEffectHandle);
    ASSERT_EQ(status, 0) << "create_effect returned an error " << status << "\n";
}

void EffectReverbHelper::releaseEffect() {
    int status = AUDIO_EFFECT_LIBRARY_INFO_SYM.release_effect(mEffectHandle);
    ASSERT_EQ(status, 0) << "release_effect returned an error " << status << "\n";
}

void EffectReverbHelper::configEffect() {
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

void EffectReverbHelper::reverbSetConfigParam(uint32_t paramType, uint32_t paramValue) {
    int reply = 0;
    uint32_t replySize = sizeof(reply);
    uint32_t paramData[2] = {paramType, paramValue};
    auto effectParam = new effect_param_t[sizeof(effect_param_t) + sizeof(paramData)];
    memcpy(&effectParam->data[0], &paramData[0], sizeof(paramData));
    effectParam->psize = sizeof(paramData[0]);
    effectParam->vsize = sizeof(paramData[1]);
    int status = (*mEffectHandle)
                         ->command(mEffectHandle, EFFECT_CMD_SET_PARAM,
                                   sizeof(effect_param_t) + sizeof(paramData), effectParam,
                                   &replySize, &reply);
    delete[] effectParam;
    ASSERT_EQ(status, 0) << "Reverb set config command returned an error " << status << "\n";
    ASSERT_EQ(reply, 0) << "Reverb set config command reply non zero " << reply << "\n";
}

void EffectReverbHelper::process(float* input, float* output) {
    audio_buffer_t inBuffer = {.frameCount = mFrameCount, .f32 = input};
    audio_buffer_t outBuffer = {.frameCount = mFrameCount, .f32 = output};
    for (size_t i = 0; i < mLoopCount; i++) {
        int status = (*mEffectHandle)->process(mEffectHandle, &inBuffer, &outBuffer);
        ASSERT_EQ(status, 0) << "process returned an error " << status << "\n";

        inBuffer.f32 += mFrameCount * mChannelCount;
        outBuffer.f32 += mFrameCount * mChannelCount;
    }
}

typedef std::tuple<int, int, int, int, int, int> SingleEffectTestParam;
class SingleEffectTest : public ::testing::TestWithParam<SingleEffectTestParam> {
  public:
    SingleEffectTest()
        : mChMask(kChMasks[std::get<0>(GetParam())]),
          mChannelCount(audio_channel_count_from_out_mask(mChMask)),
          mSampleRate(kSampleRates[std::get<1>(GetParam())]),
          mFrameCount(kFrameCounts[std::get<2>(GetParam())]),
          mLoopCount(kLoopCounts[std::get<3>(GetParam())]),
          mTotalFrameCount(mFrameCount * mLoopCount),
          mUuid(&kEffectUuids[std::get<4>(GetParam())]),
          mPreset(kPresets[std::get<5>(GetParam())]) {}

    const size_t mChMask;
    const size_t mChannelCount;
    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    const size_t mTotalFrameCount;
    const effect_uuid_t* mUuid;
    const size_t mPreset;
};

// Tests applying a single effect
TEST_P(SingleEffectTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message() << "chMask: " << mChMask << " sampleRate: " << mSampleRate
                                    << " frameCount: " << mFrameCount
                                    << " loopCount: " << mLoopCount << " preset: " << mPreset);

    EffectReverbHelper effect(mUuid, mChMask, mSampleRate, mFrameCount, mLoopCount);

    ASSERT_NO_FATAL_FAILURE(effect.createEffect());
    ASSERT_NO_FATAL_FAILURE(effect.configEffect());
    ASSERT_NO_FATAL_FAILURE(effect.reverbSetConfigParam(REVERB_PARAM_PRESET, mPreset));

    // Initialize input buffer with deterministic pseudo-random values
    std::vector<float> input(mTotalFrameCount * mChannelCount);
    std::vector<float> output(mTotalFrameCount * mChannelCount);
    std::minstd_rand gen(mChMask);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    for (auto& in : input) {
        in = dis(gen);
    }
    ASSERT_NO_FATAL_FAILURE(effect.process(input.data(), output.data()));
    ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());
}

INSTANTIATE_TEST_SUITE_P(EffectReverbTestAll, SingleEffectTest,
                         ::testing::Combine(::testing::Range(0, (int)kNumChMasks),
                                            ::testing::Range(0, (int)kNumSampleRates),
                                            ::testing::Range(0, (int)kNumFrameCounts),
                                            ::testing::Range(0, (int)kNumLoopCounts),
                                            ::testing::Range(0, (int)kNumEffectUuids),
                                            ::testing::Range(0, (int)kNumPresets)));

typedef std::tuple<int, int, int, int, int> SingleEffectComparisonTestParam;
class SingleEffectComparisonTest
    : public ::testing::TestWithParam<SingleEffectComparisonTestParam> {
  public:
    SingleEffectComparisonTest()
        : mSampleRate(kSampleRates[std::get<0>(GetParam())]),
          mFrameCount(kFrameCounts[std::get<1>(GetParam())]),
          mLoopCount(kLoopCounts[std::get<2>(GetParam())]),
          mTotalFrameCount(mFrameCount * mLoopCount),
          mUuid(&kEffectUuids[std::get<3>(GetParam())]),
          mPreset(kPresets[std::get<4>(GetParam())]) {}

    const size_t mSampleRate;
    const size_t mFrameCount;
    const size_t mLoopCount;
    const size_t mTotalFrameCount;
    const effect_uuid_t* mUuid;
    const size_t mPreset;
};

// Compares first two channels in mutli-channel output to stereo output when same effect is applied
TEST_P(SingleEffectComparisonTest, SimpleProcess) {
    SCOPED_TRACE(testing::Message()
                 << " sampleRate: " << mSampleRate << " frameCount: " << mFrameCount
                 << " loopCount: " << mLoopCount << " preset: " << mPreset);

    // Initialize mono input buffer with deterministic pseudo-random values
    std::vector<float> monoInput(mTotalFrameCount);

    std::minstd_rand gen(mSampleRate);
    std::uniform_real_distribution<> dis(-1.0f, 1.0f);
    for (auto& in : monoInput) {
        in = dis(gen);
    }

    // Generate stereo by repeating mono channel data
    std::vector<float> stereoInput(mTotalFrameCount * FCC_2);
    adjust_channels(monoInput.data(), FCC_1, stereoInput.data(), FCC_2, sizeof(float),
                    mTotalFrameCount * sizeof(float) * FCC_1);

    // Apply effect on stereo channels
    EffectReverbHelper stereoEffect(mUuid, AUDIO_CHANNEL_OUT_STEREO, mSampleRate, mFrameCount,
                                    mLoopCount);

    ASSERT_NO_FATAL_FAILURE(stereoEffect.createEffect());
    ASSERT_NO_FATAL_FAILURE(stereoEffect.configEffect());
    ASSERT_NO_FATAL_FAILURE(stereoEffect.reverbSetConfigParam(REVERB_PARAM_PRESET, mPreset));

    std::vector<float> stereoOutput(mTotalFrameCount * FCC_2);
    ASSERT_NO_FATAL_FAILURE(stereoEffect.process(stereoInput.data(), stereoOutput.data()));
    ASSERT_NO_FATAL_FAILURE(stereoEffect.releaseEffect());

    // Average of both channels data is stored for mono comparison
    std::vector<float> monoOutput(mTotalFrameCount);
    From2iToMono_Float((const float*)stereoOutput.data(), monoOutput.data(), mTotalFrameCount);

    // Convert stereo float data to stereo int16_t to be used as reference
    std::vector<int16_t> stereoRefI16(mTotalFrameCount * FCC_2);
    memcpy_to_i16_from_float(stereoRefI16.data(), stereoOutput.data(), mTotalFrameCount * FCC_2);

    // mono int16_t to be used as refernece for mono comparison
    std::vector<int16_t> monoRefI16(mTotalFrameCount);
    memcpy_to_i16_from_float(monoRefI16.data(), monoOutput.data(), mTotalFrameCount);

    for (size_t chMask : kChMasks) {
        size_t channelCount = audio_channel_count_from_out_mask(chMask);
        EffectReverbHelper testEffect(mUuid, chMask, mSampleRate, mFrameCount, mLoopCount);

        ASSERT_NO_FATAL_FAILURE(testEffect.createEffect());
        ASSERT_NO_FATAL_FAILURE(testEffect.configEffect());
        ASSERT_NO_FATAL_FAILURE(testEffect.reverbSetConfigParam(REVERB_PARAM_PRESET, mPreset));

        std::vector<float> testInput(mTotalFrameCount * channelCount);

        // Repeat mono channel data to all the channels
        // adjust_channels() zero fills channels > 2, hence can't be used here
        for (size_t i = 0; i < mTotalFrameCount; ++i) {
            auto* fp = &testInput[i * channelCount];
            std::fill(fp, fp + channelCount, monoInput[i]);
        }

        std::vector<float> testOutput(mTotalFrameCount * channelCount);
        ASSERT_NO_FATAL_FAILURE(testEffect.process(testInput.data(), testOutput.data()));
        ASSERT_NO_FATAL_FAILURE(testEffect.releaseEffect());

        if (channelCount == FCC_1) {
            // Convert the test data to int16_t
            std::vector<int16_t> monoTestI16(mTotalFrameCount);
            memcpy_to_i16_from_float(monoTestI16.data(), testOutput.data(), mTotalFrameCount);

            // SNR must be above the threshold
            float snr = computeSnr<int16_t>((const short*)monoRefI16.data(),
                                            (const short*)monoTestI16.data(), mTotalFrameCount);
            ASSERT_GT(snr, kSNRThreshold) << "SNR " << snr << "is lower than " << kSNRThreshold;
        } else {
            // Extract first two channels
            std::vector<float> stereoTestOutput(mTotalFrameCount * FCC_2);
            adjust_channels(testOutput.data(), channelCount, stereoTestOutput.data(), FCC_2,
                            sizeof(float), mTotalFrameCount * sizeof(float) * channelCount);

            // Convert the test data to int16_t
            std::vector<int16_t> stereoTestI16(mTotalFrameCount * FCC_2);
            memcpy_to_i16_from_float(stereoTestI16.data(), stereoTestOutput.data(),
                                     mTotalFrameCount * FCC_2);

            ASSERT_EQ(0,
                      memcmp(stereoRefI16.data(), stereoTestI16.data(), mTotalFrameCount * FCC_2))
                    << "First two channels do not match with stereo output \n";
        }
    }
}

INSTANTIATE_TEST_SUITE_P(EffectReverbTestAll, SingleEffectComparisonTest,
                         ::testing::Combine(::testing::Range(0, (int)kNumSampleRates),
                                            ::testing::Range(0, (int)kNumFrameCounts),
                                            ::testing::Range(0, (int)kNumLoopCounts),
                                            ::testing::Range(0, (int)kNumEffectUuids),
                                            ::testing::Range(0, (int)kNumPresets)));

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
