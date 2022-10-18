/*
 * Copyright 2022 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "EffectFreqResp"

#include <cmath>
#include <fstream>
#include <iostream>
#include <vector>
#include <system/audio_effects/effect_bassboost.h>
#include <system/audio_effects/effect_equalizer.h>

#include "EffectTestHelper.h"
#include "pffft.h"

using namespace android;

constexpr float kDefAmplitude = 0.25f;

constexpr float kSamplingFrequency = 48000;

constexpr float kAudioDuration = 1.5;  // in sec

constexpr float kAudioDurationPrimePad = 0.25;  // in sec

void generateMultiTone(std::vector<int> toneFrequencies, float samplingFrequency, float duration,
                       float amplitude, float* buffer, int numSamples) {
    int totalFrameCount = (samplingFrequency * duration);
    int limit = (totalFrameCount < numSamples) ? totalFrameCount : numSamples;

    for (auto i = 0; i < limit; i++) {
        buffer[i] = 0;
        for (auto j = 0; j < toneFrequencies.size(); j++) {
            buffer[i] += sin(2 * M_PI * toneFrequencies[j] * i / samplingFrequency);
        }
        buffer[i] *= (amplitude / toneFrequencies.size());
    }
}

// pick a suitable frameCount and loopCount for samplerate and duration
void factorPairs(int totalFrameCount, int& frameCount, int& loopCount) {
    std::vector<int> frameCounts;
    std::vector<int> loopCounts;

    for (auto i = 1; i < totalFrameCount; i++) {
        if (totalFrameCount % i == 0) {
            frameCounts.push_back(totalFrameCount / i);
            loopCounts.push_back(i);
        }
    }
    frameCount = frameCounts[frameCounts.size() / 2];
    loopCount = loopCounts[loopCounts.size() / 2];
}

TEST(TestEffect, AndroidEqualizerEffect) {
    // nxp sw bassboost
    effect_uuid_t uuid = {0xce772f20, 0x847d, 0x11df, 0xbb17, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};

    // total input frame count
    const int totalFrameCount = kSamplingFrequency * kAudioDuration;
    int frameCount, loopCount;
    factorPairs(totalFrameCount, frameCount, loopCount);

    // sample count to be ignored from output during analysis (filter transient response)
    const int frameCountPrimePad = kSamplingFrequency * kAudioDurationPrimePad;
    ASSERT_GE(kAudioDuration, 2 * kAudioDurationPrimePad + 1);

    const int n_point_fft = 16384;
    ASSERT_GE(totalFrameCount, 2 * frameCountPrimePad + n_point_fft);

    const float bin_width = (float)kSamplingFrequency / n_point_fft;

    // Get Equalizer Effect Attributes
    EffectTestHelper effect(&uuid, AUDIO_CHANNEL_OUT_MONO, AUDIO_CHANNEL_OUT_MONO,
                            kSamplingFrequency, frameCount, loopCount);
    ASSERT_NO_FATAL_FAILURE(effect.createEffect());
    ASSERT_NO_FATAL_FAILURE(effect.setConfig());
    std::vector<int16_t> paramVal;
    int status = effect.getParam<false>(EQ_PARAM_GET_NUM_OF_PRESETS, paramVal);
    EXPECT_EQ(0, status);
    int numPresets = paramVal[0];  // num of presets
    paramVal.clear();
    status = effect.getParam<false>(EQ_PARAM_NUM_BANDS, paramVal);
    EXPECT_EQ(0, status);
    int numBands = paramVal[0];  // num of bands
    paramVal.clear();
    std::vector<int> centerFrequencies;
    for (auto i = 0; i < numBands; i++) {
        std::vector<int32_t> cf;
        status = effect.getParam<false>(EQ_PARAM_CENTER_FREQ, i, cf);
        EXPECT_EQ(0, status);
        centerFrequencies.push_back(cf[0] / 1000);  // center freq of a band
    }
    ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());

    // input and output buffers for effect module
    std::vector<float> input(totalFrameCount);
    std::vector<float> output(totalFrameCount);

    std::vector<float> fftInput(n_point_fft);
    std::vector<float> fftOutput(n_point_fft);
    std::vector<float> fftInputMag(n_point_fft / 2);
    std::vector<float> fftOutputMag(n_point_fft / 2);

    generateMultiTone(centerFrequencies, kSamplingFrequency, kAudioDuration, kDefAmplitude,
                      input.data(), input.size());

    bool isPass = true;
    for (int preset = 0; preset < numPresets; preset++) {
        float expGaindB[numBands], actGaindB[numBands];

        EffectTestHelper effect(&uuid, AUDIO_CHANNEL_OUT_MONO, AUDIO_CHANNEL_OUT_MONO,
                                kSamplingFrequency, frameCount, loopCount);

        ASSERT_NO_FATAL_FAILURE(effect.createEffect());
        ASSERT_NO_FATAL_FAILURE(effect.setConfig());
        ASSERT_NO_FATAL_FAILURE(effect.setParam<int32_t>(EQ_PARAM_CUR_PRESET, preset));

        status = effect.getParam<true>(EQ_PARAM_PROPERTIES, -1, paramVal);
        EXPECT_EQ(0, status);
        ASSERT_EQ(preset, paramVal[0]);
        ASSERT_EQ(numBands, paramVal[1]);
        for (auto j = 0; j < numBands; j++) {
            expGaindB[j] = paramVal[2 + j] / 100.0f;  // gain in milli bels
            actGaindB[j] = -1.0f;
        }

        ASSERT_NO_FATAL_FAILURE(effect.process(input.data(), output.data()));
        ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());

        PFFFT_Setup* handle = pffft_new_setup(n_point_fft, PFFFT_REAL);
        pffft_transform_ordered(handle, input.data(), fftInput.data(), nullptr, PFFFT_FORWARD);
        pffft_destroy_setup(handle);

        handle = pffft_new_setup(n_point_fft, PFFFT_REAL);
        pffft_transform_ordered(handle, output.data() + frameCountPrimePad, fftOutput.data(),
                                nullptr, PFFFT_FORWARD);
        pffft_destroy_setup(handle);

        fftInputMag[0] = fabs(fftInput[0]);
        for (auto i = 2; i < fftInput.size(); i += 2) {
            fftInputMag[i >> 1] =
                    sqrt((fftInput[i] * fftInput[i]) + (fftInput[i + 1] * fftInput[i + 1]));
        }

        fftOutputMag[0] = fabs(fftOutput[0]);
        for (auto i = 2; i < fftOutput.size(); i += 2) {
            fftOutputMag[i >> 1] =
                    sqrt((fftOutput[i] * fftOutput[i]) + (fftOutput[i + 1] * fftOutput[i + 1]));
        }
        for (auto i = 0; i < numBands; i++) {
            auto biggestAt = std::max_element(std::begin(fftInputMag), std::end(fftInputMag));
            auto distance = std::distance(std::begin(fftInputMag), biggestAt);
            auto freq = distance * kSamplingFrequency / n_point_fft;
            auto inputAmp = *biggestAt;
            auto outputAmp = fftOutputMag[distance];
            auto gaindB = 20 * log10(outputAmp / inputAmp);
            int j;
            for (j = 0; j < numBands; j++) {
                if (fabs(centerFrequencies[j] - freq) < 10) {
                    ASSERT_EQ(actGaindB[j], -1.0f);
                    actGaindB[j] = gaindB;
                    break;
                }
            }
            ASSERT_TRUE(j < numBands);
            *biggestAt = 0.0f;
        }
        for (auto i = 0; i < numBands - 1; i++) {
            auto diffA = expGaindB[i] - expGaindB[i + 1];
            auto diffB = actGaindB[i] - actGaindB[i + 1];
            if (fabs(diffA - diffB) > 0.5f) {
                isPass = false;
                std::cerr << "For eq preset " << preset << ", between bands " << i << " and "
                          << i + 1 << ", expected relative gain is " << diffA
                          << ", got relative gain is " << diffB << ", error " << fabs(diffA - diffB)
                          << std::endl;
            }
        }
    }
    EXPECT_TRUE(isPass);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
