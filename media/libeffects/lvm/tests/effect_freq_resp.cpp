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

using namespace android;

// struct representing monotone signal attributes (estimated)
typedef struct {
    float estFrequency;
    float maxAmplitude;
    int totalZeroCrossings;
} SignalCharacteristics;

constexpr float kDefAmplitude = 0.25f;

constexpr float kSamplingFrequency = 48000;

constexpr float kAudioDuration = 5.0;  // in sec

// monotone generator
void generateSineWave(float toneFrequency, float samplingFrequency, float duration, float amplitude,
                      float* buffer, int size) {
    int totalFrameCount = (samplingFrequency * duration);
    int limit = (totalFrameCount < size) ? totalFrameCount : size;

    for (auto i = 0; i < limit; i++) {
        buffer[i] = sin(2 * M_PI * toneFrequency * i / samplingFrequency) * amplitude;
    }
}

// get frequency and max amplitude of the monotone signal
SignalCharacteristics getMonotoneCharacteristics(float* buffer, int size, float duration) {
    SignalCharacteristics attr{0.0f, 0.0f, 0};
    int zeroCrossings = 0;
    float maxAmplitude = 0.0f;
    for (auto i = 0; i < size - 1; i++) {
        bool signA = buffer[i] > 0;
        bool signB = buffer[i + 1] > 0;
        if (signA != signB) zeroCrossings++;
        float tmp = buffer[i] < 0 ? -buffer[i] : buffer[i];
        if (tmp > maxAmplitude) maxAmplitude = tmp;
    }
    attr.totalZeroCrossings = zeroCrossings;
    attr.estFrequency = zeroCrossings / (2 * duration);
    attr.maxAmplitude = maxAmplitude;
    return attr;
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

    /* std::vector<int> toneFrequencies;
    for (auto toneFrequency = 20; toneFrequency < 20000; toneFrequency += 10) {
        toneFrequencies.push_back(toneFrequency);
    } */

    // sample count to be ignored from output during analysis (FIR side effects)
    const int kAudioDurationPrimePad = 1;
    ASSERT_GE(kAudioDuration, 2 * kAudioDurationPrimePad + 3);
    const int frameCountPrimePad = kSamplingFrequency * kAudioDurationPrimePad;

    for (int preset = 0; preset < numPresets; preset++) {
        std::vector<SignalCharacteristics> freqResponse;
#if WRITE_TO_FILE
        char filename[64];
        sprintf(filename, "out_preset_%d.txt", preset);
        std::ofstream outData(filename, std::ios::out);
#endif
        int i = 0;
        float gaindB[numBands], achievedGaindB[numBands];
        for (auto toneFrequency : centerFrequencies) {
            generateSineWave(toneFrequency, kSamplingFrequency, kAudioDuration, kDefAmplitude,
                             input.data(), input.size());
            auto inpAttr = getMonotoneCharacteristics(input.data(), input.size(), kAudioDuration);
            EXPECT_EQ(inpAttr.estFrequency, toneFrequency);
            // EXPECT_NEAR(inpAttr.maxAmplitude, kDefAmplitude, 0.001);

            EffectTestHelper effect(&uuid, AUDIO_CHANNEL_OUT_MONO, AUDIO_CHANNEL_OUT_MONO,
                                    kSamplingFrequency, frameCount, loopCount);

            ASSERT_NO_FATAL_FAILURE(effect.createEffect());
            ASSERT_NO_FATAL_FAILURE(effect.setConfig());
            ASSERT_NO_FATAL_FAILURE(effect.setParam<int32_t>(EQ_PARAM_CUR_PRESET, preset));
            if (i == 0) {
                status = effect.getParam<true>(EQ_PARAM_PROPERTIES, -1, paramVal);
                EXPECT_EQ(0, status);
                ASSERT_EQ(preset, paramVal[0]);
                ASSERT_EQ(numBands, paramVal[1]);
                for (auto j = 0; j < numBands; j++) {
                    gaindB[j] = paramVal[2 + j] / 100.0f;  // gain in milli bels
                }
            }
            ASSERT_NO_FATAL_FAILURE(effect.process(input.data(), output.data()));
            ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());
            auto outPtr = output.data() + frameCountPrimePad;
            auto opAttr = getMonotoneCharacteristics(outPtr, output.size() - 2 * frameCountPrimePad,
                                                     kAudioDuration - 2 * kAudioDurationPrimePad);
            EXPECT_NEAR(inpAttr.estFrequency, opAttr.estFrequency, 1);
            freqResponse.push_back(opAttr);
#if WRITE_TO_FILE
            outData << opAttr.maxAmplitude / inpAttr.maxAmplitude << std::endl;
#endif
            achievedGaindB[i] = 20 * log10(opAttr.maxAmplitude / inpAttr.maxAmplitude);
            i++;
        }
#if WRITE_TO_FILE
        outData.close();
#endif
        float energyDampdB = gaindB[numBands / 2] - achievedGaindB[numBands / 2];
        for (int i = 0; i < numBands; i++) {
            achievedGaindB[i] += energyDampdB;
            EXPECT_GE(2.5, abs(achievedGaindB[i] - gaindB[i]));  // blind test 2.5db is noticeable
        }
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
