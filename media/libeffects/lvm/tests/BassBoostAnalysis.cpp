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

#include <cmath>
#include <fstream>
#include <iostream>
#include <vector>
#include <system/audio_effects/effect_bassboost.h>

#include "EffectTestHelper.h"

using namespace android;

// struct representing monotone signal attributes
typedef struct {
    float estFrequency;
    float maxAmplitude;
    int totalZeroCrossings;
} SignalCharacteristics;

constexpr float kDefAmplitude = 0.25f;

constexpr float kSamplingFrequency = 48000;

constexpr audio_channel_mask_t kChannelMask = AUDIO_CHANNEL_OUT_MONO;

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

TEST(TestEffect, NxpBassBoostEffect) {
    // nxp sw bassboost
    effect_uuid_t uuid = {0x8631f300, 0x72e2, 0x11df, 0xb57e, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
    const int boostStrengthMin = 0;
    const int boostStrengthMax = 1000;

    const int totalFrameCount = kSamplingFrequency * kAudioDuration;
    const int kAudioDurationPrimePad = 1;
    ASSERT_GE(kAudioDuration, 2 * kAudioDurationPrimePad + 3);
    const int frameCountPrimePad = kSamplingFrequency * kAudioDurationPrimePad;

    // Initialize input buffer with deterministic pseudo-random values
    std::vector<float> input(totalFrameCount);
    std::vector<float> output(totalFrameCount);

    int frameCount, loopCount;
    factorPairs(totalFrameCount, frameCount, loopCount);

    std::vector<int> boostStrengths;
    for (auto boostStrength = boostStrengthMin; boostStrength <= boostStrengthMax;
         boostStrength += 50) {
        boostStrengths.push_back(boostStrength);
    }

    std::vector<int> toneFrequencies;
    for (auto toneFrequency = 20; toneFrequency < 500; toneFrequency++) {
        toneFrequencies.push_back(toneFrequency);
    }
    /*for (auto toneFrequency = 400; toneFrequency < 1000; toneFrequency+=100) {
        toneFrequencies.push_back(toneFrequency);
    }
    for (auto toneFrequency = 1000; toneFrequency < 15000; toneFrequency+=1000) {
        toneFrequencies.push_back(toneFrequency);
    }*/

    for (auto boostStrength : boostStrengths) {
        std::vector<SignalCharacteristics> freqResponse;
        char filename[64];
        sprintf(filename, "out_bs_%d.txt", boostStrength);
        std::ofstream outData(filename, std::ios::out);
        for (auto toneFrequency : toneFrequencies) {
            generateSineWave(toneFrequency, kSamplingFrequency, kAudioDuration, kDefAmplitude,
                             input.data(), input.size());
            auto inpAttr = getMonotoneCharacteristics(input.data(), input.size(), kAudioDuration);
            EXPECT_EQ(inpAttr.estFrequency, toneFrequency);
            EXPECT_NEAR(inpAttr.maxAmplitude, kDefAmplitude, 0.001);

            EffectTestHelper effect(&uuid, kChannelMask, kChannelMask, kSamplingFrequency,
                                    frameCount, loopCount);

            ASSERT_NO_FATAL_FAILURE(effect.createEffect());
            ASSERT_NO_FATAL_FAILURE(effect.setConfig());
            ASSERT_NO_FATAL_FAILURE(
                    effect.setParam<int16_t>(BASSBOOST_PARAM_STRENGTH, boostStrength));
            ASSERT_NO_FATAL_FAILURE(effect.process(input.data(), output.data()));
            ASSERT_NO_FATAL_FAILURE(effect.releaseEffect());
            auto outPtr = output.data() + frameCountPrimePad;
            auto opAttr = getMonotoneCharacteristics(outPtr, output.size() - 2 * frameCountPrimePad,
                                                     kAudioDuration - 2 * kAudioDurationPrimePad);
            EXPECT_NEAR(inpAttr.estFrequency, opAttr.estFrequency, 1);
            // EXPECT_EQ(inpAttr.maxAmplitude, opAttr.maxAmplitude);
            freqResponse.push_back(opAttr);
            outData << opAttr.maxAmplitude / kDefAmplitude << std::endl;
#if 0
            std::ofstream fin("in.bin", std::ios::out | std::ios::binary);
            fin.write((char*)input.data(), input.size() * sizeof(float));
            fin.close();
            std::ofstream fout("out.bin", std::ios::out | std::ios::binary);
            fout.write((char*)output.data(), output.size() * sizeof(float));
            fout.close();
#endif
        }
        outData.close();
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
