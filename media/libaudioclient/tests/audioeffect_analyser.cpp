/*
 * Copyright (C) 2022 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#define LOG_TAG "AudioEffectAnalyser"

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <gtest/gtest.h>
#include <media/AudioEffect.h>
#include <system/audio_effects/effect_equalizer.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "audio_test_utils.h"
#include "pffft.hpp"

#define CHECK_OK(expr, msg) \
    mStatus = (expr);       \
    if (OK != mStatus) {    \
        mMsg = (msg);       \
        return;             \
    }

using namespace android;

constexpr float kDefAmplitude = 0.60f;

constexpr uint32_t kSamplingFrequency = 48000;

constexpr float kAudioDurationSec = 2.0;

const char* gPackageName = "AudioEffectAnalyser";

struct CaptureEnv {
    // input args
    uint32_t mSampleRate{kSamplingFrequency};
    audio_format_t mFormat{AUDIO_FORMAT_PCM_FLOAT};
    audio_channel_mask_t mChannelMask{AUDIO_CHANNEL_IN_MONO};
    float mCaptureDuration{kAudioDurationSec};
    // output val
    status_t mStatus{OK};
    std::string mMsg;
    std::string mDumpFileName;

    ~CaptureEnv();
    void capture();
};

CaptureEnv::~CaptureEnv() {
    if (!mDumpFileName.empty()) {
        std::ifstream f(mDumpFileName);
        if (f.good()) {
            f.close();
            remove(mDumpFileName.c_str());
        }
    }
}

void CaptureEnv::capture() {
    const auto capture =
            sp<AudioCapture>::make(AUDIO_SOURCE_REMOTE_SUBMIX, mSampleRate, mFormat, mChannelMask);
    CHECK_OK(capture->create(), "record creation failed")
    CHECK_OK(capture->setRecordDuration(mCaptureDuration), "set record duration failed")
    CHECK_OK(capture->enableRecordDump(), "enable record dump failed")
    CHECK_OK(capture->start(), "start recording failed")
    CHECK_OK(capture->audioProcess(), "recording process failed")
    CHECK_OK(capture->stop(), "record stop failed")
    mDumpFileName = capture->getRecordDumpFileName();
}

struct PlaybackEnv {
    // input args
    uint32_t mSampleRate{kSamplingFrequency};
    audio_format_t mFormat{AUDIO_FORMAT_PCM_FLOAT};
    audio_channel_mask_t mChannelMask{AUDIO_CHANNEL_OUT_MONO};
    audio_session_t mSessionId{AUDIO_SESSION_NONE};
    std::string mRes{"/data/local/tmp/bbb_2ch_24kHz_s16le.raw"};
    // output val
    status_t mStatus{OK};
    std::string mMsg;

    void play();
};

void PlaybackEnv::play() {
    const auto ap =
            sp<AudioPlayback>::make(mSampleRate, mFormat, mChannelMask, AUDIO_OUTPUT_FLAG_NONE,
                                    mSessionId, AudioTrack::TRANSFER_OBTAIN);
    CHECK_OK(ap->loadResource(mRes.c_str()), "Unable to open Resource")
    const auto cbPlayback = sp<OnAudioDeviceUpdateNotifier>::make();
    CHECK_OK(ap->create(), "track creation failed")
    ap->getAudioTrackHandle()->setVolume(1.0f);
    CHECK_OK(ap->getAudioTrackHandle()->addAudioDeviceCallback(cbPlayback),
             "addAudioDeviceCallback failed")
    CHECK_OK(ap->start(), "audio track start failed")
    CHECK_OK(cbPlayback->waitForAudioDeviceCb(), "audio device callback notification timed out")
    float vol;
    CHECK_OK(AudioSystem::getStreamVolume(AUDIO_STREAM_MUSIC, &vol, cbPlayback->mAudioIo),
             "getStreamVolume failed")
    if (vol < 0.5) {
        ALOGW("playback volume low, audio record capture results may not be reliable");
    }
    CHECK_OK(ap->onProcess(), "playback process failed")
    ap->stop();
}

void generateMultiTone(const std::vector<int> toneFrequencies, float samplingFrequency,
                       float duration, float amplitude, float* buffer, int numSamples) {
    int totalFrameCount = (samplingFrequency * duration);
    int limit = std::min(totalFrameCount, numSamples);

    for (auto i = 0; i < limit; i++) {
        buffer[i] = 0;
        for (auto j = 0; j < toneFrequencies.size(); j++) {
            buffer[i] += sin(2 * M_PI * toneFrequencies[j] * i / samplingFrequency);
        }
        buffer[i] *= (amplitude / toneFrequencies.size());
    }
}

sp<AudioEffect> createEffect(const effect_uuid_t* type,
                             audio_session_t sessionId = AUDIO_SESSION_OUTPUT_MIX) {
    std::string packageName{gPackageName};
    AttributionSourceState attributionSource;
    attributionSource.packageName = packageName;
    attributionSource.uid = VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
    attributionSource.pid = VALUE_OR_FATAL(legacy2aidl_pid_t_int32_t(getpid()));
    attributionSource.token = sp<BBinder>::make();
    sp<AudioEffect> effect = new AudioEffect(attributionSource);
    effect->set(type, nullptr, 0, nullptr, sessionId, AUDIO_IO_HANDLE_NONE, {}, false, false);
    return effect;
}

TEST(AudioEffectTest, CheckEqualizerEffect) {
    audio_session_t sessionId =
            (audio_session_t)AudioSystem::newAudioUniqueId(AUDIO_UNIQUE_ID_USE_SESSION);
    sp<AudioEffect> equalizer = createEffect(SL_IID_EQUALIZER, sessionId);
    ASSERT_EQ(OK, equalizer->initCheck());
    ASSERT_EQ(NO_ERROR, equalizer->setEnabled(true));
    if ((equalizer->descriptor().flags & EFFECT_FLAG_HW_ACC_MASK) != 0) {
        GTEST_SKIP() << " If the effect is hardware accelerated then remote submix capture will "
                        "not have effect processed result. Use mic capture and check if the effect "
                        "is correctly applied. This would require mic spectral response to be "
                        "taken in to consideration";
    }

#define MAX_PARAMS 64
    uint32_t buf32[sizeof(effect_param_t) / sizeof(uint32_t) + MAX_PARAMS];
    effect_param_t* eqParam = (effect_param_t*)(&buf32);

    // get num of presets
    eqParam->psize = sizeof(uint32_t);
    eqParam->vsize = sizeof(uint32_t);
    *(int32_t*)eqParam->data = EQ_PARAM_GET_NUM_OF_PRESETS;
    EXPECT_EQ(0, equalizer->getParameter(eqParam));
    EXPECT_EQ(0, eqParam->status);
    int numPresets = *((int32_t*)eqParam->data + 1);

    // get num of bands
    eqParam->psize = sizeof(uint32_t);
    eqParam->vsize = sizeof(uint32_t);
    *(int32_t*)eqParam->data = EQ_PARAM_NUM_BANDS;
    EXPECT_EQ(0, equalizer->getParameter(eqParam));
    EXPECT_EQ(0, eqParam->status);
    int numBands = *((int32_t*)eqParam->data + 1);

    const int totalFrameCount = kSamplingFrequency * kAudioDurationSec;
    const int kNPointFFT = 16384;
    const float kBinWidth = (float)kSamplingFrequency / kNPointFFT;

    // get band center frequencies
    std::vector<int> centerFrequencies;
    std::vector<int> binOffsets;
    for (auto i = 0; i < numBands; i++) {
        // TODO: Are the units of center frequencies received always in milli Hz
        eqParam->psize = sizeof(uint32_t) * 2;
        eqParam->vsize = sizeof(uint32_t);
        *(int32_t*)eqParam->data = EQ_PARAM_CENTER_FREQ;
        *((int32_t*)eqParam->data + 1) = i;
        EXPECT_EQ(0, equalizer->getParameter(eqParam));
        EXPECT_EQ(0, eqParam->status);
        float cfreq = *((int32_t*)eqParam->data + 2) / 1000;
        // pick frequency close to bin center frequency
        int bin_index = std::round(cfreq / kBinWidth);
        centerFrequencies.push_back(std::round(bin_index * kBinWidth));
        binOffsets.push_back(bin_index);
    }

    // input for effect module
    auto input = pffft::AlignedVector<float>(totalFrameCount);
    generateMultiTone(centerFrequencies, kSamplingFrequency, kAudioDurationSec, kDefAmplitude,
                      input.data(), totalFrameCount);
    auto fftInput = pffft::AlignedVector<float>(kNPointFFT);
    PFFFT_Setup* handle = pffft_new_setup(kNPointFFT, PFFFT_REAL);
    pffft_transform_ordered(handle, input.data(), fftInput.data(), nullptr, PFFFT_FORWARD);
    pffft_destroy_setup(handle);
    float inputMag[numBands];
    for (auto i = 0; i < numBands; i++) {
        auto k = binOffsets[i];
        inputMag[i] = sqrt((fftInput[k * 2] * fftInput[k * 2]) +
                           (fftInput[k * 2 + 1] * fftInput[k * 2 + 1]));
    }
    TemporaryFile tf("/data/local/tmp");
    close(tf.release());
    std::ofstream fout(tf.path, std::ios::out | std::ios::binary);
    fout.write((char*)input.data(), input.size() * sizeof(input[0]));
    fout.close();

    auto output = pffft::AlignedVector<float>(totalFrameCount);
    auto fftOutput = pffft::AlignedVector<float>(kNPointFFT);
    float outputMag[numBands];
    float expGaindB[numBands], actGaindB[numBands];
    int maxIterations = 1;  // if mic capture, run multiple times for consistency

    std::string msg = "";
    int numPresetsOk = 0, numPresetsNotFlat = 0;
    for (auto preset = 0; preset < numPresets; preset++) {
        // set preset
        eqParam->psize = sizeof(uint32_t);
        eqParam->vsize = sizeof(uint32_t);
        *(int32_t*)eqParam->data = EQ_PARAM_CUR_PRESET;
        *((int32_t*)eqParam->data + 1) = preset;
        EXPECT_EQ(0, equalizer->setParameter(eqParam));
        EXPECT_EQ(0, eqParam->status);
        // get preset gains
        eqParam->psize = sizeof(uint32_t);
        eqParam->vsize = (numBands + 1) * sizeof(uint32_t);
        *(int32_t*)eqParam->data = EQ_PARAM_PROPERTIES;
        EXPECT_EQ(0, equalizer->getParameter(eqParam));
        EXPECT_EQ(0, eqParam->status);
        t_equalizer_settings* settings =
                reinterpret_cast<t_equalizer_settings*>((int32_t*)eqParam->data + 1);
        EXPECT_EQ(preset, settings->curPreset);
        EXPECT_EQ(numBands, settings->numBands);
        bool isFlat = true;
        for (auto i = 0; i < numBands; i++) {
            expGaindB[i] = ((int16_t)settings->bandLevels[i]) / 100.0f;  // gain in milli bels
            isFlat &= expGaindB[i] == 0;
        }
        if (!isFlat) numPresetsNotFlat++;
        memset(actGaindB, 0, sizeof(actGaindB));
        for (auto j = 0; j < maxIterations; j++) {
            PlaybackEnv argsP;
            argsP.mRes = std::string{tf.path};
            argsP.mSessionId = sessionId;
            std::thread playbackThread(&PlaybackEnv::play, &argsP);
            CaptureEnv argsR;
            argsR.mCaptureDuration = 1.0;
            std::thread captureThread(&CaptureEnv::capture, &argsR);
            captureThread.join();
            playbackThread.join();
            ASSERT_EQ(OK, argsR.mStatus) << argsR.mMsg;
            ASSERT_EQ(OK, argsP.mStatus) << argsP.mMsg;
            ASSERT_FALSE(argsR.mDumpFileName.empty()) << "recorded not written to file";
            std::ifstream fin(argsR.mDumpFileName, std::ios::in | std::ios::binary);
            fin.read((char*)output.data(), totalFrameCount * sizeof(output[0]));
            fin.close();
            handle = pffft_new_setup(kNPointFFT, PFFFT_REAL);
            pffft_transform_ordered(handle, output.data() + kNPointFFT, fftOutput.data(), nullptr,
                                    PFFFT_FORWARD);
            pffft_destroy_setup(handle);

            for (auto i = 0; i < numBands; i++) {
                auto k = binOffsets[i];
                outputMag[i] = sqrt((fftOutput[k * 2] * fftOutput[k * 2]) +
                                    (fftOutput[k * 2 + 1] * fftOutput[k * 2 + 1]));
                actGaindB[i] += 20 * log10(outputMag[i] / inputMag[i]);
                if (j == maxIterations - 1) actGaindB[i] /= maxIterations;
            }
        }
        bool isOk = true;
        for (auto i = 0; i < numBands - 1; i++) {
            auto diffA = expGaindB[i] - expGaindB[i + 1];
            auto diffB = actGaindB[i] - actGaindB[i + 1];
            if (fabs(diffA - diffB) > 1.0f) {
                msg += (android::base::StringPrintf(
                        "For eq preset : %d, between bands %d and %d, expected relative gain is : "
                        "%f, got relative gain is : %f, error : %f \n",
                        preset, i, i + 1, diffA, diffB, diffA - diffB));
                isOk = false;
            }
        }
        if (isOk) numPresetsOk++;
    }
    if (numPresetsOk > numPresets - numPresetsNotFlat) {
        EXPECT_EQ(numPresetsOk, numPresets) << msg;
    } else {
        ADD_FAILURE() << "equalizer not applied";
    }
}