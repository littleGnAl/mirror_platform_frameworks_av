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

#include <gtest/gtest.h>
#include <media/AudioEffect.h>
#include <system/audio_effects/effect_equalizer.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "audio_test_utils.h"
#include "pffft.h"

#define CHECK_OK(expr, msg)   \
    env->mStatus = (expr);    \
    if (OK != env->mStatus) { \
        env->mMsg = (msg);    \
        return 0;             \
    }

using namespace android;

constexpr float kDefAmplitude = 0.60f;

constexpr uint32_t kSamplingFrequency = 48000;

constexpr float kAudioDurationSec = 3.0;

const char* gPackageName = "AudioEffectAnalyser";

template <typename... Args>
std::string StringFormat(const std::string& format, Args... args) {
    auto size = std::snprintf(nullptr, 0, format.c_str(), args...);
    if (size < 0) return std::string();
    std::vector<char> buffer(size + 1);  // Add 1 for terminating null byte
    std::snprintf(buffer.data(), buffer.size(), format.c_str(), args...);
    return std::string(buffer.data(), size);  // Exclude the terminating null byte
}

typedef struct {
    // input args
    uint32_t mSampleRate{kSamplingFrequency};
    audio_format_t mFormat{AUDIO_FORMAT_PCM_FLOAT};
    audio_channel_mask_t mChannelMask{AUDIO_CHANNEL_IN_MONO};
    float mCaptureDuration{kAudioDurationSec};
    // output val
    status_t mStatus{OK};
    std::string mMsg{""};
    std::string mDumpFileName{""};
} CaptureEnv;

typedef struct {
    // input args
    uint32_t mSampleRate{kSamplingFrequency};
    audio_format_t mFormat{AUDIO_FORMAT_PCM_FLOAT};
    audio_channel_mask_t mChannelMask{AUDIO_CHANNEL_OUT_MONO};
    audio_session_t mSessionId{AUDIO_SESSION_NONE};
    std::string mRes{"/data/local/tmp/bbb_2ch_24kHz_s16le.raw"};
    // output val
    status_t mStatus{OK};
    std::string mMsg{""};
} PlaybackEnv;

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

void* captureAudio(void* args) {
    CaptureEnv* env = static_cast<CaptureEnv*>(args);
    const auto capture = sp<AudioCapture>::make(AUDIO_SOURCE_REMOTE_SUBMIX, env->mSampleRate,
                                                env->mFormat, env->mChannelMask);
    CHECK_OK(capture->create(), "record creation failed")
    CHECK_OK(capture->setRecordDuration(env->mCaptureDuration), "set record duration failed")
    CHECK_OK(capture->enableRecordDump(), "enable record dump failed")
    CHECK_OK(capture->start(), "start recording failed")
    CHECK_OK(capture->audioProcess(), "recording process failed")
    CHECK_OK(capture->stop(), "record stop failed")
    const char* dumpFileName = capture->getRecordDumpFileName();
    if (dumpFileName) env->mDumpFileName = std::string{dumpFileName};
    return 0;
}

void* playAudio(void* args) {
    PlaybackEnv* env = static_cast<PlaybackEnv*>(args);
    const auto ap = sp<AudioPlayback>::make(env->mSampleRate, env->mFormat, env->mChannelMask,
                                            AUDIO_OUTPUT_FLAG_NONE, env->mSessionId,
                                            AudioTrack::TRANSFER_OBTAIN);
    CHECK_OK(ap->loadResource(env->mRes.c_str()), "Unable to open Resource")
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
    return 0;
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
    (void)numPresets;

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
    float* input = (float*)pffft_aligned_malloc(totalFrameCount * sizeof(*input));
    generateMultiTone(centerFrequencies, kSamplingFrequency, kAudioDurationSec, kDefAmplitude,
                      input, totalFrameCount);
    float* fftInput = (float*)pffft_aligned_malloc(kNPointFFT * sizeof(*fftInput));
    PFFFT_Setup* handle = pffft_new_setup(kNPointFFT, PFFFT_REAL);
    pffft_transform_ordered(handle, input, fftInput, nullptr, PFFFT_FORWARD);
    pffft_destroy_setup(handle);
    float inputMag[numBands];
    for (auto i = 0; i < numBands; i++) {
        auto k = binOffsets[i];
        inputMag[i] = sqrt((fftInput[k * 2] * fftInput[k * 2]) +
                           (fftInput[k * 2 + 1] * fftInput[k * 2 + 1]));
    }
    std::ofstream fout("/data/local/tmp/tones.bin", std::ios::out | std::ios::binary);
    fout.write((char*)input, totalFrameCount * sizeof(*input));
    fout.close();

    PlaybackEnv argsP;
    argsP.mRes = "/data/local/tmp/tones.bin";
    argsP.mSessionId = sessionId;
    CaptureEnv argsR;
    argsR.mCaptureDuration = 1.0;
    pthread_t captureThread, playbackThread;

    float* output = (float*)pffft_aligned_malloc(totalFrameCount * sizeof(*output));
    float* fftOutput = (float*)pffft_aligned_malloc(kNPointFFT * sizeof(*fftOutput));
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
            pthread_create(&playbackThread, nullptr, playAudio, &argsP);
            pthread_create(&captureThread, nullptr, captureAudio, &argsR);
            pthread_join(captureThread, nullptr);
            pthread_join(playbackThread, nullptr);
            ASSERT_EQ(OK, argsR.mStatus) << argsR.mMsg.c_str();
            ASSERT_EQ(OK, argsP.mStatus) << argsP.mMsg.c_str();
            ASSERT_FALSE(argsR.mDumpFileName.empty()) << "recorded not written to file";
            std::ifstream fin(argsR.mDumpFileName.c_str(), std::ios::in | std::ios::binary);
            fin.read((char*)output, totalFrameCount * sizeof(*output));
            fin.close();
            remove(argsR.mDumpFileName.c_str());
            handle = pffft_new_setup(kNPointFFT, PFFFT_REAL);
            pffft_transform_ordered(handle, output + kNPointFFT, fftOutput, nullptr, PFFFT_FORWARD);
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
                msg += (StringFormat(
                        "For eq preset : %d, between bands %d and %d, expected relative gain is : "
                        "%f, got relative gain is : %f, error : %f \n",
                        preset, i, i + 1, diffA, diffB, diffA - diffB));
                isOk = false;
            }
        }
        if (isOk) numPresetsOk++;
    }
    remove(argsP.mRes.c_str());
    pffft_aligned_free(input);
    pffft_aligned_free(fftInput);
    pffft_aligned_free(output);
    pffft_aligned_free(fftOutput);
    if (numPresetsOk > numPresets - numPresetsNotFlat) {
        EXPECT_EQ(numPresetsOk, numPresets) << msg;
    } else {
        ADD_FAILURE() << "equalizer not applied";
    }
}