/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <aidl/android/hardware/audio/effect/BnEffect.h>

#include <audio_effects/effect_aec.h>
#include <audio_effects/effect_agc2.h>
#include <audio_effects/effect_ns.h>

#include "effect-impl/EffectUUID.h"

namespace aidl::android::hardware::audio::effect {

// Acoustic Echo Cancellation
static const std::string kAcousticEchoCancelerEffectName = "Acoustic Echo Canceler";
static const AcousticEchoCanceler::Capability kAcousticEchoCancelerCap = {
        .maxEchoDelayUs = 500, .supportMobileMode = true};
static const Descriptor kAcousticEchoCancelerDesc = {
        .common = {.id = {.type = kAcousticEchoCancelerTypeUUID,
                          .uuid = kAcousticEchoCancelerSwImplUUID,
                          .proxy = kEffectNullUuid},
                   .flags = {.type = Flags::Type::PRE_PROC, .deviceIndication = true},
                   .name = kAcousticEchoCancelerEffectName,
                   .implementor = "The Android Open Source Project"},
        .capability = Capability::make<Capability::acousticEchoCanceler>(kAcousticEchoCancelerCap)};

// Automatic Gain Control 2
static const AutomaticGainControlV2::Capability kAutomaticGainControlV2Cap = {
        .maxFixedDigitalGainMb = 90};
static const std::string kAutomaticGainControlV2EffectName = "Automatic Gain Control";
static const Descriptor kAutomaticGainControlV2Desc = {
        .common = {.id = {.type = kAutomaticGainControlV2TypeUUID,
                          .uuid = kAutomaticGainControlV2SwImplUUID,
                          .proxy = kEffectNullUuid},
                   .flags = {.type = Flags::Type::PRE_PROC, .deviceIndication = true},
                   .name = kAutomaticGainControlV2EffectName,
                   .implementor = "The Android Open Source Project"},
        .capability =
                Capability::make<Capability::automaticGainControlV2>(kAutomaticGainControlV2Cap)};

// Noise suppression
static const std::string kNoiseSuppressionEffectName = "Noise Suppression";
static const Descriptor kNoiseSuppressionDesc = {
        .common = {.id = {.type = kNoiseSuppressionTypeUUID,
                          .uuid = kNoiseSuppressionSwImplUUID,
                          .proxy = kEffectNullUuid},
                   .flags = {.type = Flags::Type::PRE_PROC, .deviceIndication = true},
                   .name = kNoiseSuppressionEffectName,
                   .implementor = "The Android Open Source Project"}};

enum class PreProcessingEffectType {
    ACOUSTIC_ECHO_CANCELLATION,
    AUTOMATIC_GAIN_CONTROL_V2,
    NOISE_SUPPRESSION,
};

inline std::ostream& operator<<(std::ostream& out, const PreProcessingEffectType& type) {
    switch (type) {
        case PreProcessingEffectType::ACOUSTIC_ECHO_CANCELLATION:
            return out << kAcousticEchoCancelerEffectName;
        case PreProcessingEffectType::AUTOMATIC_GAIN_CONTROL_V2:
            return out << kAutomaticGainControlV2EffectName;
        case PreProcessingEffectType::NOISE_SUPPRESSION:
            return out << kNoiseSuppressionEffectName;
    }
    return out << "EnumPreProcessingEffectTypeError";
}

}  // namespace aidl::android::hardware::audio::effect
