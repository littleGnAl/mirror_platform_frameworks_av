/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "policy.h"
#include <Volume.h>
#include <media/AudioPolicy.h>
#include <system/audio.h>
#include <convert/convert.h>
#include <utils/Log.h>
#include <string>
#include <utils/Vector.h>
#include <utils/SortedVector.h>
#include <map>

namespace android {

static const std::map<uint32_t/*mixType*/, const std::string> mixTypeConversion = {
    {MIX_TYPE_INVALID, "MIX_TYPE_INVALID"},
    {MIX_TYPE_PLAYERS, "MIX_TYPE_PLAYERS"},
    {MIX_TYPE_RECORDERS, "MIX_TYPE_RECORDERS"}
};

static const std::map<uint32_t/*mRouteFlags*/, const std::string> routeFlagsConversion = {
    {MIX_ROUTE_FLAG_RENDER, "MIX_ROUTE_FLAG_RENDER"},
    {MIX_ROUTE_FLAG_LOOP_BACK, "MIX_ROUTE_FLAG_LOOP_BACK"},
    {MIX_ROUTE_FLAG_ALL, "MIX_ROUTE_FLAG_ALL"}
};

static const std::map<uint32_t/*mRule*/, const std::string> ruleConversion = {
    {RULE_EXCLUSION_MASK, "RULE_EXCLUSION_MASK"},
    {RULE_MATCH_ATTRIBUTE_USAGE, "RULE_MATCH_ATTRIBUTE_USAGE"},
    {RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET, "RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET"},
    {RULE_MATCH_UID, "RULE_MATCH_UID"},
    {RULE_EXCLUDE_ATTRIBUTE_USAGE, "RULE_EXCLUDE_ATTRIBUTE_USAGE"},
    {RULE_EXCLUDE_ATTRIBUTE_CAPTURE_PRESET, "RULE_EXCLUDE_ATTRIBUTE_CAPTURE_PRESET"},
    {RULE_EXCLUDE_UID, "RULE_EXCLUDE_UID"},
};

static const std::map<audio_usage_t, const std::string> usageConversion = {
    {AUDIO_USAGE_UNKNOWN, "AUDIO_USAGE_UNKNOWN"},
    {AUDIO_USAGE_MEDIA, "AUDIO_USAGE_MEDIA"},
    {AUDIO_USAGE_VOICE_COMMUNICATION, "AUDIO_USAGE_VOICE_COMMUNICATION"},
    {AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING, "AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING"},
    {AUDIO_USAGE_ALARM, "AUDIO_USAGE_ALARM"},
    {AUDIO_USAGE_NOTIFICATION, "AUDIO_USAGE_NOTIFICATION"},
    {AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE, "AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE"},
    {AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST, "AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST"},
    {AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT, "AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT"},
    {AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED, "AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED"},
    {AUDIO_USAGE_NOTIFICATION_EVENT, "AUDIO_USAGE_NOTIFICATION_EVENT"},
    {AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY, "AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY"},
    {AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE, "AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE"},
    {AUDIO_USAGE_ASSISTANCE_SONIFICATION, "AUDIO_USAGE_ASSISTANCE_SONIFICATION"},
    {AUDIO_USAGE_GAME, "AUDIO_USAGE_GAME"},
    {AUDIO_USAGE_VIRTUAL_SOURCE, "AUDIO_USAGE_VIRTUAL_SOURCE"},
    {AUDIO_USAGE_CNT, "AUDIO_USAGE_CNT"},
    {AUDIO_USAGE_MAX, "AUDIO_USAGE_MAX"},
};

static const std::map<audio_source_t, const std::string> sourceConversion = {
    {AUDIO_SOURCE_DEFAULT, "AUDIO_SOURCE_DEFAULT"},
    {AUDIO_SOURCE_MIC, "AUDIO_SOURCE_MIC"},
    {AUDIO_SOURCE_VOICE_UPLINK, "AUDIO_SOURCE_VOICE_UPLINK"},
    {AUDIO_SOURCE_VOICE_DOWNLINK, "AUDIO_SOURCE_VOICE_DOWNLINK"},
    {AUDIO_SOURCE_VOICE_CALL, "AUDIO_SOURCE_VOICE_CALL"},
    {AUDIO_SOURCE_CAMCORDER, "AUDIO_SOURCE_CAMCORDER"},
    {AUDIO_SOURCE_VOICE_RECOGNITION, "AUDIO_SOURCE_VOICE_RECOGNITION"},
    {AUDIO_SOURCE_VOICE_COMMUNICATION, "AUDIO_SOURCE_VOICE_COMMUNICATION"},
    {AUDIO_SOURCE_REMOTE_SUBMIX, "AUDIO_SOURCE_REMOTE_SUBMIX"},
    {AUDIO_SOURCE_UNPROCESSED, "AUDIO_SOURCE_UNPROCESSED"},
    {AUDIO_SOURCE_CNT, "AUDIO_SOURCE_CNT"},
    {AUDIO_SOURCE_MAX, "AUDIO_SOURCE_MAX"},
    {AUDIO_SOURCE_FM_TUNER, "AUDIO_SOURCE_FM_TUNER"},
    {AUDIO_SOURCE_HOTWORD, "AUDIO_SOURCE_HOTWORD"},
};


struct SampleRateTraits
{
    typedef uint32_t Type;
    typedef SortedVector<Type> Collection;
};
struct DeviceTraits
{
    typedef audio_devices_t Type;
    typedef Vector<Type> Collection;
};
struct OutputFlagTraits
{
    typedef audio_output_flags_t Type;
    typedef Vector<Type> Collection;
};
struct InputFlagTraits
{
    typedef audio_input_flags_t Type;
    typedef Vector<Type> Collection;
};
struct FormatTraits
{
    typedef audio_format_t Type;
    typedef Vector<Type> Collection;
};
struct ChannelTraits
{
    typedef audio_channel_mask_t Type;
    typedef SortedVector<Type> Collection;
};
struct OutputChannelTraits : public ChannelTraits {};
struct InputChannelTraits : public ChannelTraits {};
struct ChannelIndexTraits : public ChannelTraits {};
struct GainModeTraits
{
    typedef audio_gain_mode_t Type;
    typedef Vector<Type> Collection;
};
struct StreamTraits
{
  typedef audio_stream_type_t Type;
  typedef Vector<Type> Collection;
};
struct DeviceCategoryTraits
{
  typedef device_category Type;
  typedef Vector<Type> Collection;
};
template <typename T>
struct DefaultTraits
{
  typedef T Type;
  typedef Vector<Type> Collection;
};

template <class Traits>
static void collectionFromString(const std::string &str, typename Traits::Collection &collection,
                                 const char *del = "|")
{
    char *literal = strdup(str.c_str());
    for (const char *cstr = strtok(literal, del); cstr != NULL; cstr = strtok(NULL, del)) {
        typename Traits::Type value;
        if (utilities::convertTo<std::string, typename Traits::Type >(cstr, value)) {
            collection.add(value);
        }
    }
    free(literal);
}

template <class Traits>
class TypeConverter
{
public:
    static bool toString(const typename Traits::Type &value, std::string &str);

    static bool fromString(const std::string &str, typename Traits::Type &result);

    static void collectionFromString(const std::string &str,
                                     typename Traits::Collection &collection,
                                     const char *del = "|");

    static uint32_t maskFromString(const std::string &str, const char *del = "|");

protected:
    struct Table {
        const char *literal;
        typename Traits::Type value;
    };

    static const Table mTable[];
    static const size_t mSize;
};

typedef TypeConverter<DeviceTraits> DeviceConverter;
typedef TypeConverter<OutputFlagTraits> OutputFlagConverter;
typedef TypeConverter<InputFlagTraits> InputFlagConverter;
typedef TypeConverter<FormatTraits> FormatConverter;
typedef TypeConverter<OutputChannelTraits> OutputChannelConverter;
typedef TypeConverter<InputChannelTraits> InputChannelConverter;
typedef TypeConverter<ChannelIndexTraits> ChannelIndexConverter;
typedef TypeConverter<GainModeTraits> GainModeConverter;
typedef TypeConverter<StreamTraits> StreamTypeConverter;
typedef TypeConverter<DeviceCategoryTraits> DeviceCategoryConverter;

static SampleRateTraits::Collection samplingRatesFromString(const std::string &samplingRates,
                                                            const char *del = "|")
{
    SampleRateTraits::Collection samplingRateCollection;
    collectionFromString<SampleRateTraits>(samplingRates, samplingRateCollection, del);
    return samplingRateCollection;
}

static FormatTraits::Collection formatsFromString(const std::string &formats, const char *del = "|")
{
    FormatTraits::Collection formatCollection;
    FormatConverter::collectionFromString(formats, formatCollection, del);
    return formatCollection;
}

static audio_format_t formatFromString(const std::string &literalFormat)
{
    audio_format_t format;
    if (literalFormat.empty()) {
        return gDynamicFormat;
    }
    FormatConverter::fromString(literalFormat, format);
    return format;
}

static audio_channel_mask_t channelMaskFromString(const std::string &literalChannels)
{
    audio_channel_mask_t channels;
    if (!OutputChannelConverter::fromString(literalChannels, channels) ||
            !InputChannelConverter::fromString(literalChannels, channels)) {
        return AUDIO_CHANNEL_INVALID;
    }
    return channels;
}

static ChannelTraits::Collection channelMasksFromString(const std::string &channels,
                                                        const char *del = "|")
{
    ChannelTraits::Collection channelMaskCollection;
    OutputChannelConverter::collectionFromString(channels, channelMaskCollection, del);
    InputChannelConverter::collectionFromString(channels, channelMaskCollection, del);
    ChannelIndexConverter::collectionFromString(channels, channelMaskCollection, del);
    return channelMaskCollection;
}

static InputChannelTraits::Collection inputChannelMasksFromString(const std::string &inChannels,
                                                                  const char *del = "|")
{
    InputChannelTraits::Collection inputChannelMaskCollection;
    InputChannelConverter::collectionFromString(inChannels, inputChannelMaskCollection, del);
    ChannelIndexConverter::collectionFromString(inChannels, inputChannelMaskCollection, del);
    return inputChannelMaskCollection;
}

static OutputChannelTraits::Collection outputChannelMasksFromString(const std::string &outChannels,
                                                                    const char *del = "|")
{
    OutputChannelTraits::Collection outputChannelMaskCollection;
    OutputChannelConverter::collectionFromString(outChannels, outputChannelMaskCollection, del);
    ChannelIndexConverter::collectionFromString(outChannels, outputChannelMaskCollection, del);
    return outputChannelMaskCollection;
}

}; // namespace android

