/*
 * Copyright 2014, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaCodecInfo"

#include <android-base/strings.h>
#include <android-base/properties.h>
#include <utils/Log.h>

#include <media/IOMX.h>

#include <media/MediaCodecInfo.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AUtils.h>
#include <binder/Parcel.h>

namespace android {

static const Range<int> POSITIVE_INTEGERS = Range<int>(1, INT_MAX);
static const Range<long> POSITIVE_LONGS = Range(1L, LONG_MAX);
static const Range<int> BITRATE_RANGE = Range<int>(0, 500000000);
static const Range<int> FRAME_RATE_RANGE = Range<int>(0, 960);
static const Range<Rational> POSITIVE_RATIONALS =
            Range<Rational>(Rational(1, INT_MAX), Rational(INT_MAX, 1));

/* For internal use only. Not exposed as a public API */
// must not contain KEY_PROFILE
static const std::set<std::string> AUDIO_LEVEL_CRITICAL_FORMAT_KEYS = {
    // We don't set level-specific limits for audio codecs today. Key candidates would
    // be sample rate, bit rate or channel count.
    // MediaFormat.KEY_SAMPLE_RATE,
    // MediaFormat.KEY_CHANNEL_COUNT,
    // MediaFormat.KEY_BIT_RATE,
    KEY_MIME };

/* package private */
// must not contain KEY_PROFILE
static const std::set<std::string> VIDEO_LEVEL_CRITICAL_FORMAT_KEYS = {
        KEY_WIDTH,
        KEY_HEIGHT,
        KEY_FRAME_RATE,
        KEY_BIT_RATE,
        KEY_MIME };

// found stuff that is not supported by framework (=> this should not happen)
static const int ERROR_UNRECOGNIZED   = (1 << 0);
// found profile/level for which we don't have capability estimates
static const int ERROR_UNSUPPORTED    = (1 << 1);
// have not found any profile/level for which we don't have capability estimate
// static const int ERROR_NONE_SUPPORTED = (1 << 2);

/** 480p 24fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint SD_24
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(720, 480, 24);
/** 576p 25fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint SD_25
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(720, 576, 25);
/** 480p 30fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint SD_30
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(720, 480, 30);
/** 480p 48fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint SD_48
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(720, 480, 48);
/** 576p 50fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint SD_50
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(720, 576, 50);
/** 480p 60fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint SD_60
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(720, 480, 60);

/** 720p 24fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint HD_24
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1280, 720, 24);
/** 720p 25fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint HD_25
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1280, 720, 25);
/** 720p 30fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint HD_30
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1280, 720, 30);
/** 720p 50fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint HD_50
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1280, 720, 50);
/** 720p 60fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint HD_60
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1280, 720, 60);
/** 720p 100fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint HD_100
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1280, 720, 100);
/** 720p 120fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint HD_120
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1280, 720, 120);
/** 720p 200fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint HD_200
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1280, 720, 200);
/** 720p 240fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint HD_240
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1280, 720, 240);

/** 1080p 24fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint FHD_24
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1920, 1080, 24);
/** 1080p 25fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint FHD_25
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1920, 1080, 25);
/** 1080p 30fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint FHD_30
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1920, 1080, 30);
/** 1080p 50fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint FHD_50
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1920, 1080, 50);
/** 1080p 60fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint FHD_60
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1920, 1080, 60);
/** 1080p 100fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint FHD_100
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1920, 1080, 100);
/** 1080p 120fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint FHD_120
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1920, 1080, 120);
/** 1080p 200fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint FHD_200
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1920, 1080, 200);
/** 1080p 240fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint FHD_240
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(1920, 1080, 240);

/** 2160p 24fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint UHD_24
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(3840, 2160, 24);
/** 2160p 25fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint UHD_25
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(3840, 2160, 25);
/** 2160p 30fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint UHD_30
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(3840, 2160, 30);
/** 2160p 50fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint UHD_50
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(3840, 2160, 50);
/** 2160p 60fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint UHD_60
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(3840, 2160, 60);
/** 2160p 100fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint UHD_100
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(3840, 2160, 100);
/** 2160p 120fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint UHD_120
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(3840, 2160, 120);
/** 2160p 200fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint UHD_200
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(3840, 2160, 200);
/** 2160p 240fps */
static const MediaCodecInfo::VideoCapabilities::PerformancePoint UHD_240
        = MediaCodecInfo::VideoCapabilities::PerformancePoint(3840, 2160, 240);

// static
Range<int> MediaCodecInfo::GetSizeRange() {
#ifdef __LP64__
    return Range<int>(1, 32768);
#else
    std::string valueStr = base::GetProperty("media.resolution.limit.32bit", "4096");
    int value = std::atoi(valueStr.c_str());
    return Range<int>(1, value);
#endif
}

// static
void MediaCodecInfo::CheckPowerOfTwo(int value) {
    CHECK((value & (value - 1)) == 0);
}

void MediaCodecInfo::CapabilitiesBase::setParentError(int error) {
    auto lockParent = mParent.lock();
    if (!lockParent) {
        return;
    }
    lockParent->mError |= error;
}

Range<int> MediaCodecInfo::AudioCapabilities::getBitrateRange() const {
    return mBitrateRange;
}

std::vector<int> MediaCodecInfo::AudioCapabilities::getSupportedSampleRates() const {
    return mSampleRates;
}

std::vector<Range<int>> MediaCodecInfo::AudioCapabilities::getSupportedSampleRateRanges() const {
    return mSampleRateRanges;
}

int MediaCodecInfo::AudioCapabilities::getMaxInputChannelCount() const {
    int overall_max = 0;
    for (int i = mInputChannelRanges.size() - 1; i >= 0; i--) {
        int lmax = mInputChannelRanges[i].upper();
        if (lmax > overall_max) {
            overall_max = lmax;
        }
    }
    return overall_max;
}

int MediaCodecInfo::AudioCapabilities::getMinInputChannelCount() const {
    int overall_min = MAX_INPUT_CHANNEL_COUNT;
    for (int i = mInputChannelRanges.size() - 1; i >= 0; i--) {
        int lmin = mInputChannelRanges[i].lower();
        if (lmin < overall_min) {
            overall_min = lmin;
        }
    }
    return overall_min;
}

std::vector<Range<int>> MediaCodecInfo::AudioCapabilities::getInputChannelCountRanges() const {
    return mInputChannelRanges;
}

// static
std::unique_ptr<MediaCodecInfo::AudioCapabilities> MediaCodecInfo::AudioCapabilities::Create(
        const sp<AMessage> &format, CodecCapabilities &parent) {
    std::unique_ptr<AudioCapabilities> caps(new AudioCapabilities());
    caps->init(format, parent);
    return caps;
}

void MediaCodecInfo::AudioCapabilities::init(const sp<AMessage> &format,
        CodecCapabilities &parent) {
    mParent = std::make_shared<CodecCapabilities>(parent);
    initWithPlatformLimits();
    applyLevelLimits();
    parseFromInfo(format);
}

void MediaCodecInfo::AudioCapabilities::initWithPlatformLimits() {
    mBitrateRange = Range<int>(0, INT_MAX);
    mInputChannelRanges.push_back(Range<int>(1, MAX_INPUT_CHANNEL_COUNT));

    const int minSampleRate = base::GetIntProperty("ro.mediacodec.min_sample_rate", 7350);
    const int maxSampleRate = base::GetIntProperty("ro.mediacodec.max_sample_rate", 192000);
    mSampleRateRanges.push_back(Range<int>(minSampleRate, maxSampleRate));
}

bool MediaCodecInfo::AudioCapabilities::supports(int sampleRate, int inputChannels) {
    // channels and sample rates are checked orthogonally
    return std::any_of(mInputChannelRanges.begin(), mInputChannelRanges.end(),
            [inputChannels](Range<int> a) { return a.contains(inputChannels); })
            && std::any_of(mSampleRateRanges.begin(), mSampleRateRanges.end(),
            [sampleRate](Range<int> a) { return a.contains(sampleRate); });
}

bool MediaCodecInfo::AudioCapabilities::isSampleRateSupported(int sampleRate) {
    return supports(sampleRate, 0);
}

void MediaCodecInfo::AudioCapabilities::limitSampleRates(const std::vector<int> &rates) {
    for (int rate : rates) {
        if (supports(rate, 0 /* channels */)) {
            mSampleRateRanges.push_back(Range<int>(rate, rate));
        }
    }
    createDiscreteSampleRates();
}

void MediaCodecInfo::AudioCapabilities::createDiscreteSampleRates() {
    for (int i = 0; i < mSampleRateRanges.size(); i++) {
        mSampleRates.push_back(mSampleRateRanges[i].lower());
    }
}

void MediaCodecInfo::AudioCapabilities::limitSampleRates(
        std::vector<Range<int>> &rateRanges) {
    sortDistinctRanges(rateRanges);
    mSampleRateRanges = intersectSortedDistinctRanges(mSampleRateRanges, rateRanges);
    // check if all values are discrete
    for (Range<int> range: mSampleRateRanges) {
        if (range.lower() != range.upper()) {
            mSampleRates.clear();
            return;
        }
    }
    createDiscreteSampleRates();
}

void MediaCodecInfo::AudioCapabilities::applyLevelLimits() {
    std::vector<int> sampleRates;
    std::optional<Range<int>> sampleRateRange;
    std::optional<Range<int>> bitRates;
    int maxChannels = MAX_INPUT_CHANNEL_COUNT;

    auto lockParent = mParent.lock();
    if (!lockParent) {
        return;
    }
    std::vector<ProfileLevel> profileLevels = lockParent->getProfileLevels();
    std::string mediaTypeStr = lockParent->getMediaType();
    const char *mediaType = mediaTypeStr.c_str();

    if (strcasecmp(mediaType, MIMETYPE_AUDIO_MPEG) == 0) {
        sampleRates = {
                8000, 11025, 12000,
                16000, 22050, 24000,
                32000, 44100, 48000 };
        bitRates = Range<int>(8000, 320000);
        maxChannels = 2;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_AMR_NB) == 0) {
        sampleRates = { 8000 };
        bitRates = Range<int>(4750, 12200);
        maxChannels = 1;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_AMR_WB) == 0) {
        sampleRates = { 16000 };
        bitRates = Range<int>(6600, 23850);
        maxChannels = 1;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_AAC) == 0) {
        sampleRates = {
                7350, 8000,
                11025, 12000, 16000,
                22050, 24000, 32000,
                44100, 48000, 64000,
                88200, 96000 };
        bitRates = Range<int>(8000, 510000);
        maxChannels = 48;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_VORBIS) == 0) {
        bitRates = Range<int>(32000, 500000);
        sampleRateRange = Range<int>(8000, 192000);
        maxChannels = 255;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_OPUS) == 0) {
        bitRates = Range<int>(6000, 510000);
        sampleRates = { 8000, 12000, 16000, 24000, 48000 };
        maxChannels = 255;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_RAW) == 0) {
        sampleRateRange = Range<int>(1, 192000);
        bitRates = Range<int>(1, 10000000);
        maxChannels = MAX_NUM_CHANNELS;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_FLAC) == 0) {
        sampleRateRange = Range<int>(1, 655350);
        // lossless codec, so bitrate is ignored
        maxChannels = 255;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_G711_ALAW) == 0
            || strcasecmp(mediaType, MIMETYPE_AUDIO_G711_MLAW) == 0) {
        sampleRates = { 8000 };
        bitRates = Range<int>(64000, 64000);
        // platform allows multiple channels for this format
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_MSGSM) == 0) {
        sampleRates = { 8000 };
        bitRates = Range<int>(13000, 13000);
        maxChannels = 1;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_AC3) == 0) {
        maxChannels = 6;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_EAC3) == 0) {
        maxChannels = 16;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_EAC3_JOC) == 0) {
        sampleRates = { 48000 };
        bitRates = Range<int>(32000, 6144000);
        maxChannels = 16;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_AC4) == 0) {
        sampleRates = { 44100, 48000, 96000, 192000 };
        bitRates = Range<int>(16000, 2688000);
        maxChannels = 24;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_DTS) == 0) {
        sampleRates = { 44100, 48000 };
        bitRates = Range<int>(96000, 1524000);
        maxChannels = 6;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_DTS_HD) == 0) {
        for (ProfileLevel profileLevel: profileLevels) {
            switch (profileLevel.mProfile) {
                case DTS_HDProfileLBR:
                    sampleRates = { 22050, 24000, 44100, 48000 };
                    bitRates = Range<int>(32000, 768000);
                    break;
                case DTS_HDProfileHRA:
                case DTS_HDProfileMA:
                    sampleRates = { 44100, 48000, 88200, 96000, 176400, 192000 };
                    bitRates = Range<int>(96000, 24500000);
                    break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile, mediaType);
                    setParentError(ERROR_UNRECOGNIZED);
                    sampleRates = { 44100, 48000, 88200, 96000, 176400, 192000 };
                    bitRates = Range<int>(96000, 24500000);
            }
        }
        maxChannels = 8;
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_DTS_UHD) == 0) {
        for (ProfileLevel profileLevel: profileLevels) {
            switch (profileLevel.mProfile) {
                case DTS_UHDProfileP2:
                    sampleRates = { 48000 };
                    bitRates = Range<int>(96000, 768000);
                    maxChannels = 10;
                    break;
                case DTS_UHDProfileP1:
                    sampleRates = { 44100, 48000, 88200, 96000, 176400, 192000 };
                    bitRates = Range<int>(96000, 24500000);
                    maxChannels = 32;
                    break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile, mediaType);
                    setParentError(ERROR_UNRECOGNIZED);
                    sampleRates = { 44100, 48000, 88200, 96000, 176400, 192000 };
                    bitRates = Range<int>(96000, 24500000);
                    maxChannels = 32;
            }
        }
    } else {
        ALOGW("Unsupported mediaType %s", mediaType);
        setParentError(ERROR_UNSUPPORTED);
    }

    // restrict ranges
    if (!sampleRates.empty()) {
        limitSampleRates(sampleRates);
    } else if (sampleRateRange) {
        std::vector<Range<int>> rateRanges = { sampleRateRange.value() };
        limitSampleRates(rateRanges);
    }

    Range<int> channelRange = Range<int>(1, maxChannels);
    std::vector<Range<int>> inputChannels = { channelRange };
    applyLimits(inputChannels, bitRates);
}

void MediaCodecInfo::AudioCapabilities::applyLimits(
        const std::vector<Range<int>> &inputChannels,
        const std::optional<Range<int>> &bitRates) {
    // clamp & make a local copy
    std::vector<Range<int>> myInputChannels(inputChannels.size());
    for (int i = 0; i < inputChannels.size(); i++) {
        int lower = inputChannels[i].clamp(1);
        int upper = inputChannels[i].clamp(MAX_INPUT_CHANNEL_COUNT);
        myInputChannels[i] = Range<int>(lower, upper);
    }

    // sort, intersect with existing, & save channel list
    sortDistinctRanges(myInputChannels);
    mInputChannelRanges = intersectSortedDistinctRanges(myInputChannels, mInputChannelRanges);

    if (bitRates) {
        mBitrateRange = mBitrateRange.intersect(bitRates.value());
    }
}

void MediaCodecInfo::AudioCapabilities::parseFromInfo(const sp<AMessage> &format) {
    int maxInputChannels = MAX_INPUT_CHANNEL_COUNT;
    std::vector<Range<int>> channels = { Range<int>(1, maxInputChannels) };
    std::optional<Range<int>> bitRates = POSITIVE_INTEGERS;

    AString rateAString;
    if (format->findString("sample-rate-ranges", &rateAString)) {
        std::vector<std::string> rateStrings = base::Split(std::string(rateAString.c_str()), ",");
        std::vector<Range<int>> rateRanges(rateStrings.size());
        for (std::string rateString : rateStrings) {
            std::optional<Range<int>> rateRange = ParseIntRange(rateString);
            if (!rateRange) {
                continue;
            }
            rateRanges.push_back(rateRange.value());
        }
        limitSampleRates(rateRanges);
    }

    // we will prefer channel-ranges over max-channel-count
    AString aStr;
    if (format->findString("channel-ranges", &aStr)) {
        std::vector<std::string> channelStrings = base::Split(std::string(aStr.c_str()), ",");
        std::vector<Range<int>> channelRanges(channelStrings.size());
        for (std::string channelString : channelStrings) {
            std::optional<Range<int>> channelRange = ParseIntRange(channelString);
            if (!channelRange) {
                continue;
            }
            channelRanges.push_back(channelRange.value());
        }
        channels = channelRanges;
    } else if (format->findString("channel-range", &aStr)) {
        std::optional<Range<int>> oneRange = ParseIntRange(std::string(aStr.c_str()));
        if (oneRange) {
            channels = { oneRange.value() };
        }
    } else if (format->findString("max-channel-count", &aStr)) {
        maxInputChannels = std::atoi(aStr.c_str());
        if (maxInputChannels == 0) {
            channels = { Range<int>(0, 0) };
        } else {
            channels = { Range<int>(1, maxInputChannels) };
        }
    } else if (auto lockParent = mParent.lock()) {
        if ((lockParent->mError & ERROR_UNSUPPORTED) != 0) {
            maxInputChannels = 0;
            channels = { Range<int>(0, 0) };
        }
    }

    if (format->findString("bitrate-range", &aStr)) {
        std::optional<Range<int>> parsedBitrate = ParseIntRange(aStr.c_str());
        if (parsedBitrate) {
            bitRates = bitRates.value().intersect(parsedBitrate.value());
        }
    }

    applyLimits(channels, bitRates);
}

void MediaCodecInfo::AudioCapabilities::getDefaultFormat(sp<AMessage> &format) {
    // report settings that have only a single choice
    if (mBitrateRange.lower() == mBitrateRange.upper()) {
        format->setInt32(KEY_BIT_RATE, mBitrateRange.lower());
    }
    if (getMaxInputChannelCount() == 1) {
        // mono-only format
        format->setInt32(KEY_CHANNEL_COUNT, 1);
    }
    if (!mSampleRates.empty() && mSampleRates.size() == 1) {
        format->setInt32(KEY_SAMPLE_RATE, mSampleRates[0]);
    }
}

bool MediaCodecInfo::AudioCapabilities::supportsFormat(const sp<AMessage> &format) {
    int32_t sampleRate;
    format->findInt32(KEY_SAMPLE_RATE, &sampleRate);
    int32_t channels;
    format->findInt32(KEY_CHANNEL_COUNT, &channels);

    if (!supports(sampleRate, channels)) {
        return false;
    }

    if (!CodecCapabilities::supportsBitrate(mBitrateRange, format)) {
        return false;
    }

    // nothing to do for:
    // KEY_CHANNEL_MASK: codecs don't get this
    // KEY_IS_ADTS:      required feature for all AAC decoders
    return true;
}

// VideoCapabilities

Range<int> MediaCodecInfo::VideoCapabilities::getBitrateRange() const {
    return mBitrateRange;
}

Range<int> MediaCodecInfo::VideoCapabilities::getSupportedWidths() const {
    return mWidthRange;
}

Range<int> MediaCodecInfo::VideoCapabilities::getSupportedHeights() const {
    return mHeightRange;
}

int MediaCodecInfo::VideoCapabilities::getWidthAlignment() const {
    return mWidthAlignment;
}

int MediaCodecInfo::VideoCapabilities::getHeightAlignment() const {
    return mHeightAlignment;
}

int MediaCodecInfo::VideoCapabilities::getSmallerDimensionUpperLimit() const {
    return mSmallerDimensionUpperLimit;
}

Range<int> MediaCodecInfo::VideoCapabilities::getSupportedFrameRates() const {
    return mFrameRateRange;
}

Range<int> MediaCodecInfo::VideoCapabilities::getSupportedWidthsFor(int height) const {
    Range<int> range = mWidthRange;
    if (!mHeightRange.contains(height)
            || (height % mHeightAlignment) != 0) {
        ALOGE("unsupported height");
        return Range<int>(0, 0); // ToDo: catch the invalid Range in upper layers
    }
    const int heightInBlocks = divUp(height, mBlockHeight);

    // constrain by block count and by block aspect ratio
    const int minWidthInBlocks = std::max(
            divUp(mBlockCountRange.lower(), heightInBlocks),
            (int)std::ceil(mBlockAspectRatioRange.lower().doubleValue()
                    * heightInBlocks));
    const int maxWidthInBlocks = std::min(
            mBlockCountRange.upper() / heightInBlocks,
            (int)(mBlockAspectRatioRange.upper().doubleValue()
                    * heightInBlocks));
    range = range.intersect(
            (minWidthInBlocks - 1) * mBlockWidth + mWidthAlignment,
            maxWidthInBlocks * mBlockWidth);

    // constrain by smaller dimension limit
    if (height > mSmallerDimensionUpperLimit) {
        range = range.intersect(1, mSmallerDimensionUpperLimit);
    }

    // constrain by aspect ratio
    range = range.intersect(
            (int)std::ceil(mAspectRatioRange.lower().doubleValue()
                    * height),
            (int)(mAspectRatioRange.upper().doubleValue() * height));
    return range;
}

Range<int> MediaCodecInfo::VideoCapabilities::getSupportedHeightsFor(int width) const {
    Range<int> range = mHeightRange;
    if (!mWidthRange.contains(width)
            || (width % mWidthAlignment) != 0) {
        ALOGE("unsupported width");
        return Range<int>(0, 0);  // ToDo: catch the invalid Range in upper layers
    }
    const int widthInBlocks = divUp(width, mBlockWidth);

    // constrain by block count and by block aspect ratio
    const int minHeightInBlocks = std::max(
            divUp(mBlockCountRange.lower(), widthInBlocks),
            (int)std::ceil(widthInBlocks /
                    mBlockAspectRatioRange.upper().doubleValue()));
    const int maxHeightInBlocks = std::min(
            mBlockCountRange.upper() / widthInBlocks,
            (int)(widthInBlocks /
                    mBlockAspectRatioRange.lower().doubleValue()));
    range = range.intersect(
            (minHeightInBlocks - 1) * mBlockHeight + mHeightAlignment,
            maxHeightInBlocks * mBlockHeight);

    // constrain by smaller dimension limit
    if (width > mSmallerDimensionUpperLimit) {
        range = range.intersect(1, mSmallerDimensionUpperLimit);
    }

    // constrain by aspect ratio
    range = range.intersect(
            (int)std::ceil(width /
                    mAspectRatioRange.upper().doubleValue()),
            (int)(width / mAspectRatioRange.lower().doubleValue()));
    return range;
}

Range<double> MediaCodecInfo::VideoCapabilities::getSupportedFrameRatesFor(
        int width, int height) const {
    // Range<int> range = mHeightRange;
    CHECK(supports(width, height, 0));
    const int blockCount =
            divUp(width, mBlockWidth) * divUp(height, mBlockHeight);

    return Range(
            std::max(mBlocksPerSecondRange.lower() / (double) blockCount,
                (double) mFrameRateRange.lower()),
            std::min(mBlocksPerSecondRange.upper() / (double) blockCount,
                (double) mFrameRateRange.upper()));
}

int MediaCodecInfo::VideoCapabilities::getBlockCount(int width, int height) const {
    return divUp(width, mBlockWidth) * divUp(height, mBlockHeight);
}

std::optional<VideoSize> MediaCodecInfo::VideoCapabilities::findClosestSize(
        int width, int height) const {
    int targetBlockCount = getBlockCount(width, height);
    int minDiff = INT_MAX;
    for (const auto &[size, range] : mMeasuredFrameRates) {
        int diff = std::abs(targetBlockCount -
                getBlockCount(size.getWidth(), size.getHeight()));
        if (diff < minDiff) {
            minDiff = diff;
            return std::make_optional(size);
        }
    }
    return std::nullopt;
}

std::optional<Range<double>> MediaCodecInfo::VideoCapabilities::estimateFrameRatesFor(
        int width, int height) const {
    std::optional<VideoSize> size = findClosestSize(width, height);
    if (!size) {
        return std::nullopt;
    }
    auto rangeItr = mMeasuredFrameRates.find(size.value());
    if (rangeItr == mMeasuredFrameRates.end()) {
        return std::nullopt;
    }
    Range<long> range = rangeItr->second;
    double ratio = getBlockCount(size.value().getWidth(), size.value().getHeight())
            / (double)std::max(getBlockCount(width, height), 1);
    return std::make_optional(Range(range.lower() * ratio, range.upper() * ratio));
}

std::optional<Range<double>> MediaCodecInfo::VideoCapabilities::getAchievableFrameRatesFor(
        int width, int height) const {
    CHECK(supports(width, height, 0));

    if (mMeasuredFrameRates.empty()) {
        ALOGW("Codec did not publish any measurement data.");
        return std::nullopt;
    }

    return estimateFrameRatesFor(width, height);
}

// VideoCapabilities::PerformancePoint

int MediaCodecInfo::VideoCapabilities::PerformancePoint::getMaxMacroBlocks() const {
    return saturateLongToInt(mWidth * (long)mHeight);
}

int MediaCodecInfo::VideoCapabilities::PerformancePoint::getMaxFrameRate() const {
    return mMaxFrameRate;
}

long MediaCodecInfo::VideoCapabilities::PerformancePoint::getMaxMacroBlockRate() const {
    return mMaxMacroBlockRate;
}

std::string MediaCodecInfo::VideoCapabilities::PerformancePoint::toString() const {
    int blockWidth = 16 * mBlockSize.getWidth();
    int blockHeight = 16 * mBlockSize.getHeight();
    int origRate = (int)divUpLong(mMaxMacroBlockRate, getMaxMacroBlocks());
    std::string info = std::to_string(mWidth * 16) + "x" + std::to_string(mHeight * 16)
            + "@" + std::to_string(origRate);
    if (origRate < mMaxFrameRate) {
        info += ", max " + std::to_string(mMaxFrameRate) + "fps";
    }
    if (blockWidth > 16 || blockHeight > 16) {
        info += ", " + std::to_string(blockWidth) + "x"
                + std::to_string(blockHeight) + " blocks";
    }
    return "PerformancePoint(" + info + ")";
}

int MediaCodecInfo::VideoCapabilities::PerformancePoint::hashCode() const {
    // only max frame rate must equal between performance points that equal to one
    // another
    return mMaxFrameRate;
}

MediaCodecInfo::VideoCapabilities::PerformancePoint::PerformancePoint(
        int width, int height, int frameRate, int maxFrameRate, VideoSize blockSize) :
        mBlockSize(VideoSize(divUp(blockSize.getWidth(), 16),divUp(blockSize.getHeight(), 16))) {

    // Use  checkPowerOfTwo2 as we do not want width and height to be 0;
    checkPowerOfTwo2(blockSize.getWidth());
    checkPowerOfTwo2(blockSize.getHeight());

    // mBlockSize = VideoSize(divUp(blockSize.getWidth(), 16), divUp(blockSize.getHeight(), 16));
    // these are guaranteed not to overflow as we decimate by 16
    mWidth = divUp(std::max(1, width),
            std::max(blockSize.getWidth(), 16)) * mBlockSize.getWidth();
    mHeight = divUp(std::max(1, height),
            std::max(blockSize.getHeight(), 16)) * mBlockSize.getHeight();
    mMaxFrameRate = std::max(1, std::max(frameRate, maxFrameRate));
    mMaxMacroBlockRate = std::max(1, frameRate) * getMaxMacroBlocks();
}

MediaCodecInfo::VideoCapabilities::PerformancePoint::PerformancePoint(
        const PerformancePoint &pp, VideoSize newBlockSize) {
    PerformancePoint(
            pp.mWidth * 16, pp.mHeight * 16,
            // guaranteed not to overflow as these were multiplied at construction
            (int)divUpLong(pp.mMaxMacroBlockRate, pp.getMaxMacroBlocks()),
            pp.mMaxFrameRate,
            VideoSize(std::max(newBlockSize.getWidth(), pp.mBlockSize.getWidth() * 16),
                 std::max(newBlockSize.getHeight(), pp.mBlockSize.getHeight() * 16))
    );
}

MediaCodecInfo::VideoCapabilities::PerformancePoint::PerformancePoint(
        int width, int height, int frameRate) {
    PerformancePoint(width, height, frameRate, frameRate /* maxFrameRate */, VideoSize(16, 16));
}

int MediaCodecInfo::VideoCapabilities::PerformancePoint::saturateLongToInt(long value) const {
    if (value < INT_MIN) {
        return INT_MIN;
    } else if (value > INT_MAX) {
        return INT_MAX;
    } else {
        return (int)value;
    }
}

/* This method may overflow */
int MediaCodecInfo::VideoCapabilities::PerformancePoint::align(int value, int alignment) const {
    return divUp(value, alignment) * alignment;
}

void MediaCodecInfo::VideoCapabilities::PerformancePoint::checkPowerOfTwo2(int value) {
    CHECK(value == 0 || (value & (value - 1)) == 0);
}

bool MediaCodecInfo::VideoCapabilities::PerformancePoint::covers(const sp<AMessage> &format) const {
    int32_t width, height;
    format->findInt32(KEY_WIDTH, &width);
    format->findInt32(KEY_HEIGHT, &height);
    double frameRate;
    format->findDouble(KEY_FRAME_RATE, &frameRate);
    PerformancePoint other = PerformancePoint(
            width, height,
            // safely convert ceil(double) to int through float cast and std::round
            std::round((float)(std::ceil(frameRate)))
    );
    return covers(other);
}

bool MediaCodecInfo::VideoCapabilities::PerformancePoint::covers(
        const PerformancePoint &other) const {
    // convert performance points to common block size
    VideoSize commonSize = getCommonBlockSize(other);
    PerformancePoint aligned = PerformancePoint(*this, commonSize);
    PerformancePoint otherAligned = PerformancePoint(other, commonSize);

    return (aligned.getMaxMacroBlocks() >= otherAligned.getMaxMacroBlocks()
            && aligned.mMaxFrameRate >= otherAligned.mMaxFrameRate
            && aligned.mMaxMacroBlockRate >= otherAligned.mMaxMacroBlockRate);
}

VideoSize MediaCodecInfo::VideoCapabilities::PerformancePoint::getCommonBlockSize(
        const PerformancePoint &other) const {
    return VideoSize(
            std::max(mBlockSize.getWidth(), other.mBlockSize.getWidth()) * 16,
            std::max(mBlockSize.getHeight(), other.mBlockSize.getHeight()) * 16);
}

bool MediaCodecInfo::VideoCapabilities::PerformancePoint::equals(
        const PerformancePoint &other) const {
    // convert performance points to common block size
    VideoSize commonSize = getCommonBlockSize(other);
    PerformancePoint aligned = PerformancePoint(*this, commonSize);
    PerformancePoint otherAligned = PerformancePoint(other, commonSize);

    return (aligned.getMaxMacroBlocks() == otherAligned.getMaxMacroBlocks()
            && aligned.mMaxFrameRate == otherAligned.mMaxFrameRate
            && aligned.mMaxMacroBlockRate == otherAligned.mMaxMacroBlockRate);
}

// VideoCapabilities

std::vector<MediaCodecInfo::VideoCapabilities::PerformancePoint>
        MediaCodecInfo::VideoCapabilities::getSupportedPerformancePoints() const {
    return mPerformancePoints;
}

bool MediaCodecInfo::VideoCapabilities::areSizeAndRateSupported(
        int width, int height, double frameRate) const {
    return supports(width, height, frameRate);
}

bool MediaCodecInfo::VideoCapabilities::isSizeSupported(int width, int height) const {
    return supports(width, height, 0);  // Replace null with 0
}

bool MediaCodecInfo::VideoCapabilities::supports(int width, int height, double rate) const {
    bool ok = true;

    if (ok && width != 0) {  // replace null with 0
        ok = mWidthRange.contains(width)
                && (width % mWidthAlignment == 0);
    }
    if (ok && height != 0) {  // replace null with 0
        ok = mHeightRange.contains(height)
                && (height % mHeightAlignment == 0);
    }
    if (ok && rate != 0) {  // replace null with 0
        ok = mFrameRateRange.contains(IntRangeFor(rate));
    }
    if (ok && height != 0 && width != 0) {  // replace null with 0
        ok = std::min(height, width) <= mSmallerDimensionUpperLimit;

        const int widthInBlocks = divUp(width, mBlockWidth);
        const int heightInBlocks = divUp(height, mBlockHeight);
        const int blockCount = widthInBlocks * heightInBlocks;
        ok = ok && mBlockCountRange.contains(blockCount)
                && mBlockAspectRatioRange.contains(
                        Rational(widthInBlocks, heightInBlocks))
                && mAspectRatioRange.contains(Rational(width, height));
        if (ok && rate != 0) {  // replace null with 0
            double blocksPerSec = blockCount * rate;
            ok = mBlocksPerSecondRange.contains(
                    LongRangeFor(blocksPerSec));
        }
    }
    return ok;
}

bool MediaCodecInfo::VideoCapabilities::supportsFormat(const sp<AMessage> &format) const {
    int32_t width, height, rate;
    format->findInt32(KEY_WIDTH, &width);
    format->findInt32(KEY_HEIGHT, &height);
    format->findInt32(KEY_FRAME_RATE, &rate);

    if (!supports(width, height, rate)) {
        return false;
    }

    if (!CodecCapabilities::supportsBitrate(mBitrateRange, format)) {
        return false;
    }

    // we ignore color-format for now as it is not reliably reported by codec
    return true;
}

// static
std::unique_ptr<MediaCodecInfo::VideoCapabilities> MediaCodecInfo::VideoCapabilities::Create(
        const sp<AMessage> &format, CodecCapabilities &parent) {
    std::unique_ptr<VideoCapabilities> caps(new VideoCapabilities());
    caps->init(format, parent);
    return caps;
}

void MediaCodecInfo::VideoCapabilities::init(
        const sp<AMessage> &format, CodecCapabilities &parent) {
    mParent = std::make_shared<CodecCapabilities>(parent);
    initWithPlatformLimits();
    applyLevelLimits();
    parseFromInfo(format);
    updateLimits();
}

VideoSize MediaCodecInfo::VideoCapabilities::getBlockSize() const {
    return VideoSize(mBlockWidth, mBlockHeight);
}

Range<int> MediaCodecInfo::VideoCapabilities::getBlockCountRange() const {
    return mBlockCountRange;
}

Range<long> MediaCodecInfo::VideoCapabilities::getBlocksPerSecondRange() const {
    return mBlocksPerSecondRange;
}

Range<Rational> MediaCodecInfo::VideoCapabilities::getAspectRatioRange(bool blocks) const {
    return blocks ? mBlockAspectRatioRange : mAspectRatioRange;
}

// still in progress
void MediaCodecInfo::VideoCapabilities::initWithPlatformLimits() {
    mBitrateRange = BITRATE_RANGE;

    mWidthRange  = GetSizeRange();
    mHeightRange = GetSizeRange();
    mFrameRateRange = FRAME_RATE_RANGE;

    mHorizontalBlockRange = GetSizeRange();
    mVerticalBlockRange   = GetSizeRange();

    // full positive ranges are supported as these get calculated
    mBlockCountRange      = POSITIVE_INTEGERS;
    mBlocksPerSecondRange = POSITIVE_LONGS;

    mBlockAspectRatioRange = POSITIVE_RATIONALS;
    mAspectRatioRange      = POSITIVE_RATIONALS;

    // YUV 4:2:0 requires 2:2 alignment
    mWidthAlignment = 2;
    mHeightAlignment = 2;
    mBlockWidth = 2;
    mBlockHeight = 2;
    mSmallerDimensionUpperLimit = GetSizeRange().upper();
}

std::vector<MediaCodecInfo::VideoCapabilities::PerformancePoint>
        MediaCodecInfo::VideoCapabilities::getPerformancePoints(const sp<AMessage> &format) const {
    std::vector<PerformancePoint> ret;
    const std::string prefix = "performance-point-";
    AMessage::Type type;
    for (int i = 0; i < format->countEntries(); i++) {
        const char *name = format->getEntryNameAt(i, &type);
        AString rangeStr;
        if (!format->findString(name, &rangeStr)) {
            continue;
        }

        const std::string key = std::string(name);
        // looking for: performance-point-WIDTHxHEIGHT-range
        if (key.compare(0, prefix.size(), prefix) == 0) {
            continue;
        }
        std::string subKey = key.substr(prefix.size());
        if (subKey.compare("none") && ret.size() == 0) {
            // This means that component knowingly did not publish performance points.
            // This is different from when the component forgot to publish performance
            // points.
            return ret;
        }
        std::vector<std::string> temp = base::Split(key, "-");
        if (temp.size() != 4) {
            continue;
        }

        std::string sizeStr = temp.at(2);
        std::optional<VideoSize> size = VideoSize::ParseSize(sizeStr);
        if (!size || size.value().getWidth() * size.value().getHeight() <= 0) {
            continue;
        }

        std::optional<Range<long>> range = ParseLongRange(std::string(rangeStr.c_str()));
        if (!range || range.value().lower() < 0 || range.value().upper() < 0) {
            continue;
        }
        PerformancePoint given = PerformancePoint(
                size.value().getWidth(), size.value().getHeight(), (int)range.value().lower(),
                (int)range.value().upper(), VideoSize(mBlockWidth, mBlockHeight));
        PerformancePoint rotated = PerformancePoint(
                size.value().getHeight(), size.value().getWidth(), (int)range.value().lower(),
                (int)range.value().upper(), VideoSize(mBlockWidth, mBlockHeight));
        ret.push_back(given);
        if (!given.covers(rotated)) {
            ret.push_back(rotated);
        }
    }

    // check if the component specified no performance point indication
    if (ret.size() == 0) {
        return ret;
    }

    // sort reversed by area first, then by frame rate
    std::sort(ret.begin(), ret.end(), [](const PerformancePoint &a, const PerformancePoint &b) {
        return -((a.getMaxMacroBlocks() != b.getMaxMacroBlocks()) ?
                        (a.getMaxMacroBlocks() < b.getMaxMacroBlocks() ? -1 : 1) :
                (a.getMaxMacroBlockRate() != b.getMaxMacroBlockRate()) ?
                        (a.getMaxMacroBlockRate() < b.getMaxMacroBlockRate() ? -1 : 1) :
                (a.getMaxFrameRate() != b.getMaxFrameRate()) ?
                        (a.getMaxFrameRate() < b.getMaxFrameRate() ? -1 : 1) : 0);
    });

    return ret;
}

std::map<VideoSize, Range<long>, VideoSizeCompare> MediaCodecInfo::VideoCapabilities
        ::getMeasuredFrameRates(const sp<AMessage> &format) const {
    std::map<VideoSize, Range<long>, VideoSizeCompare> ret;
    const std::string prefix = "measured-frame-rate-";
    AMessage::Type type;
    for (int i = 0; i < format->countEntries(); i++) {
        const char *name = format->getEntryNameAt(i, &type);
        AString rangeStr;
        if (!format->findString(name, &rangeStr)) {
            continue;
        }

        const std::string key = std::string(name);
        // looking for: measured-frame-rate-WIDTHxHEIGHT-range
        if (key.compare(0, prefix.size(), prefix) == 0) {
            continue;
        }
        // std::string subKey = key.substr(prefix.size());
        std::vector<std::string> temp = base::Split(key, "-");
        if (temp.size() != 5) {
            continue;
        }

        std::string sizeStr = temp.at(3);
        std::optional<VideoSize> size = VideoSize::ParseSize(sizeStr);
        if (!size || size.value().getWidth() * size.value().getHeight() <= 0) {
            continue;
        }

        std::optional<Range<long>> range = ParseLongRange(std::string(rangeStr.c_str()));
        if (!range || range.value().lower() < 0 || range.value().upper() < 0) {
            continue;
        }

        ret.emplace(size.value(), range.value());
    }
    return ret;
}

// static
std::optional<std::pair<Range<int>, Range<int>>> MediaCodecInfo::VideoCapabilities
        ::ParseWidthHeightRanges(const std::string &str) {
    std::optional<std::pair<VideoSize, VideoSize>> range = ParseSizeRange(str);
    if (!range) {
        ALOGW("could not parse size range: %s", str.c_str());
        return std::nullopt;
    }

    return std::make_optional(std::pair(
            Range(range.value().first.getWidth(), range.value().second.getWidth()),
            Range(range.value().first.getHeight(), range.value().second.getHeight())));
}

// static
int MediaCodecInfo::VideoCapabilities::equivalentVP9Level(const sp<AMessage> &format) {
    int blockSizeWidth = 8;
    int blockSizeHeight = 8;
    // VideoSize *blockSizePtr = &VideoSize(8, 8);
    AString blockSizeStr;
    if (format->findString("block-size", &blockSizeStr)) {
        std::optional<VideoSize> parsedBlockSize
                = VideoSize::ParseSize(std::string(blockSizeStr.c_str()));
        if (parsedBlockSize) {
            // blockSize = parsedBlockSize.value();
            blockSizeWidth = parsedBlockSize.value().getWidth();
            blockSizeHeight = parsedBlockSize.value().getHeight();
        }
    }
    int BS = blockSizeWidth * blockSizeHeight;

    int FS = 0;
    AString blockCountRangeStr;
    if (format->findString("block-count-range", &blockCountRangeStr)) {
        std::optional<Range<int>> counts = ParseIntRange(std::string(blockCountRangeStr.c_str()));
        if (counts) {
            FS = BS * counts.value().upper();
        }
    }

    long long SR = 0;
    AString blockRatesStr;
    if (format->findString("blocks-per-second-range", &blockRatesStr)) {
        std::optional<Range<long>> blockRates = ParseLongRange(std::string(blockRatesStr.c_str()));
        if (blockRates) {
            SR = BS * blockRates.value().upper();
        }
    }

    int D = 0;
    AString dimensionRangesStr;
    if (format->findString("size-range", &dimensionRangesStr)) {
        std::optional<std::pair<Range<int>, Range<int>>> dimensionRanges =
                ParseWidthHeightRanges(std::string(dimensionRangesStr.c_str()));
        if (dimensionRanges) {
            D = std::max(dimensionRanges.value().first.upper(),
                    dimensionRanges.value().second.upper());
        }
    }

    int BR = 0;
    AString bitrateRangeStr;
    if (format->findString("bitrate-range", &bitrateRangeStr)) {
        std::optional<Range<int>> bitRates = ParseIntRange(std::string(bitrateRangeStr.c_str()));
        if (bitRates) {
            BR = divUp(bitRates.value().upper(), 1000);
        }
    }

    if (SR <=      829440 && FS <=    36864 && BR <=    200 && D <=   512)
        return VP9Level1;
    if (SR <=     2764800 && FS <=    73728 && BR <=    800 && D <=   768)
        return VP9Level11;
    if (SR <=     4608000 && FS <=   122880 && BR <=   1800 && D <=   960)
        return VP9Level2;
    if (SR <=     9216000 && FS <=   245760 && BR <=   3600 && D <=  1344)
        return VP9Level21;
    if (SR <=    20736000 && FS <=   552960 && BR <=   7200 && D <=  2048)
        return VP9Level3;
    if (SR <=    36864000 && FS <=   983040 && BR <=  12000 && D <=  2752)
        return VP9Level31;
    if (SR <=    83558400 && FS <=  2228224 && BR <=  18000 && D <=  4160)
        return VP9Level4;
    if (SR <=   160432128 && FS <=  2228224 && BR <=  30000 && D <=  4160)
        return VP9Level41;
    if (SR <=   311951360 && FS <=  8912896 && BR <=  60000 && D <=  8384)
        return VP9Level5;
    if (SR <=   588251136 && FS <=  8912896 && BR <= 120000 && D <=  8384)
        return VP9Level51;
    if (SR <=  1176502272 && FS <=  8912896 && BR <= 180000 && D <=  8384)
        return VP9Level52;
    if (SR <=  1176502272 && FS <= 35651584 && BR <= 180000 && D <= 16832)
        return VP9Level6;
    if (SR <= 2353004544L && FS <= 35651584 && BR <= 240000 && D <= 16832)
        return VP9Level61;
    if (SR <= 4706009088L && FS <= 35651584 && BR <= 480000 && D <= 16832)
        return VP9Level62;
    // returning largest level
    return VP9Level62;
}

void MediaCodecInfo::VideoCapabilities::parseFromInfo(const sp<AMessage> &format) {
    VideoSize blockSize = VideoSize(mBlockWidth, mBlockHeight);
    VideoSize alignment = VideoSize(mWidthAlignment, mHeightAlignment);
    std::optional<Range<int>> counts, widths, heights;
    std::optional<Range<int>> frameRates, bitRates;
    std::optional<Range<long>> blockRates;
    std::optional<Range<Rational>> ratios, blockRatios;

    AString blockSizeStr;
    if (format->findString("block-size", &blockSizeStr)) {
        std::optional<VideoSize> parsedBlockSize
                = VideoSize::ParseSize(std::string(blockSizeStr.c_str()));
        blockSize = parsedBlockSize.value_or(blockSize);
    }
    AString alignmentStr;
    if (format->findString("alignment", &alignmentStr)) {
        std::optional<VideoSize> parsedAlignment
            = VideoSize::ParseSize(std::string(alignmentStr.c_str()));
        alignment = parsedAlignment.value_or(alignment);
    }
    AString blockCountRangeStr;
    if (format->findString("block-count-range", &blockCountRangeStr)) {
        std::optional<Range<int>> parsedBlockCountRange =
                ParseIntRange(std::string(blockCountRangeStr.c_str()));
        if (parsedBlockCountRange) {
            counts = parsedBlockCountRange.value();
        }
    }
    AString blockRatesStr;
    if (format->findString("blocks-per-second-range", &blockRatesStr)) {
        blockRates = ParseLongRange(std::string(blockRatesStr.c_str()));
    }
    mMeasuredFrameRates = getMeasuredFrameRates(format);
    mPerformancePoints = getPerformancePoints(format);
    AString sizeRangesStr;
    if (format->findString("size-range", &sizeRangesStr)) {
        std::optional<std::pair<Range<int>, Range<int>>> sizeRanges =
            ParseWidthHeightRanges(std::string(sizeRangesStr.c_str()));
        if (sizeRanges) {
            widths = sizeRanges.value().first;
            heights = sizeRanges.value().second;
        }
    }
    // for now this just means using the smaller max size as 2nd
    // upper limit.
    // for now we are keeping the profile specific "width/height
    // in macroblocks" limits.
    if (format->contains("feature-can-swap-width-height")) {
        if (widths && heights) {
            mSmallerDimensionUpperLimit =
                std::min(widths.value().upper(), heights.value().upper());
            widths = heights = widths.value().extend(heights.value());
        } else {
            ALOGW("feature can-swap-width-height is best used with size-range");
            mSmallerDimensionUpperLimit =
                std::min(mWidthRange.upper(), mHeightRange.upper());
            mWidthRange = mHeightRange = mWidthRange.extend(mHeightRange);
        }
    }

    AString ratioStr;
    if (format->findString("block-aspect-ratio-range", &ratioStr)) {
        ratios = ParseRationalRange(std::string(ratioStr.c_str()));
    }
    AString blockRatiosStr;
    if (format->findString("pixel-aspect-ratio-range", &blockRatiosStr)) {
        blockRatios = ParseRationalRange(std::string(blockRatiosStr.c_str()));
    }
    AString frameRatesStr;
    if (format->findString("frame-rate-range", &frameRatesStr)) {
        frameRates = ParseIntRange(std::string(frameRatesStr.c_str()));
        if (frameRates) {
            frameRates = frameRates.value().intersect(FRAME_RATE_RANGE);
            if (frameRates.value().empty()) {
                ALOGW("frame rate range is out of limits");
                frameRates = std::nullopt;
            }
        }
    }
    AString bitRatesStr;
    if (format->findString("bitrate-range", &bitRatesStr)) {
        bitRates = ParseIntRange(std::string(bitRatesStr.c_str()));
        if (bitRates) {
            bitRates = bitRates.value().intersect(BITRATE_RANGE);
            if (bitRates.value().empty()) {
                ALOGW("bitrate range is out of limits");
                bitRates = std::nullopt;
            }
        }
    }

    CheckPowerOfTwo(blockSize.getWidth());
    CheckPowerOfTwo(blockSize.getHeight());
    CheckPowerOfTwo(alignment.getWidth());
    CheckPowerOfTwo(alignment.getHeight());

    // update block-size and alignment
    applyMacroBlockLimits(
            INT_MAX, INT_MAX, INT_MAX, LONG_MAX,
            blockSize.getWidth(), blockSize.getHeight(),
            alignment.getWidth(), alignment.getHeight());

    auto lockParent = mParent.lock();
    if (!lockParent) {
        return;
    }
    if ((lockParent->mError & ERROR_UNSUPPORTED) != 0 || mAllowMbOverride) {
        // codec supports profiles that we don't know.
        // Use supplied values clipped to platform limits
        if (widths) {
            mWidthRange = GetSizeRange().intersect(widths.value());
        }
        if (heights) {
            mHeightRange = GetSizeRange().intersect(heights.value());
        }
        if (counts) {
            mBlockCountRange = POSITIVE_INTEGERS.intersect(
                    FactorRange(counts.value(), mBlockWidth * mBlockHeight
                            / blockSize.getWidth() / blockSize.getHeight()));
        }
        if (blockRates) {
            mBlocksPerSecondRange = POSITIVE_LONGS.intersect(
                    FactorRange(blockRates.value(), mBlockWidth * mBlockHeight
                            / blockSize.getWidth() / blockSize.getHeight()));
        }
        if (blockRatios) {
            mBlockAspectRatioRange = POSITIVE_RATIONALS.intersect(
                    ScaleRange(blockRatios.value(),
                            mBlockHeight / blockSize.getHeight(),
                            mBlockWidth / blockSize.getWidth()));
        }
        if (ratios) {
            mAspectRatioRange = POSITIVE_RATIONALS.intersect(ratios.value());
        }
        if (frameRates) {
            mFrameRateRange = FRAME_RATE_RANGE.intersect(frameRates.value());
        }
        if (bitRates) {
            // only allow bitrate override if unsupported profiles were encountered
            if ((lockParent->mError & ERROR_UNSUPPORTED) != 0) {
                mBitrateRange = BITRATE_RANGE.intersect(bitRates.value());
            } else {
                mBitrateRange = mBitrateRange.intersect(bitRates.value());
            }
        }
    } else {
        // no unsupported profile/levels, so restrict values to known limits
        if (widths) {
            mWidthRange = mWidthRange.intersect(widths.value());
        }
        if (heights) {
            mHeightRange = mHeightRange.intersect(heights.value());
        }
        if (counts) {
            mBlockCountRange = mBlockCountRange.intersect(
                    FactorRange(counts.value(), mBlockWidth * mBlockHeight
                            / blockSize.getWidth() / blockSize.getHeight()));
        }
        if (blockRates) {
            mBlocksPerSecondRange = mBlocksPerSecondRange.intersect(
                    FactorRange(blockRates.value(), mBlockWidth * mBlockHeight
                            / blockSize.getWidth() / blockSize.getHeight()));
        }
        if (blockRatios) {
            mBlockAspectRatioRange = mBlockAspectRatioRange.intersect(
                    ScaleRange(blockRatios.value(),
                            mBlockHeight / blockSize.getHeight(),
                            mBlockWidth / blockSize.getWidth()));
        }
        if (ratios) {
            mAspectRatioRange = mAspectRatioRange.intersect(ratios.value());
        }
        if (frameRates) {
            mFrameRateRange = mFrameRateRange.intersect(frameRates.value());
        }
        if (bitRates) {
            mBitrateRange = mBitrateRange.intersect(bitRates.value());
        }
    }
    updateLimits();
}

void MediaCodecInfo::VideoCapabilities::applyBlockLimits(
        int blockWidth, int blockHeight,
        Range<int> counts, Range<long> rates, Range<Rational> ratios) {
    CheckPowerOfTwo(blockWidth);
    CheckPowerOfTwo(blockHeight);

    const int newBlockWidth = std::max(blockWidth, mBlockWidth);
    const int newBlockHeight = std::max(blockHeight, mBlockHeight);

    // factor will always be a power-of-2
    int factor =
        newBlockWidth * newBlockHeight / mBlockWidth / mBlockHeight;
    if (factor != 1) {
        mBlockCountRange = FactorRange(mBlockCountRange, factor);
        mBlocksPerSecondRange = FactorRange(
                mBlocksPerSecondRange, factor);
        mBlockAspectRatioRange = ScaleRange(
                mBlockAspectRatioRange,
                newBlockHeight / mBlockHeight,
                newBlockWidth / mBlockWidth);
        mHorizontalBlockRange = FactorRange(
                mHorizontalBlockRange, newBlockWidth / mBlockWidth);
        mVerticalBlockRange = FactorRange(
                mVerticalBlockRange, newBlockHeight / mBlockHeight);
    }
    factor = newBlockWidth * newBlockHeight / blockWidth / blockHeight;
    if (factor != 1) {
        counts = FactorRange(counts, factor);
        rates = FactorRange(rates, factor);
        ratios = ScaleRange(
                ratios, newBlockHeight / blockHeight,
                newBlockWidth / blockWidth);
    }
    mBlockCountRange = mBlockCountRange.intersect(counts);
    mBlocksPerSecondRange = mBlocksPerSecondRange.intersect(rates);
    mBlockAspectRatioRange = mBlockAspectRatioRange.intersect(ratios);
    mBlockWidth = newBlockWidth;
    mBlockHeight = newBlockHeight;
}

void MediaCodecInfo::VideoCapabilities::applyAlignment(int widthAlignment, int heightAlignment) {
    CheckPowerOfTwo(widthAlignment);
    CheckPowerOfTwo(heightAlignment);

    if (widthAlignment > mBlockWidth || heightAlignment > mBlockHeight) {
        // maintain assumption that 0 < alignment <= block-size
        applyBlockLimits(
                std::max(widthAlignment, mBlockWidth),
                std::max(heightAlignment, mBlockHeight),
                POSITIVE_INTEGERS, POSITIVE_LONGS, POSITIVE_RATIONALS);
    }

    mWidthAlignment = std::max(widthAlignment, mWidthAlignment);
    mHeightAlignment = std::max(heightAlignment, mHeightAlignment);

    mWidthRange = AlignRange(mWidthRange, mWidthAlignment);
    mHeightRange = AlignRange(mHeightRange, mHeightAlignment);
}

void MediaCodecInfo::VideoCapabilities::updateLimits() {
    // pixels -> blocks <- counts
    mHorizontalBlockRange = mHorizontalBlockRange.intersect(
            FactorRange(mWidthRange, mBlockWidth));
    mHorizontalBlockRange = mHorizontalBlockRange.intersect(
            Range(  mBlockCountRange.lower() / mVerticalBlockRange.upper(),
                    mBlockCountRange.upper() / mVerticalBlockRange.lower()));
    mVerticalBlockRange = mVerticalBlockRange.intersect(
            FactorRange(mHeightRange, mBlockHeight));
    mVerticalBlockRange = mVerticalBlockRange.intersect(
            Range(  mBlockCountRange.lower() / mHorizontalBlockRange.upper(),
                    mBlockCountRange.upper() / mHorizontalBlockRange.lower()));
    mBlockCountRange = mBlockCountRange.intersect(
            Range(  mHorizontalBlockRange.lower()
                            * mVerticalBlockRange.lower(),
                    mHorizontalBlockRange.upper()
                            * mVerticalBlockRange.upper()));
    mBlockAspectRatioRange = mBlockAspectRatioRange.intersect(
            Rational(mHorizontalBlockRange.lower(), mVerticalBlockRange.upper()),
            Rational(mHorizontalBlockRange.upper(), mVerticalBlockRange.lower()));

    // blocks -> pixels
    mWidthRange = mWidthRange.intersect(
            (mHorizontalBlockRange.lower() - 1) * mBlockWidth + mWidthAlignment,
            mHorizontalBlockRange.upper() * mBlockWidth);
    mHeightRange = mHeightRange.intersect(
            (mVerticalBlockRange.lower() - 1) * mBlockHeight + mHeightAlignment,
            mVerticalBlockRange.upper() * mBlockHeight);
    mAspectRatioRange = mAspectRatioRange.intersect(
            Rational(mWidthRange.lower(), mHeightRange.upper()),
            Rational(mWidthRange.upper(), mHeightRange.lower()));

    mSmallerDimensionUpperLimit = std::min(
            mSmallerDimensionUpperLimit,
            std::min(mWidthRange.upper(), mHeightRange.upper()));

    // blocks -> rate
    mBlocksPerSecondRange = mBlocksPerSecondRange.intersect(
            mBlockCountRange.lower() * (long)mFrameRateRange.lower(),
            mBlockCountRange.upper() * (long)mFrameRateRange.upper());
    mFrameRateRange = mFrameRateRange.intersect(
            (int)(mBlocksPerSecondRange.lower()
                    / mBlockCountRange.upper()),
            (int)(mBlocksPerSecondRange.upper()
                    / (double)mBlockCountRange.lower()));
}

void MediaCodecInfo::VideoCapabilities::applyMacroBlockLimits(
        int maxHorizontalBlocks, int maxVerticalBlocks,
        int maxBlocks, long maxBlocksPerSecond,
        int blockWidth, int blockHeight,
        int widthAlignment, int heightAlignment) {
    applyMacroBlockLimits(
            1 /* minHorizontalBlocks */, 1 /* minVerticalBlocks */,
            maxHorizontalBlocks, maxVerticalBlocks,
            maxBlocks, maxBlocksPerSecond,
            blockWidth, blockHeight, widthAlignment, heightAlignment);
}

void MediaCodecInfo::VideoCapabilities::applyMacroBlockLimits(
        int minHorizontalBlocks, int minVerticalBlocks,
        int maxHorizontalBlocks, int maxVerticalBlocks,
        int maxBlocks, long maxBlocksPerSecond,
        int blockWidth, int blockHeight,
        int widthAlignment, int heightAlignment) {
    applyAlignment(widthAlignment, heightAlignment);
    applyBlockLimits(
            blockWidth, blockHeight, Range(1, maxBlocks),
            Range(1L, maxBlocksPerSecond),
            Range(Rational(1, maxVerticalBlocks), Rational(maxHorizontalBlocks, 1)));
    mHorizontalBlockRange =
            mHorizontalBlockRange.intersect(
                    divUp(minHorizontalBlocks, (mBlockWidth / blockWidth)),
                    maxHorizontalBlocks / (mBlockWidth / blockWidth));
    mVerticalBlockRange =
            mVerticalBlockRange.intersect(
                    divUp(minVerticalBlocks, (mBlockHeight / blockHeight)),
                    maxVerticalBlocks / (mBlockHeight / blockHeight));
}

void MediaCodecInfo::VideoCapabilities::applyLevelLimits() {
    long maxBlocksPerSecond = 0;
    int maxBlocks = 0;
    int maxBps = 0;
    int maxDPBBlocks = 0;

    int errors = ERROR_UNSUPPORTED;
    auto lockParent = mParent.lock();
    if (!lockParent) {
        return;
    }
    std::vector<ProfileLevel> profileLevels = lockParent->getProfileLevels();
    std::string mediaTypeStr = lockParent->getMediaType();
    const char *mediaType = mediaTypeStr.c_str();

    if (strcasecmp(mediaType, MIMETYPE_VIDEO_AVC) == 0) {
        maxBlocks = 99;
        maxBlocksPerSecond = 1485;
        maxBps = 64000;
        maxDPBBlocks = 396;
        for (ProfileLevel profileLevel: profileLevels) {
            int MBPS = 0, FS = 0, BR = 0, DPB = 0;
            bool supported = true;
            switch (profileLevel.mLevel) {
                case AVCLevel1:
                    MBPS =     1485; FS =     99; BR =     64; DPB =    396; break;
                case AVCLevel1b:
                    MBPS =     1485; FS =     99; BR =    128; DPB =    396; break;
                case AVCLevel11:
                    MBPS =     3000; FS =    396; BR =    192; DPB =    900; break;
                case AVCLevel12:
                    MBPS =     6000; FS =    396; BR =    384; DPB =   2376; break;
                case AVCLevel13:
                    MBPS =    11880; FS =    396; BR =    768; DPB =   2376; break;
                case AVCLevel2:
                    MBPS =    11880; FS =    396; BR =   2000; DPB =   2376; break;
                case AVCLevel21:
                    MBPS =    19800; FS =    792; BR =   4000; DPB =   4752; break;
                case AVCLevel22:
                    MBPS =    20250; FS =   1620; BR =   4000; DPB =   8100; break;
                case AVCLevel3:
                    MBPS =    40500; FS =   1620; BR =  10000; DPB =   8100; break;
                case AVCLevel31:
                    MBPS =   108000; FS =   3600; BR =  14000; DPB =  18000; break;
                case AVCLevel32:
                    MBPS =   216000; FS =   5120; BR =  20000; DPB =  20480; break;
                case AVCLevel4:
                    MBPS =   245760; FS =   8192; BR =  20000; DPB =  32768; break;
                case AVCLevel41:
                    MBPS =   245760; FS =   8192; BR =  50000; DPB =  32768; break;
                case AVCLevel42:
                    MBPS =   522240; FS =   8704; BR =  50000; DPB =  34816; break;
                case AVCLevel5:
                    MBPS =   589824; FS =  22080; BR = 135000; DPB = 110400; break;
                case AVCLevel51:
                    MBPS =   983040; FS =  36864; BR = 240000; DPB = 184320; break;
                case AVCLevel52:
                    MBPS =  2073600; FS =  36864; BR = 240000; DPB = 184320; break;
                case AVCLevel6:
                    MBPS =  4177920; FS = 139264; BR = 240000; DPB = 696320; break;
                case AVCLevel61:
                    MBPS =  8355840; FS = 139264; BR = 480000; DPB = 696320; break;
                case AVCLevel62:
                    MBPS = 16711680; FS = 139264; BR = 800000; DPB = 696320; break;
                default:
                    ALOGW("Unrecognized level %d for %s", profileLevel.mLevel, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            switch (profileLevel.mProfile) {
                case AVCProfileConstrainedHigh:
                case AVCProfileHigh:
                    BR *= 1250; break;
                case AVCProfileHigh10:
                    BR *= 3000; break;
                case AVCProfileExtended:
                case AVCProfileHigh422:
                case AVCProfileHigh444:
                    ALOGW("Unsupported profile %d for %s", profileLevel.mProfile, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
                    supported = false;
                    FALLTHROUGH_INTENDED;
                    // fall through - treat as base profile
                case AVCProfileConstrainedBaseline:
                    FALLTHROUGH_INTENDED;
                case AVCProfileBaseline:
                    FALLTHROUGH_INTENDED;
                case AVCProfileMain:
                    BR *= 1000; break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
                    BR *= 1000;
            }
            if (supported) {
                errors &= ~ERROR_UNSUPPORTED;
            }
            maxBlocksPerSecond = std::max((long)MBPS, maxBlocksPerSecond);
            maxBlocks = std::max(FS, maxBlocks);
            maxBps = std::max(BR, maxBps);
            maxDPBBlocks = std::max(maxDPBBlocks, DPB);
        }

        int maxLengthInBlocks = (int)(std::sqrt(maxBlocks * 8));
        applyMacroBlockLimits(
                maxLengthInBlocks, maxLengthInBlocks,
                maxBlocks, maxBlocksPerSecond,
                16 /* blockWidth */, 16 /* blockHeight */,
                1 /* widthAlignment */, 1 /* heightAlignment */);
    } else if (strcasecmp(mediaType, MIMETYPE_VIDEO_MPEG2) == 0) {
        int maxWidth = 11, maxHeight = 9, maxRate = 15;
        maxBlocks = 99;
        maxBlocksPerSecond = 1485;
        maxBps = 64000;
        for (ProfileLevel profileLevel: profileLevels) {
            int MBPS = 0, FS = 0, BR = 0, FR = 0, W = 0, H = 0;
            bool supported = true;
            switch (profileLevel.mProfile) {
                case MPEG2ProfileSimple:
                    switch (profileLevel.mLevel) {
                        case MPEG2LevelML:
                            FR = 30; W = 45; H =  36; MBPS =  40500; FS =  1620; BR =  15000; break;
                        default:
                            ALOGW("Unrecognized profile/level %d/%d for %s",
                                    profileLevel.mProfile, profileLevel.mLevel, mediaType);
                            errors |= ERROR_UNRECOGNIZED;
                    }
                    break;
                case MPEG2ProfileMain:
                    switch (profileLevel.mLevel) {
                        case MPEG2LevelLL:
                            FR = 30; W = 22; H =  18; MBPS =  11880; FS =   396; BR =  4000; break;
                        case MPEG2LevelML:
                            FR = 30; W = 45; H =  36; MBPS =  40500; FS =  1620; BR = 15000; break;
                        case MPEG2LevelH14:
                            FR = 60; W = 90; H =  68; MBPS = 183600; FS =  6120; BR = 60000; break;
                        case MPEG2LevelHL:
                            FR = 60; W = 120; H = 68; MBPS = 244800; FS =  8160; BR = 80000; break;
                        case MPEG2LevelHP:
                            FR = 60; W = 120; H = 68; MBPS = 489600; FS =  8160; BR = 80000; break;
                        default:
                            ALOGW("Unrecognized profile/level %d / %d for %s",
                                    profileLevel.mProfile, profileLevel.mLevel, mediaType);
                            errors |= ERROR_UNRECOGNIZED;
                    }
                    break;
                case MPEG2Profile422:
                case MPEG2ProfileSNR:
                case MPEG2ProfileSpatial:
                case MPEG2ProfileHigh:
                    ALOGV("Unsupported profile %d for %s", profileLevel.mProfile, mediaType);
                    errors |= ERROR_UNSUPPORTED;
                    supported = false;
                    break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            if (supported) {
                errors &= ~ERROR_UNSUPPORTED;
            }
            maxBlocksPerSecond = std::max((long)MBPS, maxBlocksPerSecond);
            maxBlocks = std::max(FS, maxBlocks);
            maxBps = std::max(BR * 1000, maxBps);
            maxWidth = std::max(W, maxWidth);
            maxHeight = std::max(H, maxHeight);
            maxRate = std::max(FR, maxRate);
        }
        applyMacroBlockLimits(maxWidth, maxHeight,
                maxBlocks, maxBlocksPerSecond,
                16 /* blockWidth */, 16 /* blockHeight */,
                1 /* widthAlignment */, 1 /* heightAlignment */);
        mFrameRateRange = mFrameRateRange.intersect(12, maxRate);
    } else if (strcasecmp(mediaType, MIMETYPE_VIDEO_MPEG4) == 0) {
        int maxWidth = 11, maxHeight = 9, maxRate = 15;
        maxBlocks = 99;
        maxBlocksPerSecond = 1485;
        maxBps = 64000;
        for (ProfileLevel profileLevel: profileLevels) {
            int MBPS = 0, FS = 0, BR = 0, FR = 0, W = 0, H = 0;
            bool strict = false; // true: W, H and FR are individual max limits
            bool supported = true;
            switch (profileLevel.mProfile) {
                case MPEG4ProfileSimple:
                    switch (profileLevel.mLevel) {
                        case MPEG4Level0:
                            strict = true;
                            FR = 15; W = 11; H =  9; MBPS =  1485; FS =  99; BR =  64; break;
                        case MPEG4Level1:
                            FR = 30; W = 11; H =  9; MBPS =  1485; FS =  99; BR =  64; break;
                        case MPEG4Level0b:
                            strict = true;
                            FR = 15; W = 11; H =  9; MBPS =  1485; FS =  99; BR = 128; break;
                        case MPEG4Level2:
                            FR = 30; W = 22; H = 18; MBPS =  5940; FS = 396; BR = 128; break;
                        case MPEG4Level3:
                            FR = 30; W = 22; H = 18; MBPS = 11880; FS = 396; BR = 384; break;
                        case MPEG4Level4a:
                            FR = 30; W = 40; H = 30; MBPS = 36000; FS = 1200; BR = 4000; break;
                        case MPEG4Level5:
                            FR = 30; W = 45; H = 36; MBPS = 40500; FS = 1620; BR = 8000; break;
                        case MPEG4Level6:
                            FR = 30; W = 80; H = 45; MBPS = 108000; FS = 3600; BR = 12000; break;
                        default:
                            ALOGW("Unrecognized profile/level %d/%d for %s",
                                    profileLevel.mProfile, profileLevel.mLevel, mediaType);
                            errors |= ERROR_UNRECOGNIZED;
                    }
                    break;
                case MPEG4ProfileAdvancedSimple:
                    switch (profileLevel.mLevel) {
                        case MPEG4Level0:
                        case MPEG4Level1:
                            FR = 30; W = 11; H =  9; MBPS =  2970; FS =   99; BR =  128; break;
                        case MPEG4Level2:
                            FR = 30; W = 22; H = 18; MBPS =  5940; FS =  396; BR =  384; break;
                        case MPEG4Level3:
                            FR = 30; W = 22; H = 18; MBPS = 11880; FS =  396; BR =  768; break;
                        case MPEG4Level3b:
                            FR = 30; W = 22; H = 18; MBPS = 11880; FS =  396; BR = 1500; break;
                        case MPEG4Level4:
                            FR = 30; W = 44; H = 36; MBPS = 23760; FS =  792; BR = 3000; break;
                        case MPEG4Level5:
                            FR = 30; W = 45; H = 36; MBPS = 48600; FS = 1620; BR = 8000; break;
                        default:
                            ALOGW("Unrecognized profile/level %d/%d for %s",
                                    profileLevel.mProfile, profileLevel.mLevel, mediaType);
                            errors |= ERROR_UNRECOGNIZED;
                    }
                    break;
                case MPEG4ProfileMain:             // 2-4
                case MPEG4ProfileNbit:             // 2
                case MPEG4ProfileAdvancedRealTime: // 1-4
                case MPEG4ProfileCoreScalable:     // 1-3
                case MPEG4ProfileAdvancedCoding:   // 1-4
                case MPEG4ProfileCore:             // 1-2
                case MPEG4ProfileAdvancedCore:     // 1-4
                case MPEG4ProfileSimpleScalable:   // 0-2
                case MPEG4ProfileHybrid:           // 1-2

                // Studio profiles are not supported by our codecs.

                // Only profiles that can decode simple object types are considered.
                // The following profiles are not able to.
                case MPEG4ProfileBasicAnimated:    // 1-2
                case MPEG4ProfileScalableTexture:  // 1
                case MPEG4ProfileSimpleFace:       // 1-2
                case MPEG4ProfileAdvancedScalable: // 1-3
                case MPEG4ProfileSimpleFBA:        // 1-2
                    ALOGV("Unsupported profile %d for %s", profileLevel.mProfile, mediaType);
                    errors |= ERROR_UNSUPPORTED;
                    supported = false;
                    break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            if (supported) {
                errors &= ~ERROR_UNSUPPORTED;
            }
            maxBlocksPerSecond = std::max((long)MBPS, maxBlocksPerSecond);
            maxBlocks = std::max(FS, maxBlocks);
            maxBps = std::max(BR * 1000, maxBps);
            if (strict) {
                maxWidth = std::max(W, maxWidth);
                maxHeight = std::max(H, maxHeight);
                maxRate = std::max(FR, maxRate);
            } else {
                // assuming max 60 fps frame rate and 1:2 aspect ratio
                int maxDim = (int)std::sqrt(FS * 2);
                maxWidth = std::max(maxDim, maxWidth);
                maxHeight = std::max(maxDim, maxHeight);
                maxRate = std::max(std::max(FR, 60), maxRate);
            }
        }
        applyMacroBlockLimits(maxWidth, maxHeight,
                maxBlocks, maxBlocksPerSecond,
                16 /* blockWidth */, 16 /* blockHeight */,
                1 /* widthAlignment */, 1 /* heightAlignment */);
        mFrameRateRange = mFrameRateRange.intersect(12, maxRate);
    } else if (strcasecmp(mediaType, MIMETYPE_VIDEO_H263) == 0) {
        int maxWidth = 11, maxHeight = 9, maxRate = 15;
        int minWidth = maxWidth, minHeight = maxHeight;
        int minAlignment = 16;
        maxBlocks = 99;
        maxBlocksPerSecond = 1485;
        maxBps = 64000;
        for (ProfileLevel profileLevel: profileLevels) {
            int MBPS = 0, BR = 0, FR = 0, W = 0, H = 0, minW = minWidth, minH = minHeight;
            bool strict = false; // true: support only sQCIF, QCIF (maybe CIF)
            switch (profileLevel.mLevel) {
                case H263Level10:
                    strict = true; // only supports sQCIF & QCIF
                    FR = 15; W = 11; H =  9; BR =   1; MBPS =  W * H * FR; break;
                case H263Level20:
                    strict = true; // only supports sQCIF, QCIF & CIF
                    FR = 30; W = 22; H = 18; BR =   2; MBPS =  W * H * 15; break;
                case H263Level30:
                    strict = true; // only supports sQCIF, QCIF & CIF
                    FR = 30; W = 22; H = 18; BR =   6; MBPS =  W * H * FR; break;
                case H263Level40:
                    strict = true; // only supports sQCIF, QCIF & CIF
                    FR = 30; W = 22; H = 18; BR =  32; MBPS =  W * H * FR; break;
                case H263Level45:
                    // only implies level 10 support
                    strict = profileLevel.mProfile == H263ProfileBaseline
                            || profileLevel.mProfile ==
                                    H263ProfileBackwardCompatible;
                    if (!strict) {
                        minW = 1; minH = 1; minAlignment = 4;
                    }
                    FR = 15; W = 11; H =  9; BR =   2; MBPS =  W * H * FR; break;
                case H263Level50:
                    // only supports 50fps for H > 15
                    minW = 1; minH = 1; minAlignment = 4;
                    FR = 60; W = 22; H = 18; BR =  64; MBPS =  W * H * 50; break;
                case H263Level60:
                    // only supports 50fps for H > 15
                    minW = 1; minH = 1; minAlignment = 4;
                    FR = 60; W = 45; H = 18; BR = 128; MBPS =  W * H * 50; break;
                case H263Level70:
                    // only supports 50fps for H > 30
                    minW = 1; minH = 1; minAlignment = 4;
                    FR = 60; W = 45; H = 36; BR = 256; MBPS =  W * H * 50; break;
                default:
                    ALOGW("Unrecognized profile/level %d/%d for %s",
                            profileLevel.mProfile, profileLevel.mLevel, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            switch (profileLevel.mProfile) {
                case H263ProfileBackwardCompatible:
                case H263ProfileBaseline:
                case H263ProfileH320Coding:
                case H263ProfileHighCompression:
                case H263ProfileHighLatency:
                case H263ProfileInterlace:
                case H263ProfileInternet:
                case H263ProfileISWV2:
                case H263ProfileISWV3:
                    break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            if (strict) {
                // Strict levels define sub-QCIF min size and enumerated sizes. We cannot
                // express support for "only sQCIF & QCIF (& CIF)" using VideoCapabilities
                // but we can express "only QCIF (& CIF)", so set minimume size at QCIF.
                // minW = 8; minH = 6;
                minW = 11; minH = 9;
            } else {
                // any support for non-strict levels (including unrecognized profiles or
                // levels) allow custom frame size support beyond supported limits
                // (other than bitrate)
                mAllowMbOverride = true;
            }
            errors &= ~ERROR_UNSUPPORTED;
            maxBlocksPerSecond = std::max((long)MBPS, maxBlocksPerSecond);
            maxBlocks = std::max(W * H, maxBlocks);
            maxBps = std::max(BR * 64000, maxBps);
            maxWidth = std::max(W, maxWidth);
            maxHeight = std::max(H, maxHeight);
            maxRate = std::max(FR, maxRate);
            minWidth = std::min(minW, minWidth);
            minHeight = std::min(minH, minHeight);
        }
        // unless we encountered custom frame size support, limit size to QCIF and CIF
        // using aspect ratio.
        if (!mAllowMbOverride) {
            mBlockAspectRatioRange =
                Range(Rational(11, 9), Rational(11, 9));
        }
        applyMacroBlockLimits(
                minWidth, minHeight,
                maxWidth, maxHeight,
                maxBlocks, maxBlocksPerSecond,
                16 /* blockWidth */, 16 /* blockHeight */,
                minAlignment /* widthAlignment */, minAlignment /* heightAlignment */);
        mFrameRateRange = Range(1, maxRate);
    } else if (strcasecmp(mediaType, MIMETYPE_VIDEO_VP8) == 0) {
        maxBlocks = INT_MAX;
        maxBlocksPerSecond = INT_MAX;

        // TODO: set to 100Mbps for now, need a number for VP8
        maxBps = 100000000;

        // profile levels are not indicative for VPx, but verify
        // them nonetheless
        for (ProfileLevel profileLevel: profileLevels) {
            switch (profileLevel.mLevel) {
                case VP8Level_Version0:
                case VP8Level_Version1:
                case VP8Level_Version2:
                case VP8Level_Version3:
                    break;
                default:
                    ALOGW("Unrecognized level %d for %s", profileLevel.mLevel, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            switch (profileLevel.mProfile) {
                case VP8ProfileMain:
                    break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            errors &= ~ERROR_UNSUPPORTED;
        }

        const int blockSize = 16;
        applyMacroBlockLimits(SHRT_MAX, SHRT_MAX,
                maxBlocks, maxBlocksPerSecond, blockSize, blockSize,
                1 /* widthAlignment */, 1 /* heightAlignment */);
    } else if (strcasecmp(mediaType, MIMETYPE_VIDEO_VP9) == 0) {
        maxBlocksPerSecond = 829440;
        maxBlocks = 36864;
        maxBps = 200000;
        int maxDim = 512;

        for (ProfileLevel profileLevel: profileLevels) {
            long long SR = 0; // luma sample rate
            int FS = 0;  // luma picture size
            int BR = 0;  // bit rate kbps
            int D = 0;   // luma dimension
            switch (profileLevel.mLevel) {
                case VP9Level1:
                    SR =      829440; FS =    36864; BR =    200; D =   512; break;
                case VP9Level11:
                    SR =     2764800; FS =    73728; BR =    800; D =   768; break;
                case VP9Level2:
                    SR =     4608000; FS =   122880; BR =   1800; D =   960; break;
                case VP9Level21:
                    SR =     9216000; FS =   245760; BR =   3600; D =  1344; break;
                case VP9Level3:
                    SR =    20736000; FS =   552960; BR =   7200; D =  2048; break;
                case VP9Level31:
                    SR =    36864000; FS =   983040; BR =  12000; D =  2752; break;
                case VP9Level4:
                    SR =    83558400; FS =  2228224; BR =  18000; D =  4160; break;
                case VP9Level41:
                    SR =   160432128; FS =  2228224; BR =  30000; D =  4160; break;
                case VP9Level5:
                    SR =   311951360; FS =  8912896; BR =  60000; D =  8384; break;
                case VP9Level51:
                    SR =   588251136; FS =  8912896; BR = 120000; D =  8384; break;
                case VP9Level52:
                    SR =  1176502272; FS =  8912896; BR = 180000; D =  8384; break;
                case VP9Level6:
                    SR =  1176502272; FS = 35651584; BR = 180000; D = 16832; break;
                case VP9Level61:
                    SR = 2353004544L; FS = 35651584; BR = 240000; D = 16832; break;
                case VP9Level62:
                    SR = 4706009088L; FS = 35651584; BR = 480000; D = 16832; break;
                default:
                    ALOGW("Unrecognized level %d for %s", profileLevel.mLevel, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            switch (profileLevel.mProfile) {
                case VP9Profile0:
                case VP9Profile1:
                case VP9Profile2:
                case VP9Profile3:
                case VP9Profile2HDR:
                case VP9Profile3HDR:
                case VP9Profile2HDR10Plus:
                case VP9Profile3HDR10Plus:
                    break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            errors &= ~ERROR_UNSUPPORTED;
            maxBlocksPerSecond = std::max(SR, (long long)maxBlocksPerSecond);
            maxBlocks = std::max(FS, maxBlocks);
            maxBps = std::max(BR * 1000, maxBps);
            maxDim = std::max(D, maxDim);
        }

        const int blockSize = 8;
        int maxLengthInBlocks = divUp(maxDim, blockSize);
        maxBlocks = divUp(maxBlocks, blockSize * blockSize);
        maxBlocksPerSecond = divUpLong(maxBlocksPerSecond, blockSize * blockSize);

        applyMacroBlockLimits(
                maxLengthInBlocks, maxLengthInBlocks,
                maxBlocks, maxBlocksPerSecond,
                blockSize, blockSize,
                1 /* widthAlignment */, 1 /* heightAlignment */);
    } else if (strcasecmp(mediaType, MIMETYPE_VIDEO_HEVC) == 0) {
        // CTBs are at least 8x8 so use 8x8 block size
        maxBlocks = 36864 >> 6; // 192x192 pixels == 576 8x8 blocks
        maxBlocksPerSecond = maxBlocks * 15;
        maxBps = 128000;
        for (ProfileLevel profileLevel: profileLevels) {
            double FR = 0;
            int FS = 0;
            int BR = 0;
            switch (profileLevel.mLevel) {
                /* The HEVC spec talks only in a very convoluted manner about the
                    existence of levels 1-3.1 for High tier, which could also be
                    understood as 'decoders and encoders should treat these levels
                    as if they were Main tier', so we do that. */
                case HEVCMainTierLevel1:
                case HEVCHighTierLevel1:
                    FR =    15; FS =    36864; BR =    128; break;
                case HEVCMainTierLevel2:
                case HEVCHighTierLevel2:
                    FR =    30; FS =   122880; BR =   1500; break;
                case HEVCMainTierLevel21:
                case HEVCHighTierLevel21:
                    FR =    30; FS =   245760; BR =   3000; break;
                case HEVCMainTierLevel3:
                case HEVCHighTierLevel3:
                    FR =    30; FS =   552960; BR =   6000; break;
                case HEVCMainTierLevel31:
                case HEVCHighTierLevel31:
                    FR = 33.75; FS =   983040; BR =  10000; break;
                case HEVCMainTierLevel4:
                    FR =    30; FS =  2228224; BR =  12000; break;
                case HEVCHighTierLevel4:
                    FR =    30; FS =  2228224; BR =  30000; break;
                case HEVCMainTierLevel41:
                    FR =    60; FS =  2228224; BR =  20000; break;
                case HEVCHighTierLevel41:
                    FR =    60; FS =  2228224; BR =  50000; break;
                case HEVCMainTierLevel5:
                    FR =    30; FS =  8912896; BR =  25000; break;
                case HEVCHighTierLevel5:
                    FR =    30; FS =  8912896; BR = 100000; break;
                case HEVCMainTierLevel51:
                    FR =    60; FS =  8912896; BR =  40000; break;
                case HEVCHighTierLevel51:
                    FR =    60; FS =  8912896; BR = 160000; break;
                case HEVCMainTierLevel52:
                    FR =   120; FS =  8912896; BR =  60000; break;
                case HEVCHighTierLevel52:
                    FR =   120; FS =  8912896; BR = 240000; break;
                case HEVCMainTierLevel6:
                    FR =    30; FS = 35651584; BR =  60000; break;
                case HEVCHighTierLevel6:
                    FR =    30; FS = 35651584; BR = 240000; break;
                case HEVCMainTierLevel61:
                    FR =    60; FS = 35651584; BR = 120000; break;
                case HEVCHighTierLevel61:
                    FR =    60; FS = 35651584; BR = 480000; break;
                case HEVCMainTierLevel62:
                    FR =   120; FS = 35651584; BR = 240000; break;
                case HEVCHighTierLevel62:
                    FR =   120; FS = 35651584; BR = 800000; break;
                default:
                    ALOGW("Unrecognized level %d for %s", profileLevel.mLevel, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            switch (profileLevel.mProfile) {
                case HEVCProfileMain:
                case HEVCProfileMain10:
                case HEVCProfileMainStill:
                case HEVCProfileMain10HDR10:
                case HEVCProfileMain10HDR10Plus:
                    break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }

            /* DPB logic:
            if      (width * height <= FS / 4)    DPB = 16;
            else if (width * height <= FS / 2)    DPB = 12;
            else if (width * height <= FS * 0.75) DPB = 8;
            else                                  DPB = 6;
            */

            FS >>= 6; // convert pixels to blocks
            errors &= ~ERROR_UNSUPPORTED;
            maxBlocksPerSecond = std::max((long)(FR * FS), maxBlocksPerSecond);
            maxBlocks = std::max(FS, maxBlocks);
            maxBps = std::max(BR * 1000, maxBps);
        }

        int maxLengthInBlocks = (int)(std::sqrt(maxBlocks * 8));
        applyMacroBlockLimits(
                maxLengthInBlocks, maxLengthInBlocks,
                maxBlocks, maxBlocksPerSecond,
                8 /* blockWidth */, 8 /* blockHeight */,
                1 /* widthAlignment */, 1 /* heightAlignment */);
    } else if (strcasecmp(mediaType, MIMETYPE_VIDEO_AV1) == 0) {
        maxBlocksPerSecond = 829440;
        maxBlocks = 36864;
        maxBps = 200000;
        int maxDim = 512;

        // Sample rate, Picture Size, Bit rate and luma dimension for AV1 Codec,
        // corresponding to the definitions in
        // "AV1 Bitstream & Decoding Process Specification", Annex A
        // found at https://aomedia.org/av1-bitstream-and-decoding-process-specification/
        for (ProfileLevel profileLevel: profileLevels) {
            long long SR = 0; // luma sample rate
            int FS = 0;  // luma picture size
            int BR = 0;  // bit rate kbps
            int D = 0;   // luma D
            switch (profileLevel.mLevel) {
                case AV1Level2:
                    SR =     5529600; FS =   147456; BR =   1500; D =  2048; break;
                case AV1Level21:
                case AV1Level22:
                case AV1Level23:
                    SR =    10454400; FS =   278784; BR =   3000; D =  2816; break;

                case AV1Level3:
                    SR =    24969600; FS =   665856; BR =   6000; D =  4352; break;
                case AV1Level31:
                case AV1Level32:
                case AV1Level33:
                    SR =    39938400; FS =  1065024; BR =  10000; D =  5504; break;

                case AV1Level4:
                    SR =    77856768; FS =  2359296; BR =  12000; D =  6144; break;
                case AV1Level41:
                case AV1Level42:
                case AV1Level43:
                    SR =   155713536; FS =  2359296; BR =  20000; D =  6144; break;

                case AV1Level5:
                    SR =   273715200; FS =  8912896; BR =  30000; D =  8192; break;
                case AV1Level51:
                    SR =   547430400; FS =  8912896; BR =  40000; D =  8192; break;
                case AV1Level52:
                    SR =  1094860800; FS =  8912896; BR =  60000; D =  8192; break;
                case AV1Level53:
                    SR =  1176502272; FS =  8912896; BR =  60000; D =  8192; break;

                case AV1Level6:
                    SR =  1176502272; FS = 35651584; BR =  60000; D = 16384; break;
                case AV1Level61:
                    SR = 2189721600L; FS = 35651584; BR = 100000; D = 16384; break;
                case AV1Level62:
                    SR = 4379443200L; FS = 35651584; BR = 160000; D = 16384; break;
                case AV1Level63:
                    SR = 4706009088L; FS = 35651584; BR = 160000; D = 16384; break;

                default:
                    ALOGW("Unrecognized level %d for %s", profileLevel.mLevel, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            switch (profileLevel.mProfile) {
                case AV1ProfileMain8:
                case AV1ProfileMain10:
                case AV1ProfileMain10HDR10:
                case AV1ProfileMain10HDR10Plus:
                    break;
                default:
                    ALOGW("Unrecognized profile %d for %s", profileLevel.mProfile, mediaType);
                    errors |= ERROR_UNRECOGNIZED;
            }
            errors &= ~ERROR_UNSUPPORTED;
            maxBlocksPerSecond = std::max(SR, (long long)maxBlocksPerSecond);
            maxBlocks = std::max(FS, maxBlocks);
            maxBps = std::max(BR * 1000, maxBps);
            maxDim = std::max(D, maxDim);
        }

        const int blockSize = 8;
        int maxLengthInBlocks = divUp(maxDim, blockSize);
        maxBlocks = divUp(maxBlocks, blockSize * blockSize);
        maxBlocksPerSecond = divUpLong(maxBlocksPerSecond, blockSize * blockSize);
        applyMacroBlockLimits(
                maxLengthInBlocks, maxLengthInBlocks,
                maxBlocks, maxBlocksPerSecond,
                blockSize, blockSize,
                1 /* widthAlignment */, 1 /* heightAlignment */);
    } else {
        ALOGW("Unsupported mime %s", mediaType);
        // using minimal bitrate here.  should be overridden by
        // info from media_codecs.xml
        maxBps = 64000;
        errors |= ERROR_UNSUPPORTED;
    }
    mBitrateRange = Range(1, maxBps);
    setParentError(errors);
}

// EncoderCapabilities

Range<int> MediaCodecInfo::EncoderCapabilities::getQualityRange() {
    return mQualityRange;
}

Range<int> MediaCodecInfo::EncoderCapabilities::getComplexityRange() {
    return mComplexityRange;
}

// static
int MediaCodecInfo::EncoderCapabilities::ParseBitrateMode(std::string mode) {
    for (Feature feat: bitrates) {
        if (strcasecmp(feat.mName.c_str(), mode.c_str()) == 0) {
            return feat.mValue;
        }
    }
    return 0;
}

bool MediaCodecInfo::EncoderCapabilities::isBitrateModeSupported(int mode) {
    for (Feature feat: bitrates) {
        if (mode == feat.mValue) {
            return (mBitControl & (1 << mode)) != 0;
        }
    }
    return false;
}

// static
std::unique_ptr<MediaCodecInfo::EncoderCapabilities> MediaCodecInfo::EncoderCapabilities::Create(
        const sp<AMessage> &format, CodecCapabilities &parent) {
    std::unique_ptr<EncoderCapabilities> caps(new EncoderCapabilities());
    caps->init(format, parent);
    return caps;
}

void MediaCodecInfo::EncoderCapabilities::init(const sp<AMessage> &format,
        CodecCapabilities &parent) {
    // no support for complexity or quality yet
    mParent = std::make_shared<CodecCapabilities>(parent);
    mComplexityRange = Range(0, 0);
    mQualityRange = Range(0, 0);
    mBitControl = (1 << BITRATE_MODE_VBR);

    applyLevelLimits();
    parseFromInfo(format);
}

void MediaCodecInfo::EncoderCapabilities::applyLevelLimits() {
    auto lockParent = mParent.lock();
    if (!lockParent) {
        return;
    }
    const std::string mediaTypeStr = lockParent->getMediaType();
    const char* mediaType = mediaTypeStr.c_str();
    if (strcasecmp(mediaType, MIMETYPE_AUDIO_FLAC) == 0) {
        mComplexityRange = Range(0, 8);
        mBitControl = (1 << BITRATE_MODE_CQ);
    } else if (strcasecmp(mediaType, MIMETYPE_AUDIO_AMR_NB) == 0
            || strcasecmp(mediaType, MIMETYPE_AUDIO_AMR_WB) == 0
            || strcasecmp(mediaType, MIMETYPE_AUDIO_G711_ALAW) == 0
            || strcasecmp(mediaType, MIMETYPE_AUDIO_G711_MLAW) == 0
            || strcasecmp(mediaType, MIMETYPE_AUDIO_MSGSM) == 0) {
        mBitControl = (1 << BITRATE_MODE_CBR);
    }
}

void MediaCodecInfo::EncoderCapabilities::parseFromInfo(const sp<AMessage> &format) {
    AString complexityRangeAStr;
    if (format->findString("complexity-range", &complexityRangeAStr)) {
        std::optional<Range<int>> complexityRangeOpt
                = ParseIntRange(std::string(complexityRangeAStr.c_str()));
        mComplexityRange = complexityRangeOpt.value_or(mComplexityRange);
        // TODO should we limit this to level limits?
    }
    AString qualityRangeAStr;
    if (format->findString("quality-range", &qualityRangeAStr)) {
        std::optional<Range<int>> qualityRangeOpt
                = ParseIntRange(std::string(qualityRangeAStr.c_str()));
        mQualityRange = qualityRangeOpt.value_or(mQualityRange);
    }
    AString bitrateModesAStr;
    if (format->findString("feature-bitrate-modes", &bitrateModesAStr)) {
        mBitControl = 0;
        for (std::string mode: base::Split(std::string(bitrateModesAStr.c_str()), ",")) {
            mBitControl |= (1 << ParseBitrateMode(mode));
        }
    }
    format->findInt32("complexity-default", &mDefaultComplexity);
    format->findInt32("quality-default", &mDefaultQuality);
    AString qualityScaleAStr;
    if (format->findString("quality-scale", &qualityScaleAStr)) {
        mQualityScale = std::string(qualityScaleAStr.c_str());
    }
}

bool MediaCodecInfo::EncoderCapabilities::supports(
        std::optional<int> complexity, std::optional<int> quality, std::optional<int> profile) {
    bool ok = true;
    if (ok && complexity) {
        ok = mComplexityRange.contains(complexity.value());
    }
    if (ok && quality) {
        ok = mQualityRange.contains(quality.value());
    }
    if (ok && profile) {
        auto lockParent = mParent.lock();
        if (!lockParent) {
            return false;
        }
        for (ProfileLevel pl: lockParent->getProfileLevels()) {
            if (pl.mProfile == profile.value()) {
                profile = std::nullopt;
                break;
            }
        }
        ok = profile == std::nullopt;
    }
    return ok;
}

void MediaCodecInfo::EncoderCapabilities::getDefaultFormat(sp<AMessage> &format) {
    // don't list trivial quality/complexity as default for now
    if (mQualityRange.upper() != mQualityRange.lower()
            && mDefaultQuality != 0) {
        format->setInt32(KEY_QUALITY, mDefaultQuality);
    }
    if (mComplexityRange.upper() != mComplexityRange.lower()
            && mDefaultComplexity != 0) {
        format->setInt32(KEY_COMPLEXITY, mDefaultComplexity);
    }
    // bitrates are listed in order of preference
    for (Feature feat: bitrates) {
        if ((mBitControl & (1 << feat.mValue)) != 0) {
            format->setInt32(KEY_BITRATE_MODE, feat.mValue);
            break;
        }
    }
}

bool MediaCodecInfo::EncoderCapabilities::supportsFormat(const sp<AMessage> &format) {
    auto lockParent = mParent.lock();
    if (!lockParent) {
        return false;
    }
    const std::string mediaType = lockParent->getMediaType();

    int32_t mode;
    if (format->findInt32(KEY_BITRATE_MODE, &mode) && !isBitrateModeSupported(mode)) {
        return false;
    }

    std::optional<int> complexityOpt = std::nullopt;
    int complexity;
    if (format->findInt32(KEY_COMPLEXITY, &complexity)) {
        complexityOpt = complexity;
    }
    if (strcasecmp(mediaType.c_str(), MIMETYPE_AUDIO_FLAC) == 0) {
        int flacComplexity;
        if (format->findInt32(KEY_FLAC_COMPRESSION_LEVEL, &flacComplexity)) {
            if (!complexityOpt) {
                complexityOpt = flacComplexity;
            } else if (flacComplexity != complexityOpt.value()) {
                // CHECK(complexity == flacComplexity);
                ALOGE("conflicting values for complexity and flac-compression-level");
                return false;
            }
        }
    }

    // other audio parameters
    std::optional<int> profileOpt = std::nullopt;
    int profile;
    if (format->findInt32(KEY_PROFILE, &profile)) {
        profileOpt = profile;
    }
    if (strcasecmp(mediaType.c_str(), MIMETYPE_AUDIO_AAC)) {
        int aacProfile;
        if (format->findInt32(KEY_AAC_PROFILE, &aacProfile)) {
            if (!profileOpt) {
                profileOpt = aacProfile;
            } else if (aacProfile != profileOpt.value()) {
                ALOGE("conflicting values for profile and aac-profile");
                return false;
            }
        }
    }

    std::optional<int> qualityOpt = std::nullopt;
    int quality;
    if (format->findInt32(KEY_QUALITY, &quality)) {
        qualityOpt = quality;
    }

    return supports(complexity, quality, profile);
}

// CodecCapabilities

bool MediaCodecInfo::CodecCapabilities::supportsBitrate(Range<int> bitrateRange,
        const sp<AMessage> &format) {
    // consider max bitrate over average bitrate for support
    int32_t maxBitrate = 0;
    format->findInt32(KEY_MAX_BIT_RATE, &maxBitrate);
    int32_t bitrate = 0;
    format->findInt32(KEY_BIT_RATE, &bitrate);

    if (bitrate == 0) {
        bitrate = maxBitrate;
    } else if (maxBitrate != 0) {
        bitrate = std::max(bitrate, maxBitrate);
    }

    if (bitrate > 0) {
        return bitrateRange.contains(bitrate);
    }

    return true;
}

std::vector<MediaCodecInfo::ProfileLevel> MediaCodecInfo::CodecCapabilities::getProfileLevels() {
    return mProfileLevels;
}

std::string MediaCodecInfo::CodecCapabilities::getMediaType() {
    return mMediaType;
}

/** This redundant redeclaration is needed for C++ pre 14 */
constexpr char MediaCodecInfo::Capabilities::FEATURE_ADAPTIVE_PLAYBACK[];
constexpr char MediaCodecInfo::Capabilities::FEATURE_DYNAMIC_TIMESTAMP[];
constexpr char MediaCodecInfo::Capabilities::FEATURE_FRAME_PARSING[];
constexpr char MediaCodecInfo::Capabilities::FEATURE_INTRA_REFRESH[];
constexpr char MediaCodecInfo::Capabilities::FEATURE_MULTIPLE_FRAMES[];
constexpr char MediaCodecInfo::Capabilities::FEATURE_SECURE_PLAYBACK[];
constexpr char MediaCodecInfo::Capabilities::FEATURE_TUNNELED_PLAYBACK[];

void MediaCodecInfo::Capabilities::getSupportedProfileLevels(
        Vector<ProfileLevel> *profileLevels) const {
    profileLevels->clear();
    profileLevels->appendVector(mProfileLevels);
}

void MediaCodecInfo::Capabilities::getSupportedColorFormats(
        Vector<uint32_t> *colorFormats) const {
    colorFormats->clear();
    colorFormats->appendVector(mColorFormats);
}

const sp<AMessage> MediaCodecInfo::Capabilities::getDetails() const {
    return mDetails;
}

MediaCodecInfo::Capabilities::Capabilities() {
    mDetails = new AMessage;
}

// static
sp<MediaCodecInfo::Capabilities> MediaCodecInfo::Capabilities::FromParcel(
        const Parcel &parcel) {
    sp<MediaCodecInfo::Capabilities> caps = new Capabilities();
    size_t size = static_cast<size_t>(parcel.readInt32());
    for (size_t i = 0; i < size; i++) {
        ProfileLevel profileLevel;
        profileLevel.mProfile = static_cast<uint32_t>(parcel.readInt32());
        profileLevel.mLevel = static_cast<uint32_t>(parcel.readInt32());
        if (caps != NULL) {
            caps->mProfileLevels.push_back(profileLevel);
        }
    }
    size = static_cast<size_t>(parcel.readInt32());
    for (size_t i = 0; i < size; i++) {
        uint32_t color = static_cast<uint32_t>(parcel.readInt32());
        if (caps != NULL) {
            caps->mColorFormats.push_back(color);
        }
    }
    sp<AMessage> details = AMessage::FromParcel(parcel);
    if (details == NULL)
        return NULL;
    if (caps != NULL) {
        caps->mDetails = details;
    }
    return caps;
}

status_t MediaCodecInfo::Capabilities::writeToParcel(Parcel *parcel) const {
    CHECK_LE(mProfileLevels.size(), static_cast<size_t>(INT32_MAX));
    parcel->writeInt32(mProfileLevels.size());
    for (size_t i = 0; i < mProfileLevels.size(); i++) {
        parcel->writeInt32(mProfileLevels.itemAt(i).mProfile);
        parcel->writeInt32(mProfileLevels.itemAt(i).mLevel);
    }
    CHECK_LE(mColorFormats.size(), static_cast<size_t>(INT32_MAX));
    parcel->writeInt32(mColorFormats.size());
    for (size_t i = 0; i < mColorFormats.size(); i++) {
        parcel->writeInt32(mColorFormats.itemAt(i));
    }
    mDetails->writeToParcel(parcel);
    return OK;
}

void MediaCodecInfo::CapabilitiesWriter::addDetail(
        const char* key, const char* value) {
    mCap->mDetails->setString(key, value);
}

void MediaCodecInfo::CapabilitiesWriter::addDetail(
        const char* key, int32_t value) {
    mCap->mDetails->setInt32(key, value);
}

void MediaCodecInfo::CapabilitiesWriter::removeDetail(const char* key) {
    if (mCap->mDetails->removeEntryAt(mCap->mDetails->findEntryByName(key)) == OK) {
        ALOGD("successfully removed detail %s", key);
    } else {
        ALOGD("detail %s wasn't present to remove", key);
    }
}

void MediaCodecInfo::CapabilitiesWriter::addProfileLevel(
        uint32_t profile, uint32_t level) {
    ProfileLevel profileLevel;
    profileLevel.mProfile = profile;
    profileLevel.mLevel = level;
    if (mCap->mProfileLevelsSorted.indexOf(profileLevel) < 0) {
        mCap->mProfileLevels.push_back(profileLevel);
        mCap->mProfileLevelsSorted.add(profileLevel);
    }
}

void MediaCodecInfo::CapabilitiesWriter::addColorFormat(uint32_t format) {
    if (mCap->mColorFormatsSorted.indexOf(format) < 0) {
        mCap->mColorFormats.push(format);
        mCap->mColorFormatsSorted.add(format);
    }
}

MediaCodecInfo::CapabilitiesWriter::CapabilitiesWriter(
        MediaCodecInfo::Capabilities* cap) : mCap(cap) {
}

MediaCodecInfo::Attributes MediaCodecInfo::getAttributes() const {
    return mAttributes;
}

uint32_t MediaCodecInfo::getRank() const {
    return mRank;
}

void MediaCodecInfo::getAliases(Vector<AString> *aliases) const {
    *aliases = mAliases;
}

void MediaCodecInfo::getSupportedMediaTypes(Vector<AString> *mediaTypes) const {
    mediaTypes->clear();
    for (size_t ix = 0; ix < mCaps.size(); ix++) {
        mediaTypes->push_back(mCaps.keyAt(ix));
    }
}

const sp<MediaCodecInfo::Capabilities>
MediaCodecInfo::getCapabilitiesFor(const char *mediaType) const {
    ssize_t ix = getCapabilityIndex(mediaType);
    if (ix >= 0) {
        return mCaps.valueAt(ix);
    }
    return NULL;
}

const char *MediaCodecInfo::getCodecName() const {
    return mName.c_str();
}

const char *MediaCodecInfo::getOwnerName() const {
    return mOwner.c_str();
}

// static
sp<MediaCodecInfo> MediaCodecInfo::FromParcel(const Parcel &parcel) {
    AString name = AString::FromParcel(parcel);
    AString owner = AString::FromParcel(parcel);
    Attributes attributes = static_cast<Attributes>(parcel.readInt32());
    uint32_t rank = parcel.readUint32();
    sp<MediaCodecInfo> info = new MediaCodecInfo;
    info->mName = name;
    info->mOwner = owner;
    info->mAttributes = attributes;
    info->mRank = rank;
    size_t numAliases = static_cast<size_t>(parcel.readInt32());
    for (size_t i = 0; i < numAliases; i++) {
        AString alias = AString::FromParcel(parcel);
        info->mAliases.add(alias);
    }
    size_t size = static_cast<size_t>(parcel.readInt32());
    for (size_t i = 0; i < size; i++) {
        AString mediaType = AString::FromParcel(parcel);
        sp<Capabilities> caps = Capabilities::FromParcel(parcel);
        if (caps == NULL)
            return NULL;
        if (info != NULL) {
            info->mCaps.add(mediaType, caps);
        }
    }
    return info;
}

status_t MediaCodecInfo::writeToParcel(Parcel *parcel) const {
    mName.writeToParcel(parcel);
    mOwner.writeToParcel(parcel);
    parcel->writeInt32(mAttributes);
    parcel->writeUint32(mRank);
    parcel->writeInt32(mAliases.size());
    for (const AString &alias : mAliases) {
        alias.writeToParcel(parcel);
    }
    parcel->writeInt32(mCaps.size());
    for (size_t i = 0; i < mCaps.size(); i++) {
        mCaps.keyAt(i).writeToParcel(parcel);
        mCaps.valueAt(i)->writeToParcel(parcel);
    }
    return OK;
}

ssize_t MediaCodecInfo::getCapabilityIndex(const char *mediaType) const {
    if (mediaType) {
        for (size_t ix = 0; ix < mCaps.size(); ix++) {
            if (mCaps.keyAt(ix).equalsIgnoreCase(mediaType)) {
                return ix;
            }
        }
    }
    return -1;
}

MediaCodecInfo::MediaCodecInfo()
    : mAttributes((MediaCodecInfo::Attributes)0),
      mRank(0x100) {
}

void MediaCodecInfoWriter::setName(const char* name) {
    mInfo->mName = name;
}

void MediaCodecInfoWriter::addAlias(const char* name) {
    mInfo->mAliases.add(name);
}

void MediaCodecInfoWriter::setOwner(const char* owner) {
    mInfo->mOwner = owner;
}

void MediaCodecInfoWriter::setAttributes(
        typename std::underlying_type<MediaCodecInfo::Attributes>::type attributes) {
    mInfo->mAttributes = (MediaCodecInfo::Attributes)attributes;
}

void MediaCodecInfoWriter::setRank(uint32_t rank) {
    mInfo->mRank = rank;
}

std::unique_ptr<MediaCodecInfo::CapabilitiesWriter>
        MediaCodecInfoWriter::addMediaType(const char *mediaType) {
    ssize_t ix = mInfo->getCapabilityIndex(mediaType);
    if (ix >= 0) {
        return std::unique_ptr<MediaCodecInfo::CapabilitiesWriter>(
                new MediaCodecInfo::CapabilitiesWriter(
                mInfo->mCaps.valueAt(ix).get()));
    }
    sp<MediaCodecInfo::Capabilities> caps = new MediaCodecInfo::Capabilities();
    mInfo->mCaps.add(AString(mediaType), caps);
    return std::unique_ptr<MediaCodecInfo::CapabilitiesWriter>(
            new MediaCodecInfo::CapabilitiesWriter(caps.get()));
}

bool MediaCodecInfoWriter::removeMediaType(const char *mediaType) {
    ssize_t ix = mInfo->getCapabilityIndex(mediaType);
    if (ix >= 0) {
        mInfo->mCaps.removeItemsAt(ix);
        return true;
    }
    return false;
}

MediaCodecInfoWriter::MediaCodecInfoWriter(MediaCodecInfo* info) :
    mInfo(info) {
}

}  // namespace android
