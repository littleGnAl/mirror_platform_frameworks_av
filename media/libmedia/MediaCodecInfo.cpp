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
#include <binder/Parcel.h>

namespace android {

private static int checkPowerOfTwo(int value, String message) {
    if ((value & (value - 1)) != 0) {
        throw new IllegalArgumentException(message);
    }
    return value;
}

static const Range<int> POSITIVE_INTEGERS = Range<int>(1, INT_MAX);

/* For internal use only. Not exposed as a public API */
// must not contain KEY_PROFILE
static const std::set<std::string> AUDIO_LEVEL_CRITICAL_FORMAT_KEYS = {
    // We don't set level-specific limits for audio codecs today. Key candidates would
    // be sample rate, bit rate or channel count.
    // MediaFormat.KEY_SAMPLE_RATE,
    // MediaFormat.KEY_CHANNEL_COUNT,
    // MediaFormat.KEY_BIT_RATE,
    KEY_MIME };

// found stuff that is not supported by framework (=> this should not happen)
static const int ERROR_UNRECOGNIZED   = (1 << 0);
// found profile/level for which we don't have capability estimates
static const int ERROR_UNSUPPORTED    = (1 << 1);
// have not found any profile/level for which we don't have capability estimate
// static const int ERROR_NONE_SUPPORTED = (1 << 2);

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

/**
* A class that supports querying the video capabilities of a codec.
*/
public static final class VideoCapabilities {
    private static final String TAG = "VideoCapabilities";
    private CodecCapabilities mParent;
    private Range<Integer> mBitrateRange;

    private Range<Integer> mHeightRange;
    private Range<Integer> mWidthRange;
    private Range<Integer> mBlockCountRange;
    private Range<Integer> mHorizontalBlockRange;
    private Range<Integer> mVerticalBlockRange;
    private Range<Rational> mAspectRatioRange;
    private Range<Rational> mBlockAspectRatioRange;
    private Range<Long> mBlocksPerSecondRange;
    private Map<Size, Range<Long>> mMeasuredFrameRates;
    private List<PerformancePoint> mPerformancePoints;
    private Range<Integer> mFrameRateRange;

    private int mBlockWidth;
    private int mBlockHeight;
    private int mWidthAlignment;
    private int mHeightAlignment;
    private int mSmallerDimensionUpperLimit;

    private boolean mAllowMbOverride; // allow XML to override calculated limits

    /**
        * Returns the range of supported bitrates in bits/second.
        */
    public Range<Integer> getBitrateRange() {
        return mBitrateRange;
    }

    /**
        * Returns the range of supported video widths.
        * <p class=note>
        * 32-bit processes will not support resolutions larger than 4096x4096 due to
        * the limited address space.
        */
    public Range<Integer> getSupportedWidths() {
        return mWidthRange;
    }

    /**
        * Returns the range of supported video heights.
        * <p class=note>
        * 32-bit processes will not support resolutions larger than 4096x4096 due to
        * the limited address space.
        */
    public Range<Integer> getSupportedHeights() {
        return mHeightRange;
    }

    /**
        * Returns the alignment requirement for video width (in pixels).
        *
        * This is a power-of-2 value that video width must be a
        * multiple of.
        */
    public int getWidthAlignment() {
        return mWidthAlignment;
    }

    /**
        * Returns the alignment requirement for video height (in pixels).
        *
        * This is a power-of-2 value that video height must be a
        * multiple of.
        */
    public int getHeightAlignment() {
        return mHeightAlignment;
    }

    /**
        * Return the upper limit on the smaller dimension of width or height.
        * <p></p>
        * Some codecs have a limit on the smaller dimension, whether it be
        * the width or the height.  E.g. a codec may only be able to handle
        * up to 1920x1080 both in landscape and portrait mode (1080x1920).
        * In this case the maximum width and height are both 1920, but the
        * smaller dimension limit will be 1080. For other codecs, this is
        * {@code Math.min(getSupportedWidths().getUpper(),
        * getSupportedHeights().getUpper())}.
        *
        * @hide
        */
    public int getSmallerDimensionUpperLimit() {
        return mSmallerDimensionUpperLimit;
    }

    /**
        * Returns the range of supported frame rates.
        * <p>
        * This is not a performance indicator.  Rather, it expresses the
        * limits specified in the coding standard, based on the complexities
        * of encoding material for later playback at a certain frame rate,
        * or the decoding of such material in non-realtime.
        */
    public Range<Integer> getSupportedFrameRates() {
        return mFrameRateRange;
    }

    /**
        * Returns the range of supported video widths for a video height.
        * @param height the height of the video
        */
    public Range<Integer> getSupportedWidthsFor(int height) {
        try {
            Range<Integer> range = mWidthRange;
            if (!mHeightRange.contains(height)
                    || (height % mHeightAlignment) != 0) {
                throw new IllegalArgumentException("unsupported height");
            }
            final int heightInBlocks = Utils.divUp(height, mBlockHeight);

            // constrain by block count and by block aspect ratio
            final int minWidthInBlocks = Math.max(
                    Utils.divUp(mBlockCountRange.getLower(), heightInBlocks),
                    (int)Math.ceil(mBlockAspectRatioRange.getLower().doubleValue()
                            * heightInBlocks));
            final int maxWidthInBlocks = Math.min(
                    mBlockCountRange.getUpper() / heightInBlocks,
                    (int)(mBlockAspectRatioRange.getUpper().doubleValue()
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
                    (int)Math.ceil(mAspectRatioRange.getLower().doubleValue()
                            * height),
                    (int)(mAspectRatioRange.getUpper().doubleValue() * height));
            return range;
        } catch (IllegalArgumentException e) {
            // height is not supported because there are no suitable widths
            Log.v(TAG, "could not get supported widths for " + height);
            throw new IllegalArgumentException("unsupported height");
        }
    }

    /**
        * Returns the range of supported video heights for a video width
        * @param width the width of the video
        */
    public Range<Integer> getSupportedHeightsFor(int width) {
        try {
            Range<Integer> range = mHeightRange;
            if (!mWidthRange.contains(width)
                    || (width % mWidthAlignment) != 0) {
                throw new IllegalArgumentException("unsupported width");
            }
            final int widthInBlocks = Utils.divUp(width, mBlockWidth);

            // constrain by block count and by block aspect ratio
            final int minHeightInBlocks = Math.max(
                    Utils.divUp(mBlockCountRange.getLower(), widthInBlocks),
                    (int)Math.ceil(widthInBlocks /
                            mBlockAspectRatioRange.getUpper().doubleValue()));
            final int maxHeightInBlocks = Math.min(
                    mBlockCountRange.getUpper() / widthInBlocks,
                    (int)(widthInBlocks /
                            mBlockAspectRatioRange.getLower().doubleValue()));
            range = range.intersect(
                    (minHeightInBlocks - 1) * mBlockHeight + mHeightAlignment,
                    maxHeightInBlocks * mBlockHeight);

            // constrain by smaller dimension limit
            if (width > mSmallerDimensionUpperLimit) {
                range = range.intersect(1, mSmallerDimensionUpperLimit);
            }

            // constrain by aspect ratio
            range = range.intersect(
                    (int)Math.ceil(width /
                            mAspectRatioRange.getUpper().doubleValue()),
                    (int)(width / mAspectRatioRange.getLower().doubleValue()));
            return range;
        } catch (IllegalArgumentException e) {
            // width is not supported because there are no suitable heights
            Log.v(TAG, "could not get supported heights for " + width);
            throw new IllegalArgumentException("unsupported width");
        }
    }

    /**
        * Returns the range of supported video frame rates for a video size.
        * <p>
        * This is not a performance indicator.  Rather, it expresses the limits specified in
        * the coding standard, based on the complexities of encoding material of a given
        * size for later playback at a certain frame rate, or the decoding of such material
        * in non-realtime.

        * @param width the width of the video
        * @param height the height of the video
        */
    public Range<Double> getSupportedFrameRatesFor(int width, int height) {
        Range<Integer> range = mHeightRange;
        if (!supports(width, height, null)) {
            throw new IllegalArgumentException("unsupported size");
        }
        final int blockCount =
            Utils.divUp(width, mBlockWidth) * Utils.divUp(height, mBlockHeight);

        return Range.create(
                Math.max(mBlocksPerSecondRange.getLower() / (double) blockCount,
                        (double) mFrameRateRange.getLower()),
                Math.min(mBlocksPerSecondRange.getUpper() / (double) blockCount,
                        (double) mFrameRateRange.getUpper()));
    }

    private int getBlockCount(int width, int height) {
        return Utils.divUp(width, mBlockWidth) * Utils.divUp(height, mBlockHeight);
    }

    @NonNull
    private Size findClosestSize(int width, int height) {
        int targetBlockCount = getBlockCount(width, height);
        Size closestSize = null;
        int minDiff = Integer.MAX_VALUE;
        for (Size size : mMeasuredFrameRates.keySet()) {
            int diff = Math.abs(targetBlockCount -
                    getBlockCount(size.getWidth(), size.getHeight()));
            if (diff < minDiff) {
                minDiff = diff;
                closestSize = size;
            }
        }
        return closestSize;
    }

    private Range<Double> estimateFrameRatesFor(int width, int height) {
        Size size = findClosestSize(width, height);
        Range<Long> range = mMeasuredFrameRates.get(size);
        Double ratio = getBlockCount(size.getWidth(), size.getHeight())
                / (double)Math.max(getBlockCount(width, height), 1);
        return Range.create(range.getLower() * ratio, range.getUpper() * ratio);
    }

    /**
    * Returns the range of achievable video frame rates for a video size.
    * May return {@code null}, if the codec did not publish any measurement
    * data.
    * <p>
    * This is a performance estimate provided by the device manufacturer based on statistical
    * sampling of full-speed decoding and encoding measurements in various configurations
    * of common video sizes supported by the codec. As such it should only be used to
    * compare individual codecs on the device. The value is not suitable for comparing
    * different devices or even different android releases for the same device.
    * <p>
    * <em>On {@link android.os.Build.VERSION_CODES#M} release</em> the returned range
    * corresponds to the fastest frame rates achieved in the tested configurations. As
    * such, it should not be used to gauge guaranteed or even average codec performance
    * on the device.
    * <p>
    * <em>On {@link android.os.Build.VERSION_CODES#N} release</em> the returned range
    * corresponds closer to sustained performance <em>in tested configurations</em>.
    * One can expect to achieve sustained performance higher than the lower limit more than
    * 50% of the time, and higher than half of the lower limit at least 90% of the time
    * <em>in tested configurations</em>.
    * Conversely, one can expect performance lower than twice the upper limit at least
    * 90% of the time.
    * <p class=note>
    * Tested configurations use a single active codec. For use cases where multiple
    * codecs are active, applications can expect lower and in most cases significantly lower
    * performance.
    * <p class=note>
    * The returned range value is interpolated from the nearest frame size(s) tested.
    * Codec performance is severely impacted by other activity on the device as well
    * as environmental factors (such as battery level, temperature or power source), and can
    * vary significantly even in a steady environment.
    * <p class=note>
    * Use this method in cases where only codec performance matters, e.g. to evaluate if
    * a codec has any chance of meeting a performance target. Codecs are listed
    * in {@link MediaCodecList} in the preferred order as defined by the device
    * manufacturer. As such, applications should use the first suitable codec in the
    * list to achieve the best balance between power use and performance.
    *
    * @param width the width of the video
    * @param height the height of the video
    *
    * @throws IllegalArgumentException if the video size is not supported.
    */
    @Nullable
    public Range<Double> getAchievableFrameRatesFor(int width, int height) {
        if (!supports(width, height, null)) {
            throw new IllegalArgumentException("unsupported size");
        }

        if (mMeasuredFrameRates == null || mMeasuredFrameRates.size() <= 0) {
            Log.w(TAG, "Codec did not publish any measurement data.");
            return null;
        }

        return estimateFrameRatesFor(width, height);
    }

    /**
     * Video performance points are a set of standard performance points defined by number of
     * pixels, pixel rate and frame rate. Performance point represents an upper bound. This
     * means that it covers all performance points with fewer pixels, pixel rate and frame
     * rate.
     */
    public static final class PerformancePoint {
        private Size mBlockSize; // codec block size in macroblocks
        private int mWidth; // width in macroblocks
        private int mHeight; // height in macroblocks
        private int mMaxFrameRate; // max frames per second
        private long mMaxMacroBlockRate; // max macro block rate

        /**
        * Maximum number of macroblocks in the frame.
        *
        * Video frames are conceptually divided into 16-by-16 pixel blocks called macroblocks.
        * Most coding standards operate on these 16-by-16 pixel blocks; thus, codec performance
        * is characterized using such blocks.
        *
        * @hide
        */
        @TestApi
        public int getMaxMacroBlocks() {
            return saturateLongToInt(mWidth * (long)mHeight);
        }

        /**
        * Maximum frame rate in frames per second.
        *
        * @hide
        */
        @TestApi
        public int getMaxFrameRate() {
            return mMaxFrameRate;
        }

        /**
        * Maximum number of macroblocks processed per second.
        *
        * @hide
        */
        @TestApi
        public long getMaxMacroBlockRate() {
            return mMaxMacroBlockRate;
        }

        /** Convert to a debug string */
        public String toString() {
            int blockWidth = 16 * mBlockSize.getWidth();
            int blockHeight = 16 * mBlockSize.getHeight();
            int origRate = (int)Utils.divUp(mMaxMacroBlockRate, getMaxMacroBlocks());
            String info = (mWidth * 16) + "x" + (mHeight * 16) + "@" + origRate;
            if (origRate < mMaxFrameRate) {
                info += ", max " + mMaxFrameRate + "fps";
            }
            if (blockWidth > 16 || blockHeight > 16) {
                info += ", " + blockWidth + "x" + blockHeight + " blocks";
            }
            return "PerformancePoint(" + info + ")";
        }

        @Override
        public int hashCode() {
            // only max frame rate must equal between performance points that equal to one
            // another
            return mMaxFrameRate;
        }

        /**
        * Create a detailed performance point with custom max frame rate and macroblock size.
        *
        * @param width  frame width in pixels
        * @param height frame height in pixels
        * @param frameRate frames per second for frame width and height
        * @param maxFrameRate maximum frames per second for any frame size
        * @param blockSize block size for codec implementation. Must be powers of two in both
        *        width and height.
        *
        * @throws IllegalArgumentException if the blockSize dimensions are not powers of two.
        *
        * @hide
        */
        @TestApi
        public PerformancePoint(
                int width, int height, int frameRate, int maxFrameRate,
                @NonNull Size blockSize) {
            checkPowerOfTwo(blockSize.getWidth(), "block width");
            checkPowerOfTwo(blockSize.getHeight(), "block height");

            mBlockSize = new Size(Utils.divUp(blockSize.getWidth(), 16),
                                    Utils.divUp(blockSize.getHeight(), 16));
            // these are guaranteed not to overflow as we decimate by 16
            mWidth = (int)(Utils.divUp(Math.max(1L, width),
                                        Math.max(blockSize.getWidth(), 16))
                            * mBlockSize.getWidth());
            mHeight = (int)(Utils.divUp(Math.max(1L, height),
                                        Math.max(blockSize.getHeight(), 16))
                            * mBlockSize.getHeight());
            mMaxFrameRate = Math.max(1, Math.max(frameRate, maxFrameRate));
            mMaxMacroBlockRate = Math.max(1, frameRate) * getMaxMacroBlocks();
        }

        /**
        * Convert a performance point to a larger blocksize.
        *
        * @param pp performance point
        * @param blockSize block size for codec implementation
        *
        * @hide
        */
        @TestApi
        public PerformancePoint(@NonNull PerformancePoint pp, @NonNull Size newBlockSize) {
            this(
                    pp.mWidth * 16, pp.mHeight * 16,
                    // guaranteed not to overflow as these were multiplied at construction
                    (int)Utils.divUp(pp.mMaxMacroBlockRate, pp.getMaxMacroBlocks()),
                    pp.mMaxFrameRate,
                    new Size(Math.max(newBlockSize.getWidth(), pp.mBlockSize.getWidth() * 16),
                                Math.max(newBlockSize.getHeight(), pp.mBlockSize.getHeight() * 16))
            );
        }

        /**
        * Create a performance point for a given frame size and frame rate.
        *
        * @param width width of the frame in pixels
        * @param height height of the frame in pixels
        * @param frameRate frame rate in frames per second
        */
        public PerformancePoint(int width, int height, int frameRate) {
            this(width, height, frameRate, frameRate /* maxFrameRate */, new Size(16, 16));
        }

        /** Saturates a long value to int */
        private int saturateLongToInt(long value) {
            if (value < Integer.MIN_VALUE) {
                return Integer.MIN_VALUE;
            } else if (value > Integer.MAX_VALUE) {
                return Integer.MAX_VALUE;
            } else {
                return (int)value;
            }
        }

        /* This method may overflow */
        private int align(int value, int alignment) {
            return Utils.divUp(value, alignment) * alignment;
        }

        /** Checks that value is a power of two. */
        private void checkPowerOfTwo2(int value, @NonNull String description) {
            if (value == 0 || (value & (value - 1)) != 0) {
                throw new IllegalArgumentException(
                        description + " (" + value + ") must be a power of 2");
            }
        }

        /**
        * Checks whether the performance point covers a media format.
        *
        * @param format Stream format considered
        *
        * @return {@code true} if the performance point covers the format.
        */
        public boolean covers(@NonNull MediaFormat format) {
            PerformancePoint other = new PerformancePoint(
                    format.getInteger(MediaFormat.KEY_WIDTH, 0),
                    format.getInteger(MediaFormat.KEY_HEIGHT, 0),
                    // safely convert ceil(double) to int through float cast and Math.round
                    Math.round((float)(
                            Math.ceil(format.getNumber(MediaFormat.KEY_FRAME_RATE, 0)
                                    .doubleValue()))));
            return covers(other);
        }

        /**
        * Checks whether the performance point covers another performance point. Use this
        * method to determine if a performance point advertised by a codec covers the
        * performance point required. This method can also be used for loose ordering as this
        * method is transitive.
        *
        * @param other other performance point considered
        *
        * @return {@code true} if the performance point covers the other.
        */
        public boolean covers(@NonNull PerformancePoint other) {
            // convert performance points to common block size
            Size commonSize = getCommonBlockSize(other);
            PerformancePoint aligned = new PerformancePoint(this, commonSize);
            PerformancePoint otherAligned = new PerformancePoint(other, commonSize);

            return (aligned.getMaxMacroBlocks() >= otherAligned.getMaxMacroBlocks()
                    && aligned.mMaxFrameRate >= otherAligned.mMaxFrameRate
                    && aligned.mMaxMacroBlockRate >= otherAligned.mMaxMacroBlockRate);
        }

        private @NonNull Size getCommonBlockSize(@NonNull PerformancePoint other) {
            return new Size(
                    Math.max(mBlockSize.getWidth(), other.mBlockSize.getWidth()) * 16,
                    Math.max(mBlockSize.getHeight(), other.mBlockSize.getHeight()) * 16);
        }

        @Override
        public boolean equals(Object o) {
            if (o instanceof PerformancePoint) {
                // convert performance points to common block size
                PerformancePoint other = (PerformancePoint)o;
                Size commonSize = getCommonBlockSize(other);
                PerformancePoint aligned = new PerformancePoint(this, commonSize);
                PerformancePoint otherAligned = new PerformancePoint(other, commonSize);

                return (aligned.getMaxMacroBlocks() == otherAligned.getMaxMacroBlocks()
                        && aligned.mMaxFrameRate == otherAligned.mMaxFrameRate
                        && aligned.mMaxMacroBlockRate == otherAligned.mMaxMacroBlockRate);
            }
            return false;
        }

        /** 480p 24fps */
        @NonNull
        public static final PerformancePoint SD_24 = new PerformancePoint(720, 480, 24);
        /** 576p 25fps */
        @NonNull
        public static final PerformancePoint SD_25 = new PerformancePoint(720, 576, 25);
        /** 480p 30fps */
        @NonNull
        public static final PerformancePoint SD_30 = new PerformancePoint(720, 480, 30);
        /** 480p 48fps */
        @NonNull
        public static final PerformancePoint SD_48 = new PerformancePoint(720, 480, 48);
        /** 576p 50fps */
        @NonNull
        public static final PerformancePoint SD_50 = new PerformancePoint(720, 576, 50);
        /** 480p 60fps */
        @NonNull
        public static final PerformancePoint SD_60 = new PerformancePoint(720, 480, 60);

        /** 720p 24fps */
        @NonNull
        public static final PerformancePoint HD_24 = new PerformancePoint(1280, 720, 24);
        /** 720p 25fps */
        @NonNull
        public static final PerformancePoint HD_25 = new PerformancePoint(1280, 720, 25);
        /** 720p 30fps */
        @NonNull
        public static final PerformancePoint HD_30 = new PerformancePoint(1280, 720, 30);
        /** 720p 50fps */
        @NonNull
        public static final PerformancePoint HD_50 = new PerformancePoint(1280, 720, 50);
        /** 720p 60fps */
        @NonNull
        public static final PerformancePoint HD_60 = new PerformancePoint(1280, 720, 60);
        /** 720p 100fps */
        @NonNull
        public static final PerformancePoint HD_100 = new PerformancePoint(1280, 720, 100);
        /** 720p 120fps */
        @NonNull
        public static final PerformancePoint HD_120 = new PerformancePoint(1280, 720, 120);
        /** 720p 200fps */
        @NonNull
        public static final PerformancePoint HD_200 = new PerformancePoint(1280, 720, 200);
        /** 720p 240fps */
        @NonNull
        public static final PerformancePoint HD_240 = new PerformancePoint(1280, 720, 240);

        /** 1080p 24fps */
        @NonNull
        public static final PerformancePoint FHD_24 = new PerformancePoint(1920, 1080, 24);
        /** 1080p 25fps */
        @NonNull
        public static final PerformancePoint FHD_25 = new PerformancePoint(1920, 1080, 25);
        /** 1080p 30fps */
        @NonNull
        public static final PerformancePoint FHD_30 = new PerformancePoint(1920, 1080, 30);
        /** 1080p 50fps */
        @NonNull
        public static final PerformancePoint FHD_50 = new PerformancePoint(1920, 1080, 50);
        /** 1080p 60fps */
        @NonNull
        public static final PerformancePoint FHD_60 = new PerformancePoint(1920, 1080, 60);
        /** 1080p 100fps */
        @NonNull
        public static final PerformancePoint FHD_100 = new PerformancePoint(1920, 1080, 100);
        /** 1080p 120fps */
        @NonNull
        public static final PerformancePoint FHD_120 = new PerformancePoint(1920, 1080, 120);
        /** 1080p 200fps */
        @NonNull
        public static final PerformancePoint FHD_200 = new PerformancePoint(1920, 1080, 200);
        /** 1080p 240fps */
        @NonNull
        public static final PerformancePoint FHD_240 = new PerformancePoint(1920, 1080, 240);

        /** 2160p 24fps */
        @NonNull
        public static final PerformancePoint UHD_24 = new PerformancePoint(3840, 2160, 24);
        /** 2160p 25fps */
        @NonNull
        public static final PerformancePoint UHD_25 = new PerformancePoint(3840, 2160, 25);
        /** 2160p 30fps */
        @NonNull
        public static final PerformancePoint UHD_30 = new PerformancePoint(3840, 2160, 30);
        /** 2160p 50fps */
        @NonNull
        public static final PerformancePoint UHD_50 = new PerformancePoint(3840, 2160, 50);
        /** 2160p 60fps */
        @NonNull
        public static final PerformancePoint UHD_60 = new PerformancePoint(3840, 2160, 60);
        /** 2160p 100fps */
        @NonNull
        public static final PerformancePoint UHD_100 = new PerformancePoint(3840, 2160, 100);
        /** 2160p 120fps */
        @NonNull
        public static final PerformancePoint UHD_120 = new PerformancePoint(3840, 2160, 120);
        /** 2160p 200fps */
        @NonNull
        public static final PerformancePoint UHD_200 = new PerformancePoint(3840, 2160, 200);
        /** 2160p 240fps */
        @NonNull
        public static final PerformancePoint UHD_240 = new PerformancePoint(3840, 2160, 240);
    }

    /**
    * Returns the supported performance points. May return {@code null} if the codec did not
    * publish any performance point information (e.g. the vendor codecs have not been updated
    * to the latest android release). May return an empty list if the codec published that
    * if does not guarantee any performance points.
    * <p>
    * This is a performance guarantee provided by the device manufacturer for hardware codecs
    * based on hardware capabilities of the device.
    * <p>
    * The returned list is sorted first by decreasing number of pixels, then by decreasing
    * width, and finally by decreasing frame rate.
    * Performance points assume a single active codec. For use cases where multiple
    * codecs are active, should use that highest pixel count, and add the frame rates of
    * each individual codec.
    * <p class=note>
    * 32-bit processes will not support resolutions larger than 4096x4096 due to
    * the limited address space, but performance points will be presented as is.
    * In other words, even though a component publishes a performance point for
    * a resolution higher than 4096x4096, it does not mean that the resolution is supported
    * for 32-bit processes.
        */
    @Nullable
    public List<PerformancePoint> getSupportedPerformancePoints() {
        return mPerformancePoints;
    }

    /**
    * Returns whether a given video size ({@code width} and
    * {@code height}) and {@code frameRate} combination is supported.
    */
    public boolean areSizeAndRateSupported(
            int width, int height, double frameRate) {
        return supports(width, height, frameRate);
    }

    /**
    * Returns whether a given video size ({@code width} and
    * {@code height}) is supported.
    */
    public boolean isSizeSupported(int width, int height) {
        return supports(width, height, null);
    }

    private boolean supports(Integer width, Integer height, Number rate) {
        boolean ok = true;

        if (ok && width != null) {
            ok = mWidthRange.contains(width)
                    && (width % mWidthAlignment == 0);
        }
        if (ok && height != null) {
            ok = mHeightRange.contains(height)
                    && (height % mHeightAlignment == 0);
        }
        if (ok && rate != null) {
            ok = mFrameRateRange.contains(Utils.intRangeFor(rate.doubleValue()));
        }
        if (ok && height != null && width != null) {
            ok = Math.min(height, width) <= mSmallerDimensionUpperLimit;

            final int widthInBlocks = Utils.divUp(width, mBlockWidth);
            final int heightInBlocks = Utils.divUp(height, mBlockHeight);
            final int blockCount = widthInBlocks * heightInBlocks;
            ok = ok && mBlockCountRange.contains(blockCount)
                    && mBlockAspectRatioRange.contains(
                            new Rational(widthInBlocks, heightInBlocks))
                    && mAspectRatioRange.contains(new Rational(width, height));
            if (ok && rate != null) {
                double blocksPerSec = blockCount * rate.doubleValue();
                ok = mBlocksPerSecondRange.contains(
                        Utils.longRangeFor(blocksPerSec));
            }
        }
        return ok;
    }

    /* package private */
    // must not contain KEY_PROFILE
    static final Set<String> VIDEO_LEVEL_CRITICAL_FORMAT_KEYS = Set.of(
            MediaFormat.KEY_WIDTH,
            MediaFormat.KEY_HEIGHT,
            MediaFormat.KEY_FRAME_RATE,
            MediaFormat.KEY_BIT_RATE,
            MediaFormat.KEY_MIME);

    /**
    * @hide
    * @throws java.lang.ClassCastException */
    public boolean supportsFormat(MediaFormat format) {
        final Map<String, Object> map = format.getMap();
        Integer width = (Integer)map.get(MediaFormat.KEY_WIDTH);
        Integer height = (Integer)map.get(MediaFormat.KEY_HEIGHT);
        Number rate = (Number)map.get(MediaFormat.KEY_FRAME_RATE);

        if (!supports(width, height, rate)) {
            return false;
        }

        if (!CodecCapabilities.supportsBitrate(mBitrateRange, format)) {
            return false;
        }

        // we ignore color-format for now as it is not reliably reported by codec
        return true;
    }

    /* no public constructor */
    private VideoCapabilities() { }

    /** @hide */
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.P, trackingBug = 115609023)
    public static VideoCapabilities create(
            MediaFormat info, CodecCapabilities parent) {
        VideoCapabilities caps = new VideoCapabilities();
        caps.init(info, parent);
        return caps;
    }

    private void init(MediaFormat info, CodecCapabilities parent) {
        mParent = parent;
        initWithPlatformLimits();
        applyLevelLimits();
        parseFromInfo(info);
        updateLimits();
    }

    /** @hide */
    public Size getBlockSize() {
        return new Size(mBlockWidth, mBlockHeight);
    }

    /** @hide */
    public Range<Integer> getBlockCountRange() {
        return mBlockCountRange;
    }

    /** @hide */
    public Range<Long> getBlocksPerSecondRange() {
        return mBlocksPerSecondRange;
    }

    /** @hide */
    public Range<Rational> getAspectRatioRange(boolean blocks) {
        return blocks ? mBlockAspectRatioRange : mAspectRatioRange;
    }

    private void initWithPlatformLimits() {
        mBitrateRange = BITRATE_RANGE;

        mWidthRange  = getSizeRange();
        mHeightRange = getSizeRange();
        mFrameRateRange = FRAME_RATE_RANGE;

        mHorizontalBlockRange = getSizeRange();
        mVerticalBlockRange   = getSizeRange();

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
        mSmallerDimensionUpperLimit = getSizeRange().getUpper();
    }

    private @Nullable List<PerformancePoint> getPerformancePoints(Map<String, Object> map) {
        Vector<PerformancePoint> ret = new Vector<>();
        final String prefix = "performance-point-";
        Set<String> keys = map.keySet();
        for (String key : keys) {
            // looking for: performance-point-WIDTHxHEIGHT-range
            if (!key.startsWith(prefix)) {
                continue;
            }
            String subKey = key.substring(prefix.length());
            if (subKey.equals("none") && ret.size() == 0) {
                // This means that component knowingly did not publish performance points.
                // This is different from when the component forgot to publish performance
                // points.
                return Collections.unmodifiableList(ret);
            }
            String[] temp = key.split("-");
            if (temp.length != 4) {
                continue;
            }
            String sizeStr = temp[2];
            Size size = Utils.parseSize(sizeStr, null);
            if (size == null || size.getWidth() * size.getHeight() <= 0) {
                continue;
            }
            Range<Long> range = Utils.parseLongRange(map.get(key), null);
            if (range == null || range.getLower() < 0 || range.getUpper() < 0) {
                continue;
            }
            PerformancePoint given = new PerformancePoint(
                    size.getWidth(), size.getHeight(), range.getLower().intValue(),
                    range.getUpper().intValue(), new Size(mBlockWidth, mBlockHeight));
            PerformancePoint rotated = new PerformancePoint(
                    size.getHeight(), size.getWidth(), range.getLower().intValue(),
                    range.getUpper().intValue(), new Size(mBlockWidth, mBlockHeight));
            ret.add(given);
            if (!given.covers(rotated)) {
                ret.add(rotated);
            }
        }

        // check if the component specified no performance point indication
        if (ret.size() == 0) {
            return null;
        }

        // sort reversed by area first, then by frame rate
        ret.sort((a, b) ->
                    -((a.getMaxMacroBlocks() != b.getMaxMacroBlocks()) ?
                            (a.getMaxMacroBlocks() < b.getMaxMacroBlocks() ? -1 : 1) :
                    (a.getMaxMacroBlockRate() != b.getMaxMacroBlockRate()) ?
                            (a.getMaxMacroBlockRate() < b.getMaxMacroBlockRate() ? -1 : 1) :
                    (a.getMaxFrameRate() != b.getMaxFrameRate()) ?
                            (a.getMaxFrameRate() < b.getMaxFrameRate() ? -1 : 1) : 0));

        return Collections.unmodifiableList(ret);
    }

    private Map<Size, Range<Long>> getMeasuredFrameRates(Map<String, Object> map) {
        Map<Size, Range<Long>> ret = new HashMap<Size, Range<Long>>();
        final String prefix = "measured-frame-rate-";
        Set<String> keys = map.keySet();
        for (String key : keys) {
            // looking for: measured-frame-rate-WIDTHxHEIGHT-range
            if (!key.startsWith(prefix)) {
                continue;
            }
            String subKey = key.substring(prefix.length());
            String[] temp = key.split("-");
            if (temp.length != 5) {
                continue;
            }
            String sizeStr = temp[3];
            Size size = Utils.parseSize(sizeStr, null);
            if (size == null || size.getWidth() * size.getHeight() <= 0) {
                continue;
            }
            Range<Long> range = Utils.parseLongRange(map.get(key), null);
            if (range == null || range.getLower() < 0 || range.getUpper() < 0) {
                continue;
            }
            ret.put(size, range);
        }
        return ret;
    }

    private static Pair<Range<Integer>, Range<Integer>> parseWidthHeightRanges(Object o) {
        Pair<Size, Size> range = Utils.parseSizeRange(o);
        if (range != null) {
            try {
                return Pair.create(
                        Range.create(range.first.getWidth(), range.second.getWidth()),
                        Range.create(range.first.getHeight(), range.second.getHeight()));
            } catch (IllegalArgumentException e) {
                Log.w(TAG, "could not parse size range '" + o + "'");
            }
        }
        return null;
    }

    /** @hide */
    public static int equivalentVP9Level(MediaFormat info) {
        final Map<String, Object> map = info.getMap();

        Size blockSize = Utils.parseSize(map.get("block-size"), new Size(8, 8));
        int BS = blockSize.getWidth() * blockSize.getHeight();

        Range<Integer> counts = Utils.parseIntRange(map.get("block-count-range"), null);
        int FS = counts == null ? 0 : BS * counts.getUpper();

        Range<Long> blockRates =
            Utils.parseLongRange(map.get("blocks-per-second-range"), null);
        long SR = blockRates == null ? 0 : BS * blockRates.getUpper();

        Pair<Range<Integer>, Range<Integer>> dimensionRanges =
            parseWidthHeightRanges(map.get("size-range"));
        int D = dimensionRanges == null ? 0 : Math.max(
                dimensionRanges.first.getUpper(), dimensionRanges.second.getUpper());

        Range<Integer> bitRates = Utils.parseIntRange(map.get("bitrate-range"), null);
        int BR = bitRates == null ? 0 : Utils.divUp(bitRates.getUpper(), 1000);

        if (SR <=      829440 && FS <=    36864 && BR <=    200 && D <=   512)
            return CodecProfileLevel.VP9Level1;
        if (SR <=     2764800 && FS <=    73728 && BR <=    800 && D <=   768)
            return CodecProfileLevel.VP9Level11;
        if (SR <=     4608000 && FS <=   122880 && BR <=   1800 && D <=   960)
            return CodecProfileLevel.VP9Level2;
        if (SR <=     9216000 && FS <=   245760 && BR <=   3600 && D <=  1344)
            return CodecProfileLevel.VP9Level21;
        if (SR <=    20736000 && FS <=   552960 && BR <=   7200 && D <=  2048)
            return CodecProfileLevel.VP9Level3;
        if (SR <=    36864000 && FS <=   983040 && BR <=  12000 && D <=  2752)
            return CodecProfileLevel.VP9Level31;
        if (SR <=    83558400 && FS <=  2228224 && BR <=  18000 && D <=  4160)
            return CodecProfileLevel.VP9Level4;
        if (SR <=   160432128 && FS <=  2228224 && BR <=  30000 && D <=  4160)
            return CodecProfileLevel.VP9Level41;
        if (SR <=   311951360 && FS <=  8912896 && BR <=  60000 && D <=  8384)
            return CodecProfileLevel.VP9Level5;
        if (SR <=   588251136 && FS <=  8912896 && BR <= 120000 && D <=  8384)
            return CodecProfileLevel.VP9Level51;
        if (SR <=  1176502272 && FS <=  8912896 && BR <= 180000 && D <=  8384)
            return CodecProfileLevel.VP9Level52;
        if (SR <=  1176502272 && FS <= 35651584 && BR <= 180000 && D <= 16832)
            return CodecProfileLevel.VP9Level6;
        if (SR <= 2353004544L && FS <= 35651584 && BR <= 240000 && D <= 16832)
            return CodecProfileLevel.VP9Level61;
        if (SR <= 4706009088L && FS <= 35651584 && BR <= 480000 && D <= 16832)
            return CodecProfileLevel.VP9Level62;
        // returning largest level
        return CodecProfileLevel.VP9Level62;
    }

    private void parseFromInfo(MediaFormat info) {
        final Map<String, Object> map = info.getMap();
        Size blockSize = new Size(mBlockWidth, mBlockHeight);
        Size alignment = new Size(mWidthAlignment, mHeightAlignment);
        Range<Integer> counts = null, widths = null, heights = null;
        Range<Integer> frameRates = null, bitRates = null;
        Range<Long> blockRates = null;
        Range<Rational> ratios = null, blockRatios = null;

        blockSize = Utils.parseSize(map.get("block-size"), blockSize);
        alignment = Utils.parseSize(map.get("alignment"), alignment);
        counts = Utils.parseIntRange(map.get("block-count-range"), null);
        blockRates =
            Utils.parseLongRange(map.get("blocks-per-second-range"), null);
        mMeasuredFrameRates = getMeasuredFrameRates(map);
        mPerformancePoints = getPerformancePoints(map);
        Pair<Range<Integer>, Range<Integer>> sizeRanges =
            parseWidthHeightRanges(map.get("size-range"));
        if (sizeRanges != null) {
            widths = sizeRanges.first;
            heights = sizeRanges.second;
        }
        // for now this just means using the smaller max size as 2nd
        // upper limit.
        // for now we are keeping the profile specific "width/height
        // in macroblocks" limits.
        if (map.containsKey("feature-can-swap-width-height")) {
            if (widths != null) {
                mSmallerDimensionUpperLimit =
                    Math.min(widths.getUpper(), heights.getUpper());
                widths = heights = widths.extend(heights);
            } else {
                Log.w(TAG, "feature can-swap-width-height is best used with size-range");
                mSmallerDimensionUpperLimit =
                    Math.min(mWidthRange.getUpper(), mHeightRange.getUpper());
                mWidthRange = mHeightRange = mWidthRange.extend(mHeightRange);
            }
        }

        ratios = Utils.parseRationalRange(
                map.get("block-aspect-ratio-range"), null);
        blockRatios = Utils.parseRationalRange(
                map.get("pixel-aspect-ratio-range"), null);
        frameRates = Utils.parseIntRange(map.get("frame-rate-range"), null);
        if (frameRates != null) {
            try {
                frameRates = frameRates.intersect(FRAME_RATE_RANGE);
            } catch (IllegalArgumentException e) {
                Log.w(TAG, "frame rate range (" + frameRates
                        + ") is out of limits: " + FRAME_RATE_RANGE);
                frameRates = null;
            }
        }
        bitRates = Utils.parseIntRange(map.get("bitrate-range"), null);
        if (bitRates != null) {
            try {
                bitRates = bitRates.intersect(BITRATE_RANGE);
            } catch (IllegalArgumentException e) {
                Log.w(TAG,  "bitrate range (" + bitRates
                        + ") is out of limits: " + BITRATE_RANGE);
                bitRates = null;
            }
        }

        checkPowerOfTwo(
                blockSize.getWidth(), "block-size width must be power of two");
        checkPowerOfTwo(
                blockSize.getHeight(), "block-size height must be power of two");

        checkPowerOfTwo(
                alignment.getWidth(), "alignment width must be power of two");
        checkPowerOfTwo(
                alignment.getHeight(), "alignment height must be power of two");

        // update block-size and alignment
        applyMacroBlockLimits(
                Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE,
                Long.MAX_VALUE, blockSize.getWidth(), blockSize.getHeight(),
                alignment.getWidth(), alignment.getHeight());

        if ((mParent.mError & ERROR_UNSUPPORTED) != 0 || mAllowMbOverride) {
            // codec supports profiles that we don't know.
            // Use supplied values clipped to platform limits
            if (widths != null) {
                mWidthRange = getSizeRange().intersect(widths);
            }
            if (heights != null) {
                mHeightRange = getSizeRange().intersect(heights);
            }
            if (counts != null) {
                mBlockCountRange = POSITIVE_INTEGERS.intersect(
                        Utils.factorRange(counts, mBlockWidth * mBlockHeight
                                / blockSize.getWidth() / blockSize.getHeight()));
            }
            if (blockRates != null) {
                mBlocksPerSecondRange = POSITIVE_LONGS.intersect(
                        Utils.factorRange(blockRates, mBlockWidth * mBlockHeight
                                / blockSize.getWidth() / blockSize.getHeight()));
            }
            if (blockRatios != null) {
                mBlockAspectRatioRange = POSITIVE_RATIONALS.intersect(
                        Utils.scaleRange(blockRatios,
                                mBlockHeight / blockSize.getHeight(),
                                mBlockWidth / blockSize.getWidth()));
            }
            if (ratios != null) {
                mAspectRatioRange = POSITIVE_RATIONALS.intersect(ratios);
            }
            if (frameRates != null) {
                mFrameRateRange = FRAME_RATE_RANGE.intersect(frameRates);
            }
            if (bitRates != null) {
                // only allow bitrate override if unsupported profiles were encountered
                if ((mParent.mError & ERROR_UNSUPPORTED) != 0) {
                    mBitrateRange = BITRATE_RANGE.intersect(bitRates);
                } else {
                    mBitrateRange = mBitrateRange.intersect(bitRates);
                }
            }
        } else {
            // no unsupported profile/levels, so restrict values to known limits
            if (widths != null) {
                mWidthRange = mWidthRange.intersect(widths);
            }
            if (heights != null) {
                mHeightRange = mHeightRange.intersect(heights);
            }
            if (counts != null) {
                mBlockCountRange = mBlockCountRange.intersect(
                        Utils.factorRange(counts, mBlockWidth * mBlockHeight
                                / blockSize.getWidth() / blockSize.getHeight()));
            }
            if (blockRates != null) {
                mBlocksPerSecondRange = mBlocksPerSecondRange.intersect(
                        Utils.factorRange(blockRates, mBlockWidth * mBlockHeight
                                / blockSize.getWidth() / blockSize.getHeight()));
            }
            if (blockRatios != null) {
                mBlockAspectRatioRange = mBlockAspectRatioRange.intersect(
                        Utils.scaleRange(blockRatios,
                                mBlockHeight / blockSize.getHeight(),
                                mBlockWidth / blockSize.getWidth()));
            }
            if (ratios != null) {
                mAspectRatioRange = mAspectRatioRange.intersect(ratios);
            }
            if (frameRates != null) {
                mFrameRateRange = mFrameRateRange.intersect(frameRates);
            }
            if (bitRates != null) {
                mBitrateRange = mBitrateRange.intersect(bitRates);
            }
        }
        updateLimits();
    }

    private void applyBlockLimits(
            int blockWidth, int blockHeight,
            Range<Integer> counts, Range<Long> rates, Range<Rational> ratios) {
        checkPowerOfTwo(blockWidth, "blockWidth must be a power of two");
        checkPowerOfTwo(blockHeight, "blockHeight must be a power of two");

        final int newBlockWidth = Math.max(blockWidth, mBlockWidth);
        final int newBlockHeight = Math.max(blockHeight, mBlockHeight);

        // factor will always be a power-of-2
        int factor =
            newBlockWidth * newBlockHeight / mBlockWidth / mBlockHeight;
        if (factor != 1) {
            mBlockCountRange = Utils.factorRange(mBlockCountRange, factor);
            mBlocksPerSecondRange = Utils.factorRange(
                    mBlocksPerSecondRange, factor);
            mBlockAspectRatioRange = Utils.scaleRange(
                    mBlockAspectRatioRange,
                    newBlockHeight / mBlockHeight,
                    newBlockWidth / mBlockWidth);
            mHorizontalBlockRange = Utils.factorRange(
                    mHorizontalBlockRange, newBlockWidth / mBlockWidth);
            mVerticalBlockRange = Utils.factorRange(
                    mVerticalBlockRange, newBlockHeight / mBlockHeight);
        }
        factor = newBlockWidth * newBlockHeight / blockWidth / blockHeight;
        if (factor != 1) {
            counts = Utils.factorRange(counts, factor);
            rates = Utils.factorRange(rates, factor);
            ratios = Utils.scaleRange(
                    ratios, newBlockHeight / blockHeight,
                    newBlockWidth / blockWidth);
        }
        mBlockCountRange = mBlockCountRange.intersect(counts);
        mBlocksPerSecondRange = mBlocksPerSecondRange.intersect(rates);
        mBlockAspectRatioRange = mBlockAspectRatioRange.intersect(ratios);
        mBlockWidth = newBlockWidth;
        mBlockHeight = newBlockHeight;
    }

    private void applyAlignment(int widthAlignment, int heightAlignment) {
        checkPowerOfTwo(widthAlignment, "widthAlignment must be a power of two");
        checkPowerOfTwo(heightAlignment, "heightAlignment must be a power of two");

        if (widthAlignment > mBlockWidth || heightAlignment > mBlockHeight) {
            // maintain assumption that 0 < alignment <= block-size
            applyBlockLimits(
                    Math.max(widthAlignment, mBlockWidth),
                    Math.max(heightAlignment, mBlockHeight),
                    POSITIVE_INTEGERS, POSITIVE_LONGS, POSITIVE_RATIONALS);
        }

        mWidthAlignment = Math.max(widthAlignment, mWidthAlignment);
        mHeightAlignment = Math.max(heightAlignment, mHeightAlignment);

        mWidthRange = Utils.alignRange(mWidthRange, mWidthAlignment);
        mHeightRange = Utils.alignRange(mHeightRange, mHeightAlignment);
    }

    private void updateLimits() {
        // pixels -> blocks <- counts
        mHorizontalBlockRange = mHorizontalBlockRange.intersect(
                Utils.factorRange(mWidthRange, mBlockWidth));
        mHorizontalBlockRange = mHorizontalBlockRange.intersect(
                Range.create(
                        mBlockCountRange.getLower() / mVerticalBlockRange.getUpper(),
                        mBlockCountRange.getUpper() / mVerticalBlockRange.getLower()));
        mVerticalBlockRange = mVerticalBlockRange.intersect(
                Utils.factorRange(mHeightRange, mBlockHeight));
        mVerticalBlockRange = mVerticalBlockRange.intersect(
                Range.create(
                        mBlockCountRange.getLower() / mHorizontalBlockRange.getUpper(),
                        mBlockCountRange.getUpper() / mHorizontalBlockRange.getLower()));
        mBlockCountRange = mBlockCountRange.intersect(
                Range.create(
                        mHorizontalBlockRange.getLower()
                                * mVerticalBlockRange.getLower(),
                        mHorizontalBlockRange.getUpper()
                                * mVerticalBlockRange.getUpper()));
        mBlockAspectRatioRange = mBlockAspectRatioRange.intersect(
                new Rational(
                        mHorizontalBlockRange.getLower(), mVerticalBlockRange.getUpper()),
                new Rational(
                        mHorizontalBlockRange.getUpper(), mVerticalBlockRange.getLower()));

        // blocks -> pixels
        mWidthRange = mWidthRange.intersect(
                (mHorizontalBlockRange.getLower() - 1) * mBlockWidth + mWidthAlignment,
                mHorizontalBlockRange.getUpper() * mBlockWidth);
        mHeightRange = mHeightRange.intersect(
                (mVerticalBlockRange.getLower() - 1) * mBlockHeight + mHeightAlignment,
                mVerticalBlockRange.getUpper() * mBlockHeight);
        mAspectRatioRange = mAspectRatioRange.intersect(
                new Rational(mWidthRange.getLower(), mHeightRange.getUpper()),
                new Rational(mWidthRange.getUpper(), mHeightRange.getLower()));

        mSmallerDimensionUpperLimit = Math.min(
                mSmallerDimensionUpperLimit,
                Math.min(mWidthRange.getUpper(), mHeightRange.getUpper()));

        // blocks -> rate
        mBlocksPerSecondRange = mBlocksPerSecondRange.intersect(
                mBlockCountRange.getLower() * (long)mFrameRateRange.getLower(),
                mBlockCountRange.getUpper() * (long)mFrameRateRange.getUpper());
        mFrameRateRange = mFrameRateRange.intersect(
                (int)(mBlocksPerSecondRange.getLower()
                        / mBlockCountRange.getUpper()),
                (int)(mBlocksPerSecondRange.getUpper()
                        / (double)mBlockCountRange.getLower()));
    }

    private void applyMacroBlockLimits(
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

    private void applyMacroBlockLimits(
            int minHorizontalBlocks, int minVerticalBlocks,
            int maxHorizontalBlocks, int maxVerticalBlocks,
            int maxBlocks, long maxBlocksPerSecond,
            int blockWidth, int blockHeight,
            int widthAlignment, int heightAlignment) {
        applyAlignment(widthAlignment, heightAlignment);
        applyBlockLimits(
                blockWidth, blockHeight, Range.create(1, maxBlocks),
                Range.create(1L, maxBlocksPerSecond),
                Range.create(
                        new Rational(1, maxVerticalBlocks),
                        new Rational(maxHorizontalBlocks, 1)));
        mHorizontalBlockRange =
                mHorizontalBlockRange.intersect(
                        Utils.divUp(minHorizontalBlocks, (mBlockWidth / blockWidth)),
                        maxHorizontalBlocks / (mBlockWidth / blockWidth));
        mVerticalBlockRange =
                mVerticalBlockRange.intersect(
                        Utils.divUp(minVerticalBlocks, (mBlockHeight / blockHeight)),
                        maxVerticalBlocks / (mBlockHeight / blockHeight));
    }

    private void applyLevelLimits() {
        long maxBlocksPerSecond = 0;
        int maxBlocks = 0;
        int maxBps = 0;
        int maxDPBBlocks = 0;

        int errors = ERROR_NONE_SUPPORTED;
        CodecProfileLevel[] profileLevels = mParent.profileLevels;
        String mime = mParent.getMimeType();

        if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_VIDEO_AVC)) {
            maxBlocks = 99;
            maxBlocksPerSecond = 1485;
            maxBps = 64000;
            maxDPBBlocks = 396;
            for (CodecProfileLevel profileLevel: profileLevels) {
                int MBPS = 0, FS = 0, BR = 0, DPB = 0;
                boolean supported = true;
                switch (profileLevel.level) {
                    case CodecProfileLevel.AVCLevel1:
                        MBPS =     1485; FS =     99; BR =     64; DPB =    396; break;
                    case CodecProfileLevel.AVCLevel1b:
                        MBPS =     1485; FS =     99; BR =    128; DPB =    396; break;
                    case CodecProfileLevel.AVCLevel11:
                        MBPS =     3000; FS =    396; BR =    192; DPB =    900; break;
                    case CodecProfileLevel.AVCLevel12:
                        MBPS =     6000; FS =    396; BR =    384; DPB =   2376; break;
                    case CodecProfileLevel.AVCLevel13:
                        MBPS =    11880; FS =    396; BR =    768; DPB =   2376; break;
                    case CodecProfileLevel.AVCLevel2:
                        MBPS =    11880; FS =    396; BR =   2000; DPB =   2376; break;
                    case CodecProfileLevel.AVCLevel21:
                        MBPS =    19800; FS =    792; BR =   4000; DPB =   4752; break;
                    case CodecProfileLevel.AVCLevel22:
                        MBPS =    20250; FS =   1620; BR =   4000; DPB =   8100; break;
                    case CodecProfileLevel.AVCLevel3:
                        MBPS =    40500; FS =   1620; BR =  10000; DPB =   8100; break;
                    case CodecProfileLevel.AVCLevel31:
                        MBPS =   108000; FS =   3600; BR =  14000; DPB =  18000; break;
                    case CodecProfileLevel.AVCLevel32:
                        MBPS =   216000; FS =   5120; BR =  20000; DPB =  20480; break;
                    case CodecProfileLevel.AVCLevel4:
                        MBPS =   245760; FS =   8192; BR =  20000; DPB =  32768; break;
                    case CodecProfileLevel.AVCLevel41:
                        MBPS =   245760; FS =   8192; BR =  50000; DPB =  32768; break;
                    case CodecProfileLevel.AVCLevel42:
                        MBPS =   522240; FS =   8704; BR =  50000; DPB =  34816; break;
                    case CodecProfileLevel.AVCLevel5:
                        MBPS =   589824; FS =  22080; BR = 135000; DPB = 110400; break;
                    case CodecProfileLevel.AVCLevel51:
                        MBPS =   983040; FS =  36864; BR = 240000; DPB = 184320; break;
                    case CodecProfileLevel.AVCLevel52:
                        MBPS =  2073600; FS =  36864; BR = 240000; DPB = 184320; break;
                    case CodecProfileLevel.AVCLevel6:
                        MBPS =  4177920; FS = 139264; BR = 240000; DPB = 696320; break;
                    case CodecProfileLevel.AVCLevel61:
                        MBPS =  8355840; FS = 139264; BR = 480000; DPB = 696320; break;
                    case CodecProfileLevel.AVCLevel62:
                        MBPS = 16711680; FS = 139264; BR = 800000; DPB = 696320; break;
                    default:
                        Log.w(TAG, "Unrecognized level "
                                + profileLevel.level + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }
                switch (profileLevel.profile) {
                    case CodecProfileLevel.AVCProfileConstrainedHigh:
                    case CodecProfileLevel.AVCProfileHigh:
                        BR *= 1250; break;
                    case CodecProfileLevel.AVCProfileHigh10:
                        BR *= 3000; break;
                    case CodecProfileLevel.AVCProfileExtended:
                    case CodecProfileLevel.AVCProfileHigh422:
                    case CodecProfileLevel.AVCProfileHigh444:
                        Log.w(TAG, "Unsupported profile "
                                + profileLevel.profile + " for " + mime);
                        errors |= ERROR_UNSUPPORTED;
                        supported = false;
                        // fall through - treat as base profile
                    case CodecProfileLevel.AVCProfileConstrainedBaseline:
                    case CodecProfileLevel.AVCProfileBaseline:
                    case CodecProfileLevel.AVCProfileMain:
                        BR *= 1000; break;
                    default:
                        Log.w(TAG, "Unrecognized profile "
                                + profileLevel.profile + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                        BR *= 1000;
                }
                if (supported) {
                    errors &= ~ERROR_NONE_SUPPORTED;
                }
                maxBlocksPerSecond = Math.max(MBPS, maxBlocksPerSecond);
                maxBlocks = Math.max(FS, maxBlocks);
                maxBps = Math.max(BR, maxBps);
                maxDPBBlocks = Math.max(maxDPBBlocks, DPB);
            }

            int maxLengthInBlocks = (int)(Math.sqrt(maxBlocks * 8));
            applyMacroBlockLimits(
                    maxLengthInBlocks, maxLengthInBlocks,
                    maxBlocks, maxBlocksPerSecond,
                    16 /* blockWidth */, 16 /* blockHeight */,
                    1 /* widthAlignment */, 1 /* heightAlignment */);
        } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_VIDEO_MPEG2)) {
            int maxWidth = 11, maxHeight = 9, maxRate = 15;
            maxBlocks = 99;
            maxBlocksPerSecond = 1485;
            maxBps = 64000;
            for (CodecProfileLevel profileLevel: profileLevels) {
                int MBPS = 0, FS = 0, BR = 0, FR = 0, W = 0, H = 0;
                boolean supported = true;
                switch (profileLevel.profile) {
                    case CodecProfileLevel.MPEG2ProfileSimple:
                        switch (profileLevel.level) {
                            case CodecProfileLevel.MPEG2LevelML:
                                FR = 30; W = 45; H =  36; MBPS =  40500; FS =  1620; BR =  15000; break;
                            default:
                                Log.w(TAG, "Unrecognized profile/level "
                                        + profileLevel.profile + "/"
                                        + profileLevel.level + " for " + mime);
                                errors |= ERROR_UNRECOGNIZED;
                        }
                        break;
                    case CodecProfileLevel.MPEG2ProfileMain:
                        switch (profileLevel.level) {
                            case CodecProfileLevel.MPEG2LevelLL:
                                FR = 30; W = 22; H =  18; MBPS =  11880; FS =   396; BR =  4000; break;
                            case CodecProfileLevel.MPEG2LevelML:
                                FR = 30; W = 45; H =  36; MBPS =  40500; FS =  1620; BR = 15000; break;
                            case CodecProfileLevel.MPEG2LevelH14:
                                FR = 60; W = 90; H =  68; MBPS = 183600; FS =  6120; BR = 60000; break;
                            case CodecProfileLevel.MPEG2LevelHL:
                                FR = 60; W = 120; H = 68; MBPS = 244800; FS =  8160; BR = 80000; break;
                            case CodecProfileLevel.MPEG2LevelHP:
                                FR = 60; W = 120; H = 68; MBPS = 489600; FS =  8160; BR = 80000; break;
                            default:
                                Log.w(TAG, "Unrecognized profile/level "
                                        + profileLevel.profile + "/"
                                        + profileLevel.level + " for " + mime);
                                errors |= ERROR_UNRECOGNIZED;
                        }
                        break;
                    case CodecProfileLevel.MPEG2Profile422:
                    case CodecProfileLevel.MPEG2ProfileSNR:
                    case CodecProfileLevel.MPEG2ProfileSpatial:
                    case CodecProfileLevel.MPEG2ProfileHigh:
                        Log.i(TAG, "Unsupported profile "
                                + profileLevel.profile + " for " + mime);
                        errors |= ERROR_UNSUPPORTED;
                        supported = false;
                        break;
                    default:
                        Log.w(TAG, "Unrecognized profile "
                                + profileLevel.profile + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }
                if (supported) {
                    errors &= ~ERROR_NONE_SUPPORTED;
                }
                maxBlocksPerSecond = Math.max(MBPS, maxBlocksPerSecond);
                maxBlocks = Math.max(FS, maxBlocks);
                maxBps = Math.max(BR * 1000, maxBps);
                maxWidth = Math.max(W, maxWidth);
                maxHeight = Math.max(H, maxHeight);
                maxRate = Math.max(FR, maxRate);
            }
            applyMacroBlockLimits(maxWidth, maxHeight,
                    maxBlocks, maxBlocksPerSecond,
                    16 /* blockWidth */, 16 /* blockHeight */,
                    1 /* widthAlignment */, 1 /* heightAlignment */);
            mFrameRateRange = mFrameRateRange.intersect(12, maxRate);
        } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_VIDEO_MPEG4)) {
            int maxWidth = 11, maxHeight = 9, maxRate = 15;
            maxBlocks = 99;
            maxBlocksPerSecond = 1485;
            maxBps = 64000;
            for (CodecProfileLevel profileLevel: profileLevels) {
                int MBPS = 0, FS = 0, BR = 0, FR = 0, W = 0, H = 0;
                boolean strict = false; // true: W, H and FR are individual max limits
                boolean supported = true;
                switch (profileLevel.profile) {
                    case CodecProfileLevel.MPEG4ProfileSimple:
                        switch (profileLevel.level) {
                            case CodecProfileLevel.MPEG4Level0:
                                strict = true;
                                FR = 15; W = 11; H =  9; MBPS =  1485; FS =  99; BR =  64; break;
                            case CodecProfileLevel.MPEG4Level1:
                                FR = 30; W = 11; H =  9; MBPS =  1485; FS =  99; BR =  64; break;
                            case CodecProfileLevel.MPEG4Level0b:
                                strict = true;
                                FR = 15; W = 11; H =  9; MBPS =  1485; FS =  99; BR = 128; break;
                            case CodecProfileLevel.MPEG4Level2:
                                FR = 30; W = 22; H = 18; MBPS =  5940; FS = 396; BR = 128; break;
                            case CodecProfileLevel.MPEG4Level3:
                                FR = 30; W = 22; H = 18; MBPS = 11880; FS = 396; BR = 384; break;
                            case CodecProfileLevel.MPEG4Level4a:
                                FR = 30; W = 40; H = 30; MBPS = 36000; FS = 1200; BR = 4000; break;
                            case CodecProfileLevel.MPEG4Level5:
                                FR = 30; W = 45; H = 36; MBPS = 40500; FS = 1620; BR = 8000; break;
                            case CodecProfileLevel.MPEG4Level6:
                                FR = 30; W = 80; H = 45; MBPS = 108000; FS = 3600; BR = 12000; break;
                            default:
                                Log.w(TAG, "Unrecognized profile/level "
                                        + profileLevel.profile + "/"
                                        + profileLevel.level + " for " + mime);
                                errors |= ERROR_UNRECOGNIZED;
                        }
                        break;
                    case CodecProfileLevel.MPEG4ProfileAdvancedSimple:
                        switch (profileLevel.level) {
                            case CodecProfileLevel.MPEG4Level0:
                            case CodecProfileLevel.MPEG4Level1:
                                FR = 30; W = 11; H =  9; MBPS =  2970; FS =   99; BR =  128; break;
                            case CodecProfileLevel.MPEG4Level2:
                                FR = 30; W = 22; H = 18; MBPS =  5940; FS =  396; BR =  384; break;
                            case CodecProfileLevel.MPEG4Level3:
                                FR = 30; W = 22; H = 18; MBPS = 11880; FS =  396; BR =  768; break;
                            case CodecProfileLevel.MPEG4Level3b:
                                FR = 30; W = 22; H = 18; MBPS = 11880; FS =  396; BR = 1500; break;
                            case CodecProfileLevel.MPEG4Level4:
                                FR = 30; W = 44; H = 36; MBPS = 23760; FS =  792; BR = 3000; break;
                            case CodecProfileLevel.MPEG4Level5:
                                FR = 30; W = 45; H = 36; MBPS = 48600; FS = 1620; BR = 8000; break;
                            default:
                                Log.w(TAG, "Unrecognized profile/level "
                                        + profileLevel.profile + "/"
                                        + profileLevel.level + " for " + mime);
                                errors |= ERROR_UNRECOGNIZED;
                        }
                        break;
                    case CodecProfileLevel.MPEG4ProfileMain:             // 2-4
                    case CodecProfileLevel.MPEG4ProfileNbit:             // 2
                    case CodecProfileLevel.MPEG4ProfileAdvancedRealTime: // 1-4
                    case CodecProfileLevel.MPEG4ProfileCoreScalable:     // 1-3
                    case CodecProfileLevel.MPEG4ProfileAdvancedCoding:   // 1-4
                    case CodecProfileLevel.MPEG4ProfileCore:             // 1-2
                    case CodecProfileLevel.MPEG4ProfileAdvancedCore:     // 1-4
                    case CodecProfileLevel.MPEG4ProfileSimpleScalable:   // 0-2
                    case CodecProfileLevel.MPEG4ProfileHybrid:           // 1-2

                    // Studio profiles are not supported by our codecs.

                    // Only profiles that can decode simple object types are considered.
                    // The following profiles are not able to.
                    case CodecProfileLevel.MPEG4ProfileBasicAnimated:    // 1-2
                    case CodecProfileLevel.MPEG4ProfileScalableTexture:  // 1
                    case CodecProfileLevel.MPEG4ProfileSimpleFace:       // 1-2
                    case CodecProfileLevel.MPEG4ProfileAdvancedScalable: // 1-3
                    case CodecProfileLevel.MPEG4ProfileSimpleFBA:        // 1-2
                        Log.i(TAG, "Unsupported profile "
                                + profileLevel.profile + " for " + mime);
                        errors |= ERROR_UNSUPPORTED;
                        supported = false;
                        break;
                    default:
                        Log.w(TAG, "Unrecognized profile "
                                + profileLevel.profile + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }
                if (supported) {
                    errors &= ~ERROR_NONE_SUPPORTED;
                }
                maxBlocksPerSecond = Math.max(MBPS, maxBlocksPerSecond);
                maxBlocks = Math.max(FS, maxBlocks);
                maxBps = Math.max(BR * 1000, maxBps);
                if (strict) {
                    maxWidth = Math.max(W, maxWidth);
                    maxHeight = Math.max(H, maxHeight);
                    maxRate = Math.max(FR, maxRate);
                } else {
                    // assuming max 60 fps frame rate and 1:2 aspect ratio
                    int maxDim = (int)Math.sqrt(FS * 2);
                    maxWidth = Math.max(maxDim, maxWidth);
                    maxHeight = Math.max(maxDim, maxHeight);
                    maxRate = Math.max(Math.max(FR, 60), maxRate);
                }
            }
            applyMacroBlockLimits(maxWidth, maxHeight,
                    maxBlocks, maxBlocksPerSecond,
                    16 /* blockWidth */, 16 /* blockHeight */,
                    1 /* widthAlignment */, 1 /* heightAlignment */);
            mFrameRateRange = mFrameRateRange.intersect(12, maxRate);
        } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_VIDEO_H263)) {
            int maxWidth = 11, maxHeight = 9, maxRate = 15;
            int minWidth = maxWidth, minHeight = maxHeight;
            int minAlignment = 16;
            maxBlocks = 99;
            maxBlocksPerSecond = 1485;
            maxBps = 64000;
            for (CodecProfileLevel profileLevel: profileLevels) {
                int MBPS = 0, BR = 0, FR = 0, W = 0, H = 0, minW = minWidth, minH = minHeight;
                boolean strict = false; // true: support only sQCIF, QCIF (maybe CIF)
                switch (profileLevel.level) {
                    case CodecProfileLevel.H263Level10:
                        strict = true; // only supports sQCIF & QCIF
                        FR = 15; W = 11; H =  9; BR =   1; MBPS =  W * H * FR; break;
                    case CodecProfileLevel.H263Level20:
                        strict = true; // only supports sQCIF, QCIF & CIF
                        FR = 30; W = 22; H = 18; BR =   2; MBPS =  W * H * 15; break;
                    case CodecProfileLevel.H263Level30:
                        strict = true; // only supports sQCIF, QCIF & CIF
                        FR = 30; W = 22; H = 18; BR =   6; MBPS =  W * H * FR; break;
                    case CodecProfileLevel.H263Level40:
                        strict = true; // only supports sQCIF, QCIF & CIF
                        FR = 30; W = 22; H = 18; BR =  32; MBPS =  W * H * FR; break;
                    case CodecProfileLevel.H263Level45:
                        // only implies level 10 support
                        strict = profileLevel.profile == CodecProfileLevel.H263ProfileBaseline
                                || profileLevel.profile ==
                                        CodecProfileLevel.H263ProfileBackwardCompatible;
                        if (!strict) {
                            minW = 1; minH = 1; minAlignment = 4;
                        }
                        FR = 15; W = 11; H =  9; BR =   2; MBPS =  W * H * FR; break;
                    case CodecProfileLevel.H263Level50:
                        // only supports 50fps for H > 15
                        minW = 1; minH = 1; minAlignment = 4;
                        FR = 60; W = 22; H = 18; BR =  64; MBPS =  W * H * 50; break;
                    case CodecProfileLevel.H263Level60:
                        // only supports 50fps for H > 15
                        minW = 1; minH = 1; minAlignment = 4;
                        FR = 60; W = 45; H = 18; BR = 128; MBPS =  W * H * 50; break;
                    case CodecProfileLevel.H263Level70:
                        // only supports 50fps for H > 30
                        minW = 1; minH = 1; minAlignment = 4;
                        FR = 60; W = 45; H = 36; BR = 256; MBPS =  W * H * 50; break;
                    default:
                        Log.w(TAG, "Unrecognized profile/level " + profileLevel.profile
                                + "/" + profileLevel.level + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }
                switch (profileLevel.profile) {
                    case CodecProfileLevel.H263ProfileBackwardCompatible:
                    case CodecProfileLevel.H263ProfileBaseline:
                    case CodecProfileLevel.H263ProfileH320Coding:
                    case CodecProfileLevel.H263ProfileHighCompression:
                    case CodecProfileLevel.H263ProfileHighLatency:
                    case CodecProfileLevel.H263ProfileInterlace:
                    case CodecProfileLevel.H263ProfileInternet:
                    case CodecProfileLevel.H263ProfileISWV2:
                    case CodecProfileLevel.H263ProfileISWV3:
                        break;
                    default:
                        Log.w(TAG, "Unrecognized profile "
                                + profileLevel.profile + " for " + mime);
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
                errors &= ~ERROR_NONE_SUPPORTED;
                maxBlocksPerSecond = Math.max(MBPS, maxBlocksPerSecond);
                maxBlocks = Math.max(W * H, maxBlocks);
                maxBps = Math.max(BR * 64000, maxBps);
                maxWidth = Math.max(W, maxWidth);
                maxHeight = Math.max(H, maxHeight);
                maxRate = Math.max(FR, maxRate);
                minWidth = Math.min(minW, minWidth);
                minHeight = Math.min(minH, minHeight);
            }
            // unless we encountered custom frame size support, limit size to QCIF and CIF
            // using aspect ratio.
            if (!mAllowMbOverride) {
                mBlockAspectRatioRange =
                    Range.create(new Rational(11, 9), new Rational(11, 9));
            }
            applyMacroBlockLimits(
                    minWidth, minHeight,
                    maxWidth, maxHeight,
                    maxBlocks, maxBlocksPerSecond,
                    16 /* blockWidth */, 16 /* blockHeight */,
                    minAlignment /* widthAlignment */, minAlignment /* heightAlignment */);
            mFrameRateRange = Range.create(1, maxRate);
        } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_VIDEO_VP8)) {
            maxBlocks = Integer.MAX_VALUE;
            maxBlocksPerSecond = Integer.MAX_VALUE;

            // TODO: set to 100Mbps for now, need a number for VP8
            maxBps = 100000000;

            // profile levels are not indicative for VPx, but verify
            // them nonetheless
            for (CodecProfileLevel profileLevel: profileLevels) {
                switch (profileLevel.level) {
                    case CodecProfileLevel.VP8Level_Version0:
                    case CodecProfileLevel.VP8Level_Version1:
                    case CodecProfileLevel.VP8Level_Version2:
                    case CodecProfileLevel.VP8Level_Version3:
                        break;
                    default:
                        Log.w(TAG, "Unrecognized level "
                                + profileLevel.level + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }
                switch (profileLevel.profile) {
                    case CodecProfileLevel.VP8ProfileMain:
                        break;
                    default:
                        Log.w(TAG, "Unrecognized profile "
                                + profileLevel.profile + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }
                errors &= ~ERROR_NONE_SUPPORTED;
            }

            final int blockSize = 16;
            applyMacroBlockLimits(Short.MAX_VALUE, Short.MAX_VALUE,
                    maxBlocks, maxBlocksPerSecond, blockSize, blockSize,
                    1 /* widthAlignment */, 1 /* heightAlignment */);
        } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_VIDEO_VP9)) {
            maxBlocksPerSecond = 829440;
            maxBlocks = 36864;
            maxBps = 200000;
            int maxDim = 512;

            for (CodecProfileLevel profileLevel: profileLevels) {
                long SR = 0; // luma sample rate
                int FS = 0;  // luma picture size
                int BR = 0;  // bit rate kbps
                int D = 0;   // luma dimension
                switch (profileLevel.level) {
                    case CodecProfileLevel.VP9Level1:
                        SR =      829440; FS =    36864; BR =    200; D =   512; break;
                    case CodecProfileLevel.VP9Level11:
                        SR =     2764800; FS =    73728; BR =    800; D =   768; break;
                    case CodecProfileLevel.VP9Level2:
                        SR =     4608000; FS =   122880; BR =   1800; D =   960; break;
                    case CodecProfileLevel.VP9Level21:
                        SR =     9216000; FS =   245760; BR =   3600; D =  1344; break;
                    case CodecProfileLevel.VP9Level3:
                        SR =    20736000; FS =   552960; BR =   7200; D =  2048; break;
                    case CodecProfileLevel.VP9Level31:
                        SR =    36864000; FS =   983040; BR =  12000; D =  2752; break;
                    case CodecProfileLevel.VP9Level4:
                        SR =    83558400; FS =  2228224; BR =  18000; D =  4160; break;
                    case CodecProfileLevel.VP9Level41:
                        SR =   160432128; FS =  2228224; BR =  30000; D =  4160; break;
                    case CodecProfileLevel.VP9Level5:
                        SR =   311951360; FS =  8912896; BR =  60000; D =  8384; break;
                    case CodecProfileLevel.VP9Level51:
                        SR =   588251136; FS =  8912896; BR = 120000; D =  8384; break;
                    case CodecProfileLevel.VP9Level52:
                        SR =  1176502272; FS =  8912896; BR = 180000; D =  8384; break;
                    case CodecProfileLevel.VP9Level6:
                        SR =  1176502272; FS = 35651584; BR = 180000; D = 16832; break;
                    case CodecProfileLevel.VP9Level61:
                        SR = 2353004544L; FS = 35651584; BR = 240000; D = 16832; break;
                    case CodecProfileLevel.VP9Level62:
                        SR = 4706009088L; FS = 35651584; BR = 480000; D = 16832; break;
                    default:
                        Log.w(TAG, "Unrecognized level "
                                + profileLevel.level + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }
                switch (profileLevel.profile) {
                    case CodecProfileLevel.VP9Profile0:
                    case CodecProfileLevel.VP9Profile1:
                    case CodecProfileLevel.VP9Profile2:
                    case CodecProfileLevel.VP9Profile3:
                    case CodecProfileLevel.VP9Profile2HDR:
                    case CodecProfileLevel.VP9Profile3HDR:
                    case CodecProfileLevel.VP9Profile2HDR10Plus:
                    case CodecProfileLevel.VP9Profile3HDR10Plus:
                        break;
                    default:
                        Log.w(TAG, "Unrecognized profile "
                                + profileLevel.profile + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }
                errors &= ~ERROR_NONE_SUPPORTED;
                maxBlocksPerSecond = Math.max(SR, maxBlocksPerSecond);
                maxBlocks = Math.max(FS, maxBlocks);
                maxBps = Math.max(BR * 1000, maxBps);
                maxDim = Math.max(D, maxDim);
            }

            final int blockSize = 8;
            int maxLengthInBlocks = Utils.divUp(maxDim, blockSize);
            maxBlocks = Utils.divUp(maxBlocks, blockSize * blockSize);
            maxBlocksPerSecond = Utils.divUp(maxBlocksPerSecond, blockSize * blockSize);

            applyMacroBlockLimits(
                    maxLengthInBlocks, maxLengthInBlocks,
                    maxBlocks, maxBlocksPerSecond,
                    blockSize, blockSize,
                    1 /* widthAlignment */, 1 /* heightAlignment */);
        } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_VIDEO_HEVC)) {
            // CTBs are at least 8x8 so use 8x8 block size
            maxBlocks = 36864 >> 6; // 192x192 pixels == 576 8x8 blocks
            maxBlocksPerSecond = maxBlocks * 15;
            maxBps = 128000;
            for (CodecProfileLevel profileLevel: profileLevels) {
                double FR = 0;
                int FS = 0;
                int BR = 0;
                switch (profileLevel.level) {
                    /* The HEVC spec talks only in a very convoluted manner about the
                        existence of levels 1-3.1 for High tier, which could also be
                        understood as 'decoders and encoders should treat these levels
                        as if they were Main tier', so we do that. */
                    case CodecProfileLevel.HEVCMainTierLevel1:
                    case CodecProfileLevel.HEVCHighTierLevel1:
                        FR =    15; FS =    36864; BR =    128; break;
                    case CodecProfileLevel.HEVCMainTierLevel2:
                    case CodecProfileLevel.HEVCHighTierLevel2:
                        FR =    30; FS =   122880; BR =   1500; break;
                    case CodecProfileLevel.HEVCMainTierLevel21:
                    case CodecProfileLevel.HEVCHighTierLevel21:
                        FR =    30; FS =   245760; BR =   3000; break;
                    case CodecProfileLevel.HEVCMainTierLevel3:
                    case CodecProfileLevel.HEVCHighTierLevel3:
                        FR =    30; FS =   552960; BR =   6000; break;
                    case CodecProfileLevel.HEVCMainTierLevel31:
                    case CodecProfileLevel.HEVCHighTierLevel31:
                        FR = 33.75; FS =   983040; BR =  10000; break;
                    case CodecProfileLevel.HEVCMainTierLevel4:
                        FR =    30; FS =  2228224; BR =  12000; break;
                    case CodecProfileLevel.HEVCHighTierLevel4:
                        FR =    30; FS =  2228224; BR =  30000; break;
                    case CodecProfileLevel.HEVCMainTierLevel41:
                        FR =    60; FS =  2228224; BR =  20000; break;
                    case CodecProfileLevel.HEVCHighTierLevel41:
                        FR =    60; FS =  2228224; BR =  50000; break;
                    case CodecProfileLevel.HEVCMainTierLevel5:
                        FR =    30; FS =  8912896; BR =  25000; break;
                    case CodecProfileLevel.HEVCHighTierLevel5:
                        FR =    30; FS =  8912896; BR = 100000; break;
                    case CodecProfileLevel.HEVCMainTierLevel51:
                        FR =    60; FS =  8912896; BR =  40000; break;
                    case CodecProfileLevel.HEVCHighTierLevel51:
                        FR =    60; FS =  8912896; BR = 160000; break;
                    case CodecProfileLevel.HEVCMainTierLevel52:
                        FR =   120; FS =  8912896; BR =  60000; break;
                    case CodecProfileLevel.HEVCHighTierLevel52:
                        FR =   120; FS =  8912896; BR = 240000; break;
                    case CodecProfileLevel.HEVCMainTierLevel6:
                        FR =    30; FS = 35651584; BR =  60000; break;
                    case CodecProfileLevel.HEVCHighTierLevel6:
                        FR =    30; FS = 35651584; BR = 240000; break;
                    case CodecProfileLevel.HEVCMainTierLevel61:
                        FR =    60; FS = 35651584; BR = 120000; break;
                    case CodecProfileLevel.HEVCHighTierLevel61:
                        FR =    60; FS = 35651584; BR = 480000; break;
                    case CodecProfileLevel.HEVCMainTierLevel62:
                        FR =   120; FS = 35651584; BR = 240000; break;
                    case CodecProfileLevel.HEVCHighTierLevel62:
                        FR =   120; FS = 35651584; BR = 800000; break;
                    default:
                        Log.w(TAG, "Unrecognized level "
                                + profileLevel.level + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }
                switch (profileLevel.profile) {
                    case CodecProfileLevel.HEVCProfileMain:
                    case CodecProfileLevel.HEVCProfileMain10:
                    case CodecProfileLevel.HEVCProfileMainStill:
                    case CodecProfileLevel.HEVCProfileMain10HDR10:
                    case CodecProfileLevel.HEVCProfileMain10HDR10Plus:
                        break;
                    default:
                        Log.w(TAG, "Unrecognized profile "
                                + profileLevel.profile + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }

                /* DPB logic:
                if      (width * height <= FS / 4)    DPB = 16;
                else if (width * height <= FS / 2)    DPB = 12;
                else if (width * height <= FS * 0.75) DPB = 8;
                else                                  DPB = 6;
                */

                FS >>= 6; // convert pixels to blocks
                errors &= ~ERROR_NONE_SUPPORTED;
                maxBlocksPerSecond = Math.max((int)(FR * FS), maxBlocksPerSecond);
                maxBlocks = Math.max(FS, maxBlocks);
                maxBps = Math.max(BR * 1000, maxBps);
            }

            int maxLengthInBlocks = (int)(Math.sqrt(maxBlocks * 8));
            applyMacroBlockLimits(
                    maxLengthInBlocks, maxLengthInBlocks,
                    maxBlocks, maxBlocksPerSecond,
                    8 /* blockWidth */, 8 /* blockHeight */,
                    1 /* widthAlignment */, 1 /* heightAlignment */);
        } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_VIDEO_AV1)) {
            maxBlocksPerSecond = 829440;
            maxBlocks = 36864;
            maxBps = 200000;
            int maxDim = 512;

            // Sample rate, Picture Size, Bit rate and luma dimension for AV1 Codec,
            // corresponding to the definitions in
            // "AV1 Bitstream & Decoding Process Specification", Annex A
            // found at https://aomedia.org/av1-bitstream-and-decoding-process-specification/
            for (CodecProfileLevel profileLevel: profileLevels) {
                long SR = 0; // luma sample rate
                int FS = 0;  // luma picture size
                int BR = 0;  // bit rate kbps
                int D = 0;   // luma D
                switch (profileLevel.level) {
                    case CodecProfileLevel.AV1Level2:
                        SR =     5529600; FS =   147456; BR =   1500; D =  2048; break;
                    case CodecProfileLevel.AV1Level21:
                    case CodecProfileLevel.AV1Level22:
                    case CodecProfileLevel.AV1Level23:
                        SR =    10454400; FS =   278784; BR =   3000; D =  2816; break;

                    case CodecProfileLevel.AV1Level3:
                        SR =    24969600; FS =   665856; BR =   6000; D =  4352; break;
                    case CodecProfileLevel.AV1Level31:
                    case CodecProfileLevel.AV1Level32:
                    case CodecProfileLevel.AV1Level33:
                        SR =    39938400; FS =  1065024; BR =  10000; D =  5504; break;

                    case CodecProfileLevel.AV1Level4:
                        SR =    77856768; FS =  2359296; BR =  12000; D =  6144; break;
                    case CodecProfileLevel.AV1Level41:
                    case CodecProfileLevel.AV1Level42:
                    case CodecProfileLevel.AV1Level43:
                        SR =   155713536; FS =  2359296; BR =  20000; D =  6144; break;

                    case CodecProfileLevel.AV1Level5:
                        SR =   273715200; FS =  8912896; BR =  30000; D =  8192; break;
                    case CodecProfileLevel.AV1Level51:
                        SR =   547430400; FS =  8912896; BR =  40000; D =  8192; break;
                    case CodecProfileLevel.AV1Level52:
                        SR =  1094860800; FS =  8912896; BR =  60000; D =  8192; break;
                    case CodecProfileLevel.AV1Level53:
                        SR =  1176502272; FS =  8912896; BR =  60000; D =  8192; break;

                    case CodecProfileLevel.AV1Level6:
                        SR =  1176502272; FS = 35651584; BR =  60000; D = 16384; break;
                    case CodecProfileLevel.AV1Level61:
                        SR = 2189721600L; FS = 35651584; BR = 100000; D = 16384; break;
                    case CodecProfileLevel.AV1Level62:
                        SR = 4379443200L; FS = 35651584; BR = 160000; D = 16384; break;
                    case CodecProfileLevel.AV1Level63:
                        SR = 4706009088L; FS = 35651584; BR = 160000; D = 16384; break;

                    default:
                        Log.w(TAG, "Unrecognized level "
                                + profileLevel.level + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }
                switch (profileLevel.profile) {
                    case CodecProfileLevel.AV1ProfileMain8:
                    case CodecProfileLevel.AV1ProfileMain10:
                    case CodecProfileLevel.AV1ProfileMain10HDR10:
                    case CodecProfileLevel.AV1ProfileMain10HDR10Plus:
                        break;
                    default:
                        Log.w(TAG, "Unrecognized profile "
                                + profileLevel.profile + " for " + mime);
                        errors |= ERROR_UNRECOGNIZED;
                }
                errors &= ~ERROR_NONE_SUPPORTED;
                maxBlocksPerSecond = Math.max(SR, maxBlocksPerSecond);
                maxBlocks = Math.max(FS, maxBlocks);
                maxBps = Math.max(BR * 1000, maxBps);
                maxDim = Math.max(D, maxDim);
            }

            final int blockSize = 8;
            int maxLengthInBlocks = Utils.divUp(maxDim, blockSize);
            maxBlocks = Utils.divUp(maxBlocks, blockSize * blockSize);
            maxBlocksPerSecond = Utils.divUp(maxBlocksPerSecond, blockSize * blockSize);
            applyMacroBlockLimits(
                    maxLengthInBlocks, maxLengthInBlocks,
                    maxBlocks, maxBlocksPerSecond,
                    blockSize, blockSize,
                    1 /* widthAlignment */, 1 /* heightAlignment */);
        } else {
            Log.w(TAG, "Unsupported mime " + mime);
            // using minimal bitrate here.  should be overriden by
            // info from media_codecs.xml
            maxBps = 64000;
            errors |= ERROR_UNSUPPORTED;
        }
        mBitrateRange = Range.create(1, maxBps);
        mParent.mError |= errors;
    }
}

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
