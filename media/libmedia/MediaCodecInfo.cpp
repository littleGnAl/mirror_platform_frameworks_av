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
#include <utils/Log.h>

#include <media/IOMX.h>

#include <media/MediaCodecInfo.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <binder/Parcel.h>

namespace android {

    /**
     * A class that supports querying the audio capabilities of a codec.
     */
    public static final class AudioCapabilities {
        private static final String TAG = "AudioCapabilities";
        private CodecCapabilities mParent;
        private Range<Integer> mBitrateRange;

        private int[] mSampleRates;
        private Range<Integer>[] mSampleRateRanges;
        private Range<Integer>[] mInputChannelRanges;

        private static final int MAX_INPUT_CHANNEL_COUNT = 30;

        /**
         * Returns the range of supported bitrates in bits/second.
         */
        public Range<Integer> getBitrateRange() {
            return mBitrateRange;
        }

        /**
         * Returns the array of supported sample rates if the codec
         * supports only discrete values.  Otherwise, it returns
         * {@code null}.  The array is sorted in ascending order.
         */
        public int[] getSupportedSampleRates() {
            return mSampleRates != null ? Arrays.copyOf(mSampleRates, mSampleRates.length) : null;
        }

        /**
         * Returns the array of supported sample rate ranges.  The
         * array is sorted in ascending order, and the ranges are
         * distinct.
         */
        public Range<Integer>[] getSupportedSampleRateRanges() {
            return Arrays.copyOf(mSampleRateRanges, mSampleRateRanges.length);
        }

        /**
         * Returns the maximum number of input channels supported.
         *
         * Through {@link android.os.Build.VERSION_CODES#R}, this method indicated support
         * for any number of input channels between 1 and this maximum value.
         *
         * As of {@link android.os.Build.VERSION_CODES#S},
         * the implied lower limit of 1 channel is no longer valid.
         * As of {@link android.os.Build.VERSION_CODES#S}, {@link #getMaxInputChannelCount} is
         * superseded by {@link #getInputChannelCountRanges},
         * which returns an array of ranges of channels.
         * The {@link #getMaxInputChannelCount} method will return the highest value
         * in the ranges returned by {@link #getInputChannelCountRanges}
         *
         */
        @IntRange(from = 1, to = 255)
        public int getMaxInputChannelCount() {
            int overall_max = 0;
            for (int i = mInputChannelRanges.length - 1; i >= 0; i--) {
                int lmax = mInputChannelRanges[i].getUpper();
                if (lmax > overall_max) {
                    overall_max = lmax;
                }
            }
            return overall_max;
        }

        /**
         * Returns the minimum number of input channels supported.
         * This is often 1, but does vary for certain mime types.
         *
         * This returns the lowest channel count in the ranges returned by
         * {@link #getInputChannelCountRanges}.
         */
        @IntRange(from = 1, to = 255)
        public int getMinInputChannelCount() {
            int overall_min = MAX_INPUT_CHANNEL_COUNT;
            for (int i = mInputChannelRanges.length - 1; i >= 0; i--) {
                int lmin = mInputChannelRanges[i].getLower();
                if (lmin < overall_min) {
                    overall_min = lmin;
                }
            }
            return overall_min;
        }

        /*
         * Returns an array of ranges representing the number of input channels supported.
         * The codec supports any number of input channels within this range.
         *
         * This supersedes the {@link #getMaxInputChannelCount} method.
         *
         * For many codecs, this will be a single range [1..N], for some N.
         */
        @SuppressLint("ArrayReturn")
        @NonNull
        public Range<Integer>[] getInputChannelCountRanges() {
            return Arrays.copyOf(mInputChannelRanges, mInputChannelRanges.length);
        }

        /* no public constructor */
        private AudioCapabilities() { }

        /** @hide */
        public static AudioCapabilities create(
                MediaFormat info, CodecCapabilities parent) {
            AudioCapabilities caps = new AudioCapabilities();
            caps.init(info, parent);
            return caps;
        }

        private void init(MediaFormat info, CodecCapabilities parent) {
            mParent = parent;
            initWithPlatformLimits();
            applyLevelLimits();
            parseFromInfo(info);
        }

        private void initWithPlatformLimits() {
            mBitrateRange = Range.create(0, Integer.MAX_VALUE);
            mInputChannelRanges = new Range[] {Range.create(1, MAX_INPUT_CHANNEL_COUNT)};
            // mBitrateRange = Range.create(1, 320000);
            final int minSampleRate = SystemProperties.
                getInt("ro.mediacodec.min_sample_rate", 7350);
            final int maxSampleRate = SystemProperties.
                getInt("ro.mediacodec.max_sample_rate", 192000);
            mSampleRateRanges = new Range[] { Range.create(minSampleRate, maxSampleRate) };
            mSampleRates = null;
        }

        private boolean supports(Integer sampleRate, Integer inputChannels) {
            // channels and sample rates are checked orthogonally
            if (inputChannels != null) {
                int ix = Utils.binarySearchDistinctRanges(
                        mInputChannelRanges, inputChannels);
                if (ix < 0) {
                    return false;
                }
            }
            if (sampleRate != null) {
                int ix = Utils.binarySearchDistinctRanges(
                        mSampleRateRanges, sampleRate);
                if (ix < 0) {
                    return false;
                }
            }
            return true;
        }

        /**
         * Query whether the sample rate is supported by the codec.
         */
        public boolean isSampleRateSupported(int sampleRate) {
            return supports(sampleRate, null);
        }

        /** modifies rates */
        private void limitSampleRates(int[] rates) {
            Arrays.sort(rates);
            ArrayList<Range<Integer>> ranges = new ArrayList<Range<Integer>>();
            for (int rate: rates) {
                if (supports(rate, null /* channels */)) {
                    ranges.add(Range.create(rate, rate));
                }
            }
            mSampleRateRanges = ranges.toArray(new Range[ranges.size()]);
            createDiscreteSampleRates();
        }

        private void createDiscreteSampleRates() {
            mSampleRates = new int[mSampleRateRanges.length];
            for (int i = 0; i < mSampleRateRanges.length; i++) {
                mSampleRates[i] = mSampleRateRanges[i].getLower();
            }
        }

        /** modifies rateRanges */
        private void limitSampleRates(Range<Integer>[] rateRanges) {
            sortDistinctRanges(rateRanges);
            mSampleRateRanges = intersectSortedDistinctRanges(mSampleRateRanges, rateRanges);

            // check if all values are discrete
            for (Range<Integer> range: mSampleRateRanges) {
                if (!range.getLower().equals(range.getUpper())) {
                    mSampleRates = null;
                    return;
                }
            }
            createDiscreteSampleRates();
        }

        private void applyLevelLimits() {
            int[] sampleRates = null;
            Range<Integer> sampleRateRange = null, bitRates = null;
            int maxChannels = MAX_INPUT_CHANNEL_COUNT;
            CodecProfileLevel[] profileLevels = mParent.profileLevels;
            String mime = mParent.getMimeType();

            if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_MPEG)) {
                sampleRates = new int[] {
                        8000, 11025, 12000,
                        16000, 22050, 24000,
                        32000, 44100, 48000 };
                bitRates = Range.create(8000, 320000);
                maxChannels = 2;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_AMR_NB)) {
                sampleRates = new int[] { 8000 };
                bitRates = Range.create(4750, 12200);
                maxChannels = 1;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_AMR_WB)) {
                sampleRates = new int[] { 16000 };
                bitRates = Range.create(6600, 23850);
                maxChannels = 1;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_AAC)) {
                sampleRates = new int[] {
                        7350, 8000,
                        11025, 12000, 16000,
                        22050, 24000, 32000,
                        44100, 48000, 64000,
                        88200, 96000 };
                bitRates = Range.create(8000, 510000);
                maxChannels = 48;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_VORBIS)) {
                bitRates = Range.create(32000, 500000);
                sampleRateRange = Range.create(8000, 192000);
                maxChannels = 255;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_OPUS)) {
                bitRates = Range.create(6000, 510000);
                sampleRates = new int[] { 8000, 12000, 16000, 24000, 48000 };
                maxChannels = 255;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_RAW)) {
                sampleRateRange = Range.create(1, 192000);
                bitRates = Range.create(1, 10000000);
                maxChannels = AudioSystem.OUT_CHANNEL_COUNT_MAX;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_FLAC)) {
                sampleRateRange = Range.create(1, 655350);
                // lossless codec, so bitrate is ignored
                maxChannels = 255;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_G711_ALAW)
                    || mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_G711_MLAW)) {
                sampleRates = new int[] { 8000 };
                bitRates = Range.create(64000, 64000);
                // platform allows multiple channels for this format
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_MSGSM)) {
                sampleRates = new int[] { 8000 };
                bitRates = Range.create(13000, 13000);
                maxChannels = 1;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_AC3)) {
                maxChannels = 6;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_EAC3)) {
                maxChannels = 16;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_EAC3_JOC)) {
                sampleRates = new int[] { 48000 };
                bitRates = Range.create(32000, 6144000);
                maxChannels = 16;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_AC4)) {
                sampleRates = new int[] { 44100, 48000, 96000, 192000 };
                bitRates = Range.create(16000, 2688000);
                maxChannels = 24;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_DTS)) {
                sampleRates = new int[] { 44100, 48000 };
                bitRates = Range.create(96000, 1524000);
                maxChannels = 6;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_DTS_HD)) {
                for (CodecProfileLevel profileLevel: profileLevels) {
                    switch (profileLevel.profile) {
                        case CodecProfileLevel.DTS_HDProfileLBR:
                            sampleRates = new int[]{ 22050, 24000, 44100, 48000 };
                            bitRates = Range.create(32000, 768000);
                            break;
                        case CodecProfileLevel.DTS_HDProfileHRA:
                        case CodecProfileLevel.DTS_HDProfileMA:
                            sampleRates = new int[]{ 44100, 48000, 88200, 96000, 176400, 192000 };
                            bitRates = Range.create(96000, 24500000);
                            break;
                        default:
                            Log.w(TAG, "Unrecognized profile "
                                    + profileLevel.profile + " for " + mime);
                            mParent.mError |= ERROR_UNRECOGNIZED;
                            sampleRates = new int[]{ 44100, 48000, 88200, 96000, 176400, 192000 };
                            bitRates = Range.create(96000, 24500000);
                    }
                }
                maxChannels = 8;
            } else if (mime.equalsIgnoreCase(MediaFormat.MIMETYPE_AUDIO_DTS_UHD)) {
                for (CodecProfileLevel profileLevel: profileLevels) {
                    switch (profileLevel.profile) {
                        case CodecProfileLevel.DTS_UHDProfileP2:
                            sampleRates = new int[]{ 48000 };
                            bitRates = Range.create(96000, 768000);
                            maxChannels = 10;
                            break;
                        case CodecProfileLevel.DTS_UHDProfileP1:
                            sampleRates = new int[]{ 44100, 48000, 88200, 96000, 176400, 192000 };
                            bitRates = Range.create(96000, 24500000);
                            maxChannels = 32;
                            break;
                        default:
                            Log.w(TAG, "Unrecognized profile "
                                    + profileLevel.profile + " for " + mime);
                            mParent.mError |= ERROR_UNRECOGNIZED;
                            sampleRates = new int[]{ 44100, 48000, 88200, 96000, 176400, 192000 };
                            bitRates = Range.create(96000, 24500000);
                            maxChannels = 32;
                    }
                }
            } else {
                Log.w(TAG, "Unsupported mime " + mime);
                mParent.mError |= ERROR_UNSUPPORTED;
            }

            // restrict ranges
            if (sampleRates != null) {
                limitSampleRates(sampleRates);
            } else if (sampleRateRange != null) {
                limitSampleRates(new Range[] { sampleRateRange });
            }

            Range<Integer> channelRange = Range.create(1, maxChannels);

            applyLimits(new Range[] { channelRange }, bitRates);
        }

        private void applyLimits(Range<Integer>[] inputChannels, Range<Integer> bitRates) {

            // clamp & make a local copy
            Range<Integer>[] myInputChannels = new Range[inputChannels.length];
            for (int i = 0; i < inputChannels.length; i++) {
                int lower = inputChannels[i].clamp(1);
                int upper = inputChannels[i].clamp(MAX_INPUT_CHANNEL_COUNT);
                myInputChannels[i] = Range.create(lower, upper);
            }

            // sort, intersect with existing, & save channel list
            sortDistinctRanges(myInputChannels);
            Range<Integer>[] joinedChannelList =
                            intersectSortedDistinctRanges(myInputChannels, mInputChannelRanges);
            mInputChannelRanges = joinedChannelList;

            if (bitRates != null) {
                mBitrateRange = mBitrateRange.intersect(bitRates);
            }
        }

        private void parseFromInfo(MediaFormat info) {
            int maxInputChannels = MAX_INPUT_CHANNEL_COUNT;
            Range<Integer>[] channels = new Range[] { Range.create(1, maxInputChannels)};
            Range<Integer> bitRates = POSITIVE_INTEGERS;

            if (info.containsKey("sample-rate-ranges")) {
                String[] rateStrings = info.getString("sample-rate-ranges").split(",");
                Range<Integer>[] rateRanges = new Range[rateStrings.length];
                for (int i = 0; i < rateStrings.length; i++) {
                    rateRanges[i] = Utils.parseIntRange(rateStrings[i], null);
                }
                limitSampleRates(rateRanges);
            }

            // we will prefer channel-ranges over max-channel-count
            if (info.containsKey("channel-ranges")) {
                String[] channelStrings = info.getString("channel-ranges").split(",");
                Range<Integer>[] channelRanges = new Range[channelStrings.length];
                for (int i = 0; i < channelStrings.length; i++) {
                    channelRanges[i] = Utils.parseIntRange(channelStrings[i], null);
                }
                channels = channelRanges;
            } else if (info.containsKey("channel-range")) {
                Range<Integer> oneRange = Utils.parseIntRange(info.getString("channel-range"),
                                                              null);
                channels = new Range[] { oneRange };
            } else if (info.containsKey("max-channel-count")) {
                maxInputChannels = Utils.parseIntSafely(
                        info.getString("max-channel-count"), maxInputChannels);
                if (maxInputChannels == 0) {
                    channels = new Range[] {Range.create(0, 0)};
                } else {
                    channels = new Range[] {Range.create(1, maxInputChannels)};
                }
            } else if ((mParent.mError & ERROR_UNSUPPORTED) != 0) {
                maxInputChannels = 0;
                channels = new Range[] {Range.create(0, 0)};
            }

            if (info.containsKey("bitrate-range")) {
                bitRates = bitRates.intersect(
                        Utils.parseIntRange(info.getString("bitrate-range"), bitRates));
            }

            applyLimits(channels, bitRates);
        }

        /** @hide */
        public void getDefaultFormat(MediaFormat format) {
            // report settings that have only a single choice
            if (mBitrateRange.getLower().equals(mBitrateRange.getUpper())) {
                format.setInteger(MediaFormat.KEY_BIT_RATE, mBitrateRange.getLower());
            }
            if (getMaxInputChannelCount() == 1) {
                // mono-only format
                format.setInteger(MediaFormat.KEY_CHANNEL_COUNT, 1);
            }
            if (mSampleRates != null && mSampleRates.length == 1) {
                format.setInteger(MediaFormat.KEY_SAMPLE_RATE, mSampleRates[0]);
            }
        }

        /* package private */
        // must not contain KEY_PROFILE
        static final Set<String> AUDIO_LEVEL_CRITICAL_FORMAT_KEYS = Set.of(
                // We don't set level-specific limits for audio codecs today. Key candidates would
                // be sample rate, bit rate or channel count.
                // MediaFormat.KEY_SAMPLE_RATE,
                // MediaFormat.KEY_CHANNEL_COUNT,
                // MediaFormat.KEY_BIT_RATE,
                MediaFormat.KEY_MIME);

        /** @hide */
        public boolean supportsFormat(MediaFormat format) {
            Map<String, Object> map = format.getMap();
            Integer sampleRate = (Integer)map.get(MediaFormat.KEY_SAMPLE_RATE);
            Integer channels = (Integer)map.get(MediaFormat.KEY_CHANNEL_COUNT);

            if (!supports(sampleRate, channels)) {
                return false;
            }

            if (!CodecCapabilities.supportsBitrate(mBitrateRange, format)) {
                return false;
            }

            // nothing to do for:
            // KEY_CHANNEL_MASK: codecs don't get this
            // KEY_IS_ADTS:      required feature for all AAC decoders
            return true;
        }
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
