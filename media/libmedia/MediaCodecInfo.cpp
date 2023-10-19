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
