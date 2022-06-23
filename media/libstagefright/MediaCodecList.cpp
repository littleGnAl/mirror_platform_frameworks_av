/*
 * Copyright 2012, The Android Open Source Project
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
#define LOG_TAG "MediaCodecList"
#include <utils/Log.h>

#include "MediaCodecListOverrides.h"

#include <binder/IServiceManager.h>

#include <media/IMediaCodecList.h>
#include <media/IMediaPlayerService.h>
#include <media/MediaCodecInfo.h>

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AUtils.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <media/stagefright/omx/OMXUtils.h>
#include <media/stagefright/xmlparser/MediaCodecsXmlParser.h>
#include <media/stagefright/CCodec.h>
#include <media/stagefright/Codec2InfoBuilder.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/MediaCodecList.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/OmxInfoBuilder.h>
#include <media/stagefright/PersistentSurface.h>

#include <sys/stat.h>
#include <utils/threads.h>

#include <cutils/properties.h>

#include <algorithm>
#include <limits>
#include <regex>

namespace android {

namespace {

Mutex sInitMutex;

Mutex sRemoteInitMutex;

constexpr const char* kProfilingResults =
        MediaCodecsXmlParser::defaultProfilingResultsXmlPath;

bool isProfilingNeeded() {
    int8_t value = property_get_bool("debug.stagefright.profilecodec", 0);
    if (value == 0) {
        return false;
    }

    bool profilingNeeded = true;
    FILE *resultsFile = fopen(kProfilingResults, "r");
    if (resultsFile) {
        AString currentVersion = getProfilingVersionString();
        size_t currentVersionSize = currentVersion.size();
        char *versionString = new char[currentVersionSize + 1];
        fgets(versionString, currentVersionSize + 1, resultsFile);
        if (strcmp(versionString, currentVersion.c_str()) == 0) {
            // profiling result up to date
            profilingNeeded = false;
        }
        fclose(resultsFile);
        delete[] versionString;
    }
    return profilingNeeded;
}

OmxInfoBuilder sOmxInfoBuilder{true /* allowSurfaceEncoders */};
OmxInfoBuilder sOmxNoSurfaceEncoderInfoBuilder{false /* allowSurfaceEncoders */};

Mutex sCodec2InfoBuilderMutex;
std::unique_ptr<MediaCodecListBuilderBase> sCodec2InfoBuilder;

MediaCodecListBuilderBase *GetCodec2InfoBuilder() {
    Mutex::Autolock _l(sCodec2InfoBuilderMutex);
    if (!sCodec2InfoBuilder) {
        sCodec2InfoBuilder.reset(new Codec2InfoBuilder);
    }
    return sCodec2InfoBuilder.get();
}

std::vector<MediaCodecListBuilderBase *> GetBuilders() {
    std::vector<MediaCodecListBuilderBase *> builders;
    // if plugin provides the input surface, we cannot use OMX video encoders.
    // In this case, rely on plugin to provide list of OMX codecs that are usable.
    sp<PersistentSurface> surfaceTest = CCodec::CreateInputSurface();
    if (surfaceTest == nullptr) {
        ALOGD("Allowing all OMX codecs");
        builders.push_back(&sOmxInfoBuilder);
    } else {
        ALOGD("Allowing only non-surface-encoder OMX codecs");
        builders.push_back(&sOmxNoSurfaceEncoderInfoBuilder);
    }
    builders.push_back(GetCodec2InfoBuilder());
    return builders;
}

}  // unnamed namespace

// static
sp<IMediaCodecList> MediaCodecList::sCodecList;

// static
void *MediaCodecList::profilerThreadWrapper(void * /*arg*/) {
    ALOGV("Enter profilerThreadWrapper.");
    remove(kProfilingResults);  // remove previous result so that it won't be loaded to
                                // the new MediaCodecList
    sp<MediaCodecList> codecList(new MediaCodecList(GetBuilders()));
    if (codecList->initCheck() != OK) {
        ALOGW("Failed to create a new MediaCodecList, skipping codec profiling.");
        return nullptr;
    }

    const auto& infos = codecList->mCodecInfos;
    ALOGV("Codec profiling started.");
    profileCodecs(infos, kProfilingResults);
    ALOGV("Codec profiling completed.");
    codecList = new MediaCodecList(GetBuilders());
    if (codecList->initCheck() != OK) {
        ALOGW("Failed to parse profiling results.");
        return nullptr;
    }

    {
        Mutex::Autolock autoLock(sInitMutex);
        sCodecList = codecList;
    }
    return nullptr;
}

// static
sp<IMediaCodecList> MediaCodecList::getLocalInstance() {
    Mutex::Autolock autoLock(sInitMutex);

    if (sCodecList == nullptr) {
        MediaCodecList *codecList = new MediaCodecList(GetBuilders());
        if (codecList->initCheck() == OK) {
            sCodecList = codecList;

            if (isProfilingNeeded()) {
                ALOGV("Codec profiling needed, will be run in separated thread.");
                pthread_t profiler;
                if (pthread_create(&profiler, nullptr, profilerThreadWrapper, nullptr) != 0) {
                    ALOGW("Failed to create thread for codec profiling.");
                }
            }
        } else {
            // failure to initialize may be temporary. retry on next call.
            delete codecList;
        }
    }

    return sCodecList;
}

sp<IMediaCodecList> MediaCodecList::sRemoteList;

sp<MediaCodecList::BinderDeathObserver> MediaCodecList::sBinderDeathObserver;
sp<IBinder> MediaCodecList::sMediaPlayer;  // kept since linked to death

void MediaCodecList::BinderDeathObserver::binderDied(const wp<IBinder> &who __unused) {
    Mutex::Autolock _l(sRemoteInitMutex);
    sRemoteList.clear();
    sBinderDeathObserver.clear();
}

// static
sp<IMediaCodecList> MediaCodecList::getInstance() {
    Mutex::Autolock _l(sRemoteInitMutex);
    if (sRemoteList == nullptr) {
        sMediaPlayer = defaultServiceManager()->getService(String16("media.player"));
        sp<IMediaPlayerService> service =
            interface_cast<IMediaPlayerService>(sMediaPlayer);
        if (service.get() != nullptr) {
            sRemoteList = service->getCodecList();
            if (sRemoteList != nullptr) {
                sBinderDeathObserver = new BinderDeathObserver();
                sMediaPlayer->linkToDeath(sBinderDeathObserver.get());
            }
        }
        if (sRemoteList == nullptr) {
            // if failed to get remote list, create local list
            sRemoteList = getLocalInstance();
        }
    }
    return sRemoteList;
}

MediaCodecList::MediaCodecList(std::vector<MediaCodecListBuilderBase*> builders) {
    mGlobalSettings = new AMessage();
    mCodecInfos.clear();
    MediaCodecListWriter writer;
    for (MediaCodecListBuilderBase *builder : builders) {
        if (builder == nullptr) {
            ALOGD("ignored a null builder");
            continue;
        }
        auto currentCheck = builder->buildMediaCodecList(&writer);
        if (currentCheck != OK) {
            ALOGD("ignored failed builder");
            continue;
        } else {
            mInitCheck = currentCheck;
        }
    }
    writer.writeGlobalSettings(mGlobalSettings);
    writer.writeCodecInfos(&mCodecInfos);
    std::stable_sort(
            mCodecInfos.begin(),
            mCodecInfos.end(),
            [](const sp<MediaCodecInfo> &info1, const sp<MediaCodecInfo> &info2) {
                // null is lowest
                return info1 == nullptr
                        || (info2 != nullptr && info1->getRank() < info2->getRank());
            });

    // remove duplicate entries
    bool dedupe = property_get_bool("debug.stagefright.dedupe-codecs", true);
    if (dedupe) {
        std::set<std::string> codecsSeen;
        for (auto it = mCodecInfos.begin(); it != mCodecInfos.end(); ) {
            std::string codecName = (*it)->getCodecName();
            if (codecsSeen.count(codecName) == 0) {
                codecsSeen.emplace(codecName);
                it++;
            } else {
                it = mCodecInfos.erase(it);
            }
        }
    }
}

MediaCodecList::~MediaCodecList() {
}

status_t MediaCodecList::initCheck() const {
    return mInitCheck;
}

// legacy method for non-advanced codecs
ssize_t MediaCodecList::findCodecByType(
        const char *type, bool encoder, size_t startIndex) const {
    static const char *advancedFeatures[] = {
        "feature-secure-playback",
        "feature-tunneled-playback",
    };

    size_t numCodecInfos = mCodecInfos.size();
    for (; startIndex < numCodecInfos; ++startIndex) {
        const MediaCodecInfo &info = *mCodecInfos[startIndex];

        if (info.isEncoder() != encoder) {
            continue;
        }
        sp<MediaCodecInfo::Capabilities> capabilities = info.getCapabilitiesFor(type);
        if (capabilities == nullptr) {
            continue;
        }
        const sp<AMessage> &details = capabilities->getDetails();

        int32_t required;
        bool isAdvanced = false;
        for (size_t ix = 0; ix < ARRAY_SIZE(advancedFeatures); ix++) {
            if (details->findInt32(advancedFeatures[ix], &required) &&
                    required != 0) {
                isAdvanced = true;
                break;
            }
        }

        if (!isAdvanced) {
            return startIndex;
        }
    }

    return -ENOENT;
}

ssize_t MediaCodecList::findCodecByName(const char *name) const {
    Vector<AString> aliases;
    for (size_t i = 0; i < mCodecInfos.size(); ++i) {
        if (strcmp(mCodecInfos[i]->getCodecName(), name) == 0) {
            return i;
        }
        mCodecInfos[i]->getAliases(&aliases);
        for (const AString &alias : aliases) {
            if (alias == name) {
                return i;
            }
        }
    }

    return -ENOENT;
}

size_t MediaCodecList::countCodecs() const {
    return mCodecInfos.size();
}

const sp<AMessage> MediaCodecList::getGlobalSettings() const {
    return mGlobalSettings;
}

//static
bool MediaCodecList::isSoftwareCodec(const AString &componentName) {
    return componentName.startsWithIgnoreCase("OMX.google.")
            || componentName.startsWithIgnoreCase("c2.android.")
            || (!componentName.startsWithIgnoreCase("OMX.")
                    && !componentName.startsWithIgnoreCase("c2."));
}

static int compareSoftwareCodecsFirst(const AString *name1, const AString *name2) {
    // sort order 1: software codecs are first (lower)
    bool isSoftwareCodec1 = MediaCodecList::isSoftwareCodec(*name1);
    bool isSoftwareCodec2 = MediaCodecList::isSoftwareCodec(*name2);
    if (isSoftwareCodec1 != isSoftwareCodec2) {
        return isSoftwareCodec2 - isSoftwareCodec1;
    }

    // sort order 2: Codec 2.0 codecs are first (lower)
    bool isC2_1 = name1->startsWithIgnoreCase("c2.");
    bool isC2_2 = name2->startsWithIgnoreCase("c2.");
    if (isC2_1 != isC2_2) {
        return isC2_2 - isC2_1;
    }

    // sort order 3: OMX codecs are first (lower)
    bool isOMX1 = name1->startsWithIgnoreCase("OMX.");
    bool isOMX2 = name2->startsWithIgnoreCase("OMX.");
    return isOMX2 - isOMX1;
}

//static
void MediaCodecList::findMatchingCodecs(
        const char *mime, bool encoder, uint32_t flags,
        Vector<AString> *matches) {
    sp<AMessage> format;        // initializes as clear/null
    findMatchingCodecs(mime, encoder, flags, format, matches);
}

//static
void MediaCodecList::findMatchingCodecs(
        const char *mime, bool encoder, uint32_t flags, sp<AMessage> format,
        Vector<AString> *matches) {
    matches->clear();

    const sp<IMediaCodecList> list = getInstance();
    if (list == nullptr) {
        return;
    }

    size_t index = 0;
    for (;;) {
        ssize_t matchIndex =
            list->findCodecByType(mime, encoder, index);

        if (matchIndex < 0) {
            break;
        }

        index = matchIndex + 1;

        const sp<MediaCodecInfo> info = list->getCodecInfo(matchIndex);
        CHECK(info != nullptr);

        AString componentName = info->getCodecName();

        if (!codecHandlesFormat(mime, info, format)) {
            ALOGV("skipping codec '%s' which doesn't satisfy format %s",
                  componentName.c_str(), format->debugString(2).c_str());
            continue;
        }

        if ((flags & kHardwareCodecsOnly) && isSoftwareCodec(componentName)) {
            ALOGV("skipping SW codec '%s'", componentName.c_str());
            continue;
        }

        matches->push(componentName);
        ALOGV("matching '%s'", componentName.c_str());
    }

    if (flags & kPreferSoftwareCodecs ||
            property_get_bool("debug.stagefright.swcodec", false)) {
        matches->sort(compareSoftwareCodecsFirst);
    }
}

/*static*/
bool MediaCodecList::codecHandlesFormat(const char *mime, sp<MediaCodecInfo> info,
                                        sp<AMessage> format) {

    if (format == nullptr) {
        ALOGD("codecHandlesFormat: no format, so no extra checks");
        return true;
    }

    sp<MediaCodecInfo::Capabilities> capabilities = info->getCapabilitiesFor(mime);

    // ... no capabilities listed means 'handle it all'
    if (capabilities == nullptr) {
        ALOGD("codecHandlesFormat: no capabilities for refinement");
        return true;
    }

    const sp<AMessage> &details = capabilities->getDetails();

    // if parsing the capabilities fails, ignore this particular codec
    // currently video-centric evaluation
    //
    // TODO: like to make it handle the same set of properties from
    // MediaCodecInfo::isFormatSupported()
    // not yet done here are:
    //  profile, level, bitrate, features,

    bool isVideo = false;
    if (strncmp(mime, "video/", 6) == 0) {
        isVideo = true;
    }

    if (isVideo) {
        int width = -1;
        int height = -1;

        if (format->findInt32("height", &height) && format->findInt32("width", &width)) {

            // is it within the supported size range of the codec?
            AString sizeRange;
            AString minSize,maxSize;
            AString minWidth, minHeight;
            AString maxWidth, maxHeight;
            if (!details->findString("size-range", &sizeRange)
                || !splitString(sizeRange, "-", &minSize, &maxSize)) {
                ALOGW("Unable to parse size-range from codec info");
                return false;
            }
            if (!splitString(minSize, "x", &minWidth, &minHeight)) {
                if (!splitString(minSize, "*", &minWidth, &minHeight)) {
                    ALOGW("Unable to parse size-range/min-size from codec info");
                    return false;
                }
            }
            if (!splitString(maxSize, "x", &maxWidth, &maxHeight)) {
                if (!splitString(maxSize, "*", &maxWidth, &maxHeight)) {
                    ALOGW("Unable to fully parse size-range/max-size from codec info");
                    return false;
                }
            }

            // strtol() returns 0 if unable to parse a number, which works for our later tests
            int minW = strtol(minWidth.c_str(), NULL, 10);
            int minH = strtol(minHeight.c_str(), NULL, 10);
            int maxW = strtol(maxWidth.c_str(), NULL, 10);
            int maxH = strtol(maxHeight.c_str(), NULL, 10);

            if (minW == 0 || minH == 0 || maxW == 0 || maxH == 0) {
                ALOGW("Unable to parse values from size-range from codec info");
                return false;
            }

            // finally, comparison time
            if (width < minW || width > maxW || height < minH || height > maxH) {
                ALOGV("format %dx%d outside of allowed %dx%d-%dx%d",
                      width, height, minW, minH, maxW, maxH);
                // at this point, it's a rejection, UNLESS
                // the codec allows swapping width and height
                int32_t swappable;
                if (!details->findInt32("feature-can-swap-width-height", &swappable)
                    || swappable == 0) {
                    return false;
                }
                // NB: deliberate comparison of height vs width limits (and width vs height)
                if (height < minW || height > maxW || width < minH || width > maxH) {
                    return false;
                }
            }

            // @ 'alignment' [e.g. "2x2" which tells us that both dimensions must be even]
            // no alignment == we're ok with anything
            AString alignment, alignWidth, alignHeight;
            if (details->findString("alignment", &alignment)) {
                if (splitString(alignment, "x", &alignWidth, &alignHeight) ||
                    splitString(alignment, "*", &alignWidth, &alignHeight)) {
                    int wAlign = strtol(alignWidth.c_str(), NULL, 10);
                    int hAlign = strtol(alignHeight.c_str(), NULL, 10);
                    // strtol() returns 0 if failing to parse, treat as "no restriction"
                    if (wAlign > 0 && hAlign > 0) {
                         if ((width % wAlign) != 0 || (height % hAlign) != 0) {
                            ALOGV("format dimensions %dx%d not aligned to %dx%d",
                                 width, height, wAlign, hAlign);
                            return false;
                         }
                    }
                }
            }
        }

        int32_t profile = -1;
        if (format->findInt32("profile", &profile)) {
            int32_t level = -1;
            format->findInt32("level", &level);
            Vector<MediaCodecInfo::ProfileLevel> profileLevels;
            capabilities->getSupportedProfileLevels(&profileLevels);
            auto it = profileLevels.begin();
            for (; it != profileLevels.end(); ++it) {
                if (profile != it->mProfile) {
                    continue;
                }
                if (level > -1 && level > it->mLevel) {
                    continue;
                }
                break;
            }

            if (it == profileLevels.end()) {
                ALOGV("Codec does not support profile %d with level %d", profile, level);
                return false;
            }

            // check max-blocks
            auto [errs, blockWidth, blockHeight, maxBlocks] = applyLevelLimits(mime, level);
            if (errs != OK ||
                    divUp(width, blockWidth) * divUp(height, blockHeight) > maxBlocks) {
                return false;
            }
        }
    }

    // haven't found a reason to discard this one
    return true;
}

// static
std::tuple<int, int, int, int> MediaCodecList::applyLevelLimits(const char *mime,
                                                                const int32_t level) {
    int errors = OK;
    int blockWidth = 2;
    int blockHeight = 2;
    int maxBlocks = 99;
    int FS = 0; // Frame Size
    if (strcmp(mime, MIMETYPE_VIDEO_AVC) == 0) {
        switch (level) {
            case AVCLevel1:
            case AVCLevel1b:
                FS =     99; break;
            case AVCLevel11:
            case AVCLevel12:
            case AVCLevel13:
            case AVCLevel2:
                FS =    396; break;
            case AVCLevel21:
                FS =    792; break;
            case AVCLevel22:
            case AVCLevel3:
                FS =   1620; break;
            case AVCLevel31:
                FS =   3600; break;
            case AVCLevel32:
                FS =   5120; break;
            case AVCLevel4:
            case AVCLevel41:
                FS =   8192; break;
            case AVCLevel42:
                FS =   8704; break;
            case AVCLevel5:
                FS =  22080; break;
            case AVCLevel51:
            case AVCLevel52:
                FS =  36864; break;
            case AVCLevel6:
            case AVCLevel61:
            case AVCLevel62:
                FS = 139264; break;
            default:
                ALOGE("Unrecognized level %d for %s", level, mime);
                errors |= ERROR_UNRECOGNIZED;
        }
        blockWidth = 16;
        blockHeight = 16;
        maxBlocks = std::max(FS, maxBlocks);
    } else if (strcmp(mime, MIMETYPE_VIDEO_MPEG2) == 0) {
        switch (level) {
            case MPEG2LevelLL:
                FS =   396; break;
            case MPEG2LevelML:
                FS =  1620; break;
            case MPEG2LevelH14:
                FS =  6120; break;
            case MPEG2LevelHL:
            case MPEG2LevelHP:
                FS =  8160; break;
            default:
                ALOGE("Unrecognized level %d for %s", level, mime);
                errors |= ERROR_UNRECOGNIZED;
        }
        blockWidth = 16;
        blockHeight = 16;
        maxBlocks = std::max(FS, maxBlocks);
    } else if (strcmp(mime, MIMETYPE_VIDEO_MPEG4) == 0) {
        switch (level) {
            case MPEG4Level0:
            case MPEG4Level1:
            case MPEG4Level0b:
                FS =   99; break;
            case MPEG4Level2:
            case MPEG4Level3:
            case MPEG4Level3b:
                FS =  396; break;
            case MPEG4Level4:
                FS =  792; break;
            case MPEG4Level4a:
                FS = 1200; break;
            case MPEG4Level5:
                FS = 1620; break;
            case MPEG4Level6:
                FS = 3600; break;
            default:
                ALOGE("Unrecognized level %d for %s", level, mime);
                errors |= ERROR_UNRECOGNIZED;
        }
        blockWidth = 16;
        blockHeight = 16;
        maxBlocks = std::max(FS, maxBlocks);
    } else if (strcmp(mime, MIMETYPE_VIDEO_H263) == 0) {
        int W = 0, H = 0;
        switch (level) {
            case H263Level10:
                W = 11; H =  9; break;
            case H263Level20:
            case H263Level30:
            case H263Level40:
                W = 22; H = 18; break;
            case H263Level45:
                W = 11; H =  9; break;
            case H263Level50:
                W = 22; H = 18; break;
            case H263Level60:
                W = 45; H = 18; break;
            case H263Level70:
                W = 45; H = 36; break;
            default:
                ALOGE("Unrecognized level %d for %s", level, mime);
                errors |= ERROR_UNRECOGNIZED;
        }
        blockWidth = 16;
        blockHeight = 16;
        maxBlocks = std::max(W * H, maxBlocks);
    } else if (strcmp(mime, MIMETYPE_VIDEO_VP8)) {
        blockWidth = 16;
        blockHeight = 16;
        maxBlocks = std::numeric_limits<int>::max();
    } else if (strcmp(mime, MIMETYPE_VIDEO_VP9) == 0) {
        maxBlocks = 36864;
        switch (level) {
            case VP9Level1:
                FS =    36864; break;
            case VP9Level11:
                FS =    73728; break;
            case VP9Level2:
                FS =   122880; break;
            case VP9Level21:
                FS =   245760; break;
            case VP9Level3:
                FS =   552960; break;
            case VP9Level31:
                FS =   983040; break;
            case VP9Level4:
            case VP9Level41:
                FS =  2228224; break;
            case VP9Level5:
            case VP9Level51:
            case VP9Level52:
                FS =  8912896; break;
            case VP9Level6:
            case VP9Level61:
            case VP9Level62:
                FS = 35651584; break;
            default:
                ALOGE("Unrecognized level %d for %s", level, mime);
                errors |= ERROR_UNRECOGNIZED;
        }
        blockWidth = 8;
        blockHeight = 8;
        maxBlocks = std::max(FS, maxBlocks);
        maxBlocks = divUp(maxBlocks, blockWidth * blockHeight);
    } else if (strcmp(mime, MIMETYPE_VIDEO_HEVC) == 0) {
        // CTBs are at least 8x8 so use 8x8 block size
        maxBlocks = 36864 >> 6; // 192x192 pixels == 576 8x8 blocks
        switch (level) {
            case HEVCMainTierLevel1:
            case HEVCHighTierLevel1:
                FS =    36864; break;
            case HEVCMainTierLevel2:
            case HEVCHighTierLevel2:
                FS =   122880; break;
            case HEVCMainTierLevel21:
            case HEVCHighTierLevel21:
                FS =   245760; break;
            case HEVCMainTierLevel3:
            case HEVCHighTierLevel3:
                FS =   552960; break;
            case HEVCMainTierLevel31:
            case HEVCHighTierLevel31:
                FS =   983040; break;
            case HEVCMainTierLevel4:
            case HEVCHighTierLevel4:
            case HEVCMainTierLevel41:
            case HEVCHighTierLevel41:
                FS =  2228224; break;
            case HEVCMainTierLevel5:
            case HEVCHighTierLevel5:
            case HEVCMainTierLevel51:
            case HEVCHighTierLevel51:
            case HEVCMainTierLevel52:
            case HEVCHighTierLevel52:
                FS =  8912896; break;
            case HEVCMainTierLevel6:
            case HEVCHighTierLevel6:
            case HEVCMainTierLevel61:
            case HEVCHighTierLevel61:
            case HEVCMainTierLevel62:
            case HEVCHighTierLevel62:
                FS = 35651584; break;
            default:
                ALOGE("Unrecognized level %d for %s", level, mime);
                errors |= ERROR_UNRECOGNIZED;
        }
        blockWidth = 8;
        blockHeight = 8;
        maxBlocks = std::max(FS, maxBlocks);
    } else if (strcmp(mime, MIMETYPE_VIDEO_AV1) == 0) {
        maxBlocks = 36864;
        switch (level) {
            case AV1Level2:
                FS =   147456; break;
            case AV1Level21:
            case AV1Level22:
            case AV1Level23:
                FS =   278784; break;

            case AV1Level3:
                FS =   665856; break;
            case AV1Level31:
            case AV1Level32:
            case AV1Level33:
                FS =  1065024; break;

            case AV1Level4:
            case AV1Level41:
            case AV1Level42:
            case AV1Level43:
                FS =  2359296; break;

            case AV1Level5:
            case AV1Level51:
            case AV1Level52:
            case AV1Level53:
                FS =  8912896; break;

            case AV1Level6:
            case AV1Level61:
            case AV1Level62:
            case AV1Level63:
                FS = 35651584; break;
            default:
                ALOGE("Unrecognized level %d for %s", level, mime);
                errors |= ERROR_UNRECOGNIZED;
        }
        blockWidth = 8;
        blockHeight = 8;
        maxBlocks = std::max(FS, maxBlocks);
        maxBlocks = divUp(maxBlocks, blockWidth * blockHeight);
    } else {
        ALOGE("Unsupported mime %s", mime);
        errors |= ERROR_UNSUPPORTED;
    }
    return std::make_tuple(errors, blockWidth, blockHeight, maxBlocks);
}

}  // namespace android
