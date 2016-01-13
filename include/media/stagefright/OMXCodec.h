/*
 * Copyright (C) 2009 The Android Open Source Project
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

#ifndef OMX_CODEC_H_

#define OMX_CODEC_H_

#include <android/native_window.h>
#include <media/IOMX.h>
#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/MediaSource.h>
#include <utils/threads.h>

#include <OMX_Audio.h>

namespace android {

struct MediaCodecInfo;
class MemoryDealer;
struct OMXCodecObserver;
struct CodecProfileLevel;
class SkipCutBuffer;

struct OMXCodec : public MediaSource,
                  public MediaBufferObserver {
    enum CreationFlags {
        kPreferSoftwareCodecs    = 1,
        kIgnoreCodecSpecificData = 2,

        // Request for software or hardware codecs. If request
        // can not be fullfilled, Create() returns NULL.
        kSoftwareCodecsOnly      = 8,
        kHardwareCodecsOnly      = 16,
    };

    static void setComponentRole(
        const sp<IOMX> &omx, IOMX::node_id node, bool isEncoder,
        const char *mime);

    enum Quirks {
        kNeedsFlushBeforeDisable              = 1,
        kWantsNALFragments                    = 2,
        kRequiresLoadedToIdleAfterAllocation  = 4,
        kRequiresAllocateBufferOnInputPorts   = 8,
        kRequiresFlushCompleteEmulation       = 16,
        kRequiresAllocateBufferOnOutputPorts  = 32,
        kRequiresFlushBeforeShutdown          = 64,
        kDefersOutputBufferAllocation         = 128,
        kDecoderLiesAboutNumberOfChannels     = 256,
        kInputBufferSizesAreBogus             = 512,
        kSupportsMultipleFramesPerInputBuffer = 1024,
        kRequiresLargerEncoderOutputBuffer    = 2048,
        kOutputBuffersAreUnreadable           = 4096,
    };

    struct CodecNameAndQuirks {
        String8 mName;
        uint32_t mQuirks;
    };

    // for use by ACodec
    static void findMatchingCodecs(
            const char *mime,
            bool createEncoder, const char *matchComponentName,
            uint32_t flags,
            Vector<CodecNameAndQuirks> *matchingCodecNamesAndQuirks);

    static uint32_t getComponentQuirks(
            const sp<MediaCodecInfo> &list);

    static bool findCodecQuirks(const char *componentName, uint32_t *quirks);
};

struct CodecCapabilities {
    enum {
        kFlagSupportsAdaptivePlayback = 1 << 0,
    };

    String8 mComponentName;
    Vector<CodecProfileLevel> mProfileLevels;
    Vector<OMX_U32> mColorFormats;
    uint32_t mFlags;
};

// Return a vector of componentNames with supported profile/level pairs
// supporting the given mime type, if queryDecoders==true, returns components
// that decode content of the given type, otherwise returns components
// that encode content of the given type.
// profile and level indications only make sense for h.263, mpeg4 and avc
// video.
// If hwCodecOnly==true, only returns hardware-based components, software and
// hardware otherwise.
// The profile/level values correspond to
// OMX_VIDEO_H263PROFILETYPE, OMX_VIDEO_MPEG4PROFILETYPE,
// OMX_VIDEO_AVCPROFILETYPE, OMX_VIDEO_H263LEVELTYPE, OMX_VIDEO_MPEG4LEVELTYPE
// and OMX_VIDEO_AVCLEVELTYPE respectively.

status_t QueryCodecs(
        const sp<IOMX> &omx,
        const char *mimeType, bool queryDecoders, bool hwCodecOnly,
        Vector<CodecCapabilities> *results);

status_t QueryCodecs(
        const sp<IOMX> &omx,
        const char *mimeType, bool queryDecoders,
        Vector<CodecCapabilities> *results);

status_t QueryCodec(
        const sp<IOMX> &omx,
        const char *componentName, const char *mime,
        bool isEncoder,
        CodecCapabilities *caps);

status_t getOMXChannelMapping(size_t numChannels, OMX_AUDIO_CHANNELTYPE map[]);

}  // namespace android

#endif  // OMX_CODEC_H_
