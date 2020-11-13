/*
 * Copyright (C) 2020 The Android Open Source Project
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


#define LOG_NDEBUG 0
#define LOG_TAG "MediaVendorExt"
#include <utils/Log.h>

#include "MediaVendorExt.h"
#include <media/stagefright/omx/OMXUtils.h>
#include <media/IOMX.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <dlfcn.h>
#include <unistd.h>
#include <OMX_VendorExt.h>




namespace android {

MediaVendorExt* MediaVendorExt::gImp = NULL;


const char *MEDIA_MIMETYPE_VIDEO_MSMPEG4 = "video/x-msmpeg";
const char *MEDIA_MIMETYPE_VIDEO_SORENSON_SPARK = "video/x-sorenson-spark";
const char *MEDIA_MIMETYPE_VIDEO_VC1 = "video/vc1";
const char *MEDIA_MIMETYPE_VIDEO_WVC1 = "video/wvc1";
const char *MEDIA_MIMETYPE_VIDEO_VPX = "video/x-vnd.on2.vp8";
const char *MEDIA_MIMETYPE_VIDEO_RM10 = "video/rm10";
const char *MEDIA_MIMETYPE_VIDEO_RM20 = "video/rm20";
const char *MEDIA_MIMETYPE_VIDEO_RM30 = "video/rm30";
const char *MEDIA_MIMETYPE_VIDEO_RM40 = "video/rm40";
const char *MEDIA_MIMETYPE_VIDEO_VP6 = "video/x-vnd.on2.vp6";
const char *MEDIA_MIMETYPE_VIDEO_VP6F = "video/x-vnd.on2.vp6f";
const char *MEDIA_MIMETYPE_VIDEO_VP6A = "video/x-vnd.on2.vp6a";
const char *MEDIA_MIMETYPE_VIDEO_WMV1 = "video/wmv1";
const char *MEDIA_MIMETYPE_VIDEO_WMV2 = "video/wmv2";
const char *MEDIA_MIMETYPE_VIDEO_WMV3 = "video/wmv3";
const char *MEDIA_MIMETYPE_VIDEO_MSWMV3 = "video/x-ms-wmv";
const char *MEDIA_MIMETYPE_VIDEO_AVS = "video/avs";
const char *MEDIA_MIMETYPE_VIDEO_AVS2 = "video/avs2";
const char *MEDIA_MIMETYPE_AUDIO_DTS = "audio/dtshd";
const char *MEDIA_MIMETYPE_AUDIO_MP1 = "audio/mp1";
const char *MEDIA_MIMETYPE_AUDIO_MP2 = "audio/mp2";
const char *MEDIA_MIMETYPE_AUDIO_ADPCM_IMA = "audio/adpcm-ima";
const char *MEDIA_MIMETYPE_AUDIO_ADPCM_MS = "audio/adpcm-ms";
const char *MEDIA_MIMETYPE_AUDIO_AAC_ADIF = "audio/aac-adif";
const char *MEDIA_MIMETYPE_AUDIO_AAC_LATM = "audio/aac-latm";
const char *MEDIA_MIMETYPE_AUDIO_ADTS_PROFILE = "audio/adts";
const char *MEDIA_MIMETYPE_AUDIO_WMAPRO = "audio/wmapro";
const char *MEDIA_MIMETYPE_AUDIO_DTSHD  = "audio/dtshd";
const char *MEDIA_MIMETYPE_AUDIO_TRUEHD = "audio/truehd";
const char *MEDIA_MIMETYPE_AUDIO_EC3 = "audio/eac3";
const char *MEDIA_MIMETYPE_AUDIO_FFMPEG = "audio/ffmpeg";

const char*  AGetComponentRole(bool isEncoder, const char *mime) {
    ALOGI("AmAVUtils::getComponentRole isEncoder :%d mime:%s \n",isEncoder,mime);
    const char *role = GetComponentRole(isEncoder, mime);
    if (role != NULL) {
        return role;
    }

    struct MimeToRole {
        const char *mime;
        const char *decoderRole;
        const char *encoderRole;
    };

    static const MimeToRole kMimeToRole[] = {
         {MEDIA_MIMETYPE_AUDIO_DTSHD,
         "audio_decoder.dtshd",  "audio_encoder.dtshd" },
         { MEDIA_MIMETYPE_AUDIO_AAC_ADIF,
         "audio_decoder.adif", "audio_encoder.adif" },
         { MEDIA_MIMETYPE_AUDIO_AAC_LATM,
         "audio_decoder.latm", "audio_encoder.latm" },
         { MEDIA_MIMETYPE_AUDIO_ADTS_PROFILE,
         "audio_decoder.adts", "audio_encoder.adts" },
         { MEDIA_MIMETYPE_VIDEO_MJPEG,
         "video_decoder.mjpeg", "video_encoder.mjpeg" },
         { MEDIA_MIMETYPE_VIDEO_WMV3,
         "video_decoder.wmv", "video_encoder.wmv" },
         { MEDIA_MIMETYPE_VIDEO_MSWMV3,
         "video_decoder.wmv3", "video_encoder.wmv3" },
         { MEDIA_MIMETYPE_AUDIO_WMA,
         "audio_decoder.wma", "audio_encoder.wma" },
         { MEDIA_MIMETYPE_AUDIO_WMAPRO,
         "audio_decoder.wmapro", "audio_encoder.wmapro" },
         { MEDIA_MIMETYPE_AUDIO_TRUEHD,
         "audio_decoder.truehd", "audio_encoder.truehd" },
         { MEDIA_MIMETYPE_VIDEO_VC1,
         "video_decoder.vc1", "video_encoder.vc1" },
         { MEDIA_MIMETYPE_VIDEO_WVC1,
         "video_decoder.wvc1", "video_encoder.wvc1" },
         { MEDIA_MIMETYPE_VIDEO_VP6,
         "video_decoder.amvp6", "video_encoder.amvp6" },
         { MEDIA_MIMETYPE_VIDEO_VP6A,
         "video_decoder.amvp6a", "video_encoder.amvp6a" },
         { MEDIA_MIMETYPE_VIDEO_VP6F,
         "video_decoder.amvp6f", "video_encoder.amvp6f" },
         { MEDIA_MIMETYPE_VIDEO_RM10,
         "video_decoder.rm10", "video_encoder.rm10"},
         { MEDIA_MIMETYPE_VIDEO_RM20,
         "video_decoder.rm20", "video_encoder.rm20"},
         { MEDIA_MIMETYPE_VIDEO_RM30,
         "video_decoder.rm30", "video_encoder.rm30"},
         { MEDIA_MIMETYPE_VIDEO_RM40,
         "video_decoder.rm40", "video_encoder.rm40"},
         { MEDIA_MIMETYPE_VIDEO_WMV2,
         "video_decoder.wmv2", "video_encoder.wmv2"},
         { MEDIA_MIMETYPE_VIDEO_WMV1,
         "video_decoder.wmv1", "video_encoder.wmv1"},
         { MEDIA_MIMETYPE_AUDIO_FFMPEG,
         "audio_decoder.ffmpeg", "audio_encoder.ffmpeg" },
         { MEDIA_MIMETYPE_AUDIO_ADTS_PROFILE,
         "audio_decoder.adts", "audio_encoder.adts" },
         { MEDIA_MIMETYPE_VIDEO_AVS,
         "video_decoder.avs", "video_encoder.avs"},
         { MEDIA_MIMETYPE_VIDEO_AVS2,
         "video_decoder.avs2", "video_encoder.avs2"},
    };

    static const size_t kNumMimeToRole =
        sizeof(kMimeToRole) / sizeof(kMimeToRole[0]);
    ALOGI("AmAVUtils::getComponentRole isEncoder :%d kNumMimeToRole:%d \n",isEncoder,kNumMimeToRole);

    size_t i;
    for (i = 0; i < kNumMimeToRole; ++i) {
        if (!strcasecmp(mime, kMimeToRole[i].mime)) {
            ALOGI("AmAVUtils::getComponentRole break\n");
            break;
        }
    }
    if (i == kNumMimeToRole) {
        ALOGE("AmAVUtils::have no Component role isEncoder :%d mime:%s",isEncoder,mime);
        return NULL;
    }
    ALOGI("AmAVUtils::getComponentRole isEncoder :%d Role:%s \n",isEncoder,isEncoder ? kMimeToRole[i].encoderRole: kMimeToRole[i].decoderRole);
    return isEncoder ? kMimeToRole[i].encoderRole
            : kMimeToRole[i].decoderRole;

}

const char *MediaVendorExt::getComponentRole(bool isEncoder, const char *mime) {
    ALOGV("AVUtils::getComponentRole");

    return AGetComponentRole(isEncoder,mime);
}

static const struct VideoCodingMapEntry {
    const char *mMime;
    OMX_VIDEO_CODINGTYPE mVideoCodingType;
} kVideoCodingMapEntry[] = {
    { MEDIA_MIMETYPE_VIDEO_MJPEG, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingMJPEG) },
    { MEDIA_MIMETYPE_VIDEO_VC1, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingVC1) },
    { MEDIA_MIMETYPE_VIDEO_WVC1, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingVC1) },
    { MEDIA_MIMETYPE_VIDEO_WMV3, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingWMV) },
    { MEDIA_MIMETYPE_VIDEO_MSWMV3, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingWMV3) },
    { MEDIA_MIMETYPE_VIDEO_VP6, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingVP6) },
    { MEDIA_MIMETYPE_VIDEO_VP6F, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingVP6) },
    { MEDIA_MIMETYPE_VIDEO_VP6A, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingVP6) },
    { MEDIA_MIMETYPE_VIDEO_RM10, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingRV10) },
    { MEDIA_MIMETYPE_VIDEO_RM20, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingRV20) },
    { MEDIA_MIMETYPE_VIDEO_RM30, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingRV30) },
    { MEDIA_MIMETYPE_VIDEO_RM40, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingRV40) },
    { MEDIA_MIMETYPE_VIDEO_WMV2, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingWMV) },
    { MEDIA_MIMETYPE_VIDEO_WMV1, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingWMV) },
    { MEDIA_MIMETYPE_VIDEO_AVS, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingAVS) },
    { MEDIA_MIMETYPE_VIDEO_AVS2, static_cast<OMX_VIDEO_CODINGTYPE>(OMX_VIDEO_CodingAVS2) },
};

status_t MediaVendorExt::getVideoCodingTypeFromMimeEx(
        const char *mime, OMX_VIDEO_CODINGTYPE *codingType) {
            for (size_t i = 0;
         i < sizeof(kVideoCodingMapEntry) / sizeof(kVideoCodingMapEntry[0]);
         ++i) {
        if (!strcasecmp(mime, kVideoCodingMapEntry[i].mMime)) {
            *codingType = kVideoCodingMapEntry[i].mVideoCodingType;
            return OK;
        }
    }

    *codingType = OMX_VIDEO_CodingUnused;
    ALOGE("Can not find coding type ,%s: UNSUPPORTED", mime);

    return ERROR_UNSUPPORTED;
}

bool MediaVendorExt::isVendorSoftDecoder(const char *) {
    return false;
}

bool MediaVendorExt::isAudioExtendFormat(const char *) {
    return false;
}

bool MediaVendorExt::isExtendFormat(const char *) {
    return false;
}

bool MediaVendorExt::isAudioExtendCoding(int) {
    return false;
}
int MediaVendorExt::getAudioExtendParameter(int, uint32_t ,const sp<IOMXNode> &OMXNode, sp<AMessage> &notify) {
    if (OMXNode == NULL ||notify == NULL)
        ALOGI("AVUtils::getAudioExtendParameter err");
    return -1;
}
int MediaVendorExt::setAudioExtendParameter(const char *,const sp<IOMXNode> &OMXNode, const sp<AMessage> &notify) {
    if (OMXNode == NULL ||notify == NULL)
        ALOGI("AVUtils::setAudioExtendParameter err");
    return -1;
}

int MediaVendorExt::handleExtendParameter(const char *,const sp<IOMXNode> &OMXNode, const sp<AMessage> &notify) {
    if (OMXNode == NULL ||notify == NULL)
        ALOGI("AVUtils::setVideoExtendParameter err");
    return -1;
}

void MediaVendorExt::addExtendXML(MediaCodecsXmlParser*) {
    ALOGI("AVUtils::addExtendXML");
    //addExtendXML(xmlparser);
    return;
}

bool MediaVendorExt::isExtendPlayer(player_type) {
    return false;
}

status_t MediaVendorExt::convertMetaDataToMessage(
        const sp<MetaData> &, sp<AMessage> &) {
    return OK;
}

status_t MediaVendorExt::convertMessageToMetaData(
            const sp<AMessage> &, sp<MetaData> &) {
    return OK;
}



void* gMediaVendorExtPlugin = NULL;

static MediaVendorExt* getMediaVendorExtPlugin() {
    if (!gMediaVendorExtPlugin) {
        gMediaVendorExtPlugin = dlopen("libmediavendor_ext.so", RTLD_NOW);
        if (gMediaVendorExtPlugin == NULL) {
            ALOGD("unable to dlopen libmediavendor_ext: %s", dlerror());
            return NULL;
        }
    }

    typedef void *(*createMediaVendorExt)(void);


    createMediaVendorExt getMediaVendorExt = (createMediaVendorExt)dlsym(gMediaVendorExtPlugin, "MediaVendorExt");
    if (getMediaVendorExt == NULL) {
        dlclose(gMediaVendorExtPlugin);
        gMediaVendorExtPlugin = NULL;
        ALOGE("can not create AmVideoDec_create\n");
        return NULL;
    }
    MediaVendorExt* hanle = (MediaVendorExt*)(*getMediaVendorExt)();
    return hanle;
}


//static
MediaVendorExt* MediaVendorExt::imp() {
    if (gImp != NULL) {
        return gImp;
    }
    gImp = getMediaVendorExtPlugin();
    if (gImp == NULL) {
        gImp = new MediaVendorExt();
    }
    return gImp;
}



} //namespace android

