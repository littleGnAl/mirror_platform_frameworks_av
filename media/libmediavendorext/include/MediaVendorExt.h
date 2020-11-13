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

#ifndef _MEDIA_VENDOR_EXT_H_
#define _MEDIA_VENDOR_EXT_H_

#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/xmlparser/MediaCodecsXmlParser.h>
#include <OMX_Video.h>
#include <media/IOMX.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/MediaPlayerInterface.h>


namespace android {

/*
 * Common delegate to the classes in libstagefright
 */
struct MediaVendorExt {
    MediaVendorExt() {}

    virtual const char *getComponentRole(bool isEncoder, const char *mime);

    virtual status_t getVideoCodingTypeFromMimeEx(
        const char *, OMX_VIDEO_CODINGTYPE *);

    virtual bool isVendorSoftDecoder(const char *);

    virtual bool isAudioExtendFormat(const char *);

    virtual bool isAudioExtendCoding(int);

    virtual int getAudioExtendParameter(int, uint32_t ,const sp<IOMXNode> &OMXNode, sp<AMessage> &notify);

    virtual int setAudioExtendParameter(const char *,const sp<IOMXNode> &OMXNode,const sp<AMessage> &notify);

    virtual bool isExtendFormat(const char *);

    virtual int handleExtendParameter(const char *,const sp<IOMXNode> &OMXNode,const sp<AMessage> &notify);

    virtual void addExtendXML(MediaCodecsXmlParser*);

    virtual bool isExtendPlayer(player_type);

    virtual status_t convertMetaDataToMessage(
        const sp<MetaData> &, sp<AMessage> &);

    virtual status_t  convertMessageToMetaData(
            const sp<AMessage> &, sp<MetaData> &);

    static MediaVendorExt* imp();


protected:
    virtual ~MediaVendorExt() {}
    static MediaVendorExt* gImp;

private:
    MediaVendorExt(const MediaVendorExt &);
    MediaVendorExt &operator=(const MediaVendorExt &);

};

}

#endif // _AV_EXTENSIONS__H_
