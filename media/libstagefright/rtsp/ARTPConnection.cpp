/*
 * Copyright (C) 2010 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "ARTPConnection"
#include <utils/Log.h>

#include "ARTPAssembler.h"
#include "ARTPConnection.h"

#include "ARTPSource.h"
#include "ASessionDescription.h"

#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/foundation/hexdump.h>

#include <arpa/inet.h>
#include <sys/socket.h>

namespace android {

static const size_t kMaxUDPSize = 1500;

static uint16_t u16at(const uint8_t *data) {
    return data[0] << 8 | data[1];
}

static uint32_t u32at(const uint8_t *data) {
    return u16at(data) << 16 | u16at(&data[2]);
}

static uint64_t u64at(const uint8_t *data) {
    return (uint64_t)(u32at(data)) << 32 | u32at(&data[4]);
}

// static
const int64_t ARTPConnection::kSelectTimeoutUs = 1000LL;

struct ARTPConnection::StreamInfo {
    bool isIPv6;
    int mRTPSocket;
    int mRTCPSocket;
    sp<ASessionDescription> mSessionDesc;
    size_t mIndex;
    sp<AMessage> mNotifyMsg;
    KeyedVector<uint32_t, sp<ARTPSource> > mSources;

    int64_t mNumRTCPPacketsReceived;
    int64_t mNumRTPPacketsReceived;
    struct sockaddr_in mRemoteRTCPAddr;
    struct sockaddr_in6 mRemoteRTCPAddr6;

    bool mIsInjected;
};

ARTPConnection::ARTPConnection(uint32_t flags)
    : mFlags(flags),
      mPollEventPending(false),
      mLastReceiverReportTimeUs(-1) {
}

ARTPConnection::~ARTPConnection() {
}

void ARTPConnection::addStream(
        int rtpSocket, int rtcpSocket,
        const sp<ASessionDescription> &sessionDesc,
        size_t index,
        const sp<AMessage> &notify,
        bool injected) {
    sp<AMessage> msg = new AMessage(kWhatAddStream, this);
    msg->setInt32("rtp-socket", rtpSocket);
    msg->setInt32("rtcp-socket", rtcpSocket);
    msg->setObject("session-desc", sessionDesc);
    msg->setSize("index", index);
    msg->setMessage("notify", notify);
    msg->setInt32("injected", injected);
    msg->post();
}

void ARTPConnection::removeStream(int rtpSocket, int rtcpSocket) {
    sp<AMessage> msg = new AMessage(kWhatRemoveStream, this);
    msg->setInt32("rtp-socket", rtpSocket);
    msg->setInt32("rtcp-socket", rtcpSocket);
    msg->post();
}

static void bumpSocketBufferSize(int s) {
    int size = 256 * 1024;
    CHECK_EQ(setsockopt(s, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)), 0);
}

// static
void ARTPConnection::MakePortPair(
        int *rtpSocket, int *rtcpSocket, unsigned *rtpPort) {
    *rtpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK_GE(*rtpSocket, 0);

    bumpSocketBufferSize(*rtpSocket);

    *rtcpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK_GE(*rtcpSocket, 0);

    bumpSocketBufferSize(*rtcpSocket);

    /* rand() * 1000 may overflow int type, use long long */
    unsigned start = (unsigned)((rand()* 1000LL)/RAND_MAX) + 15550;
    start &= ~1;

    for (unsigned port = start; port < 65535; port += 2) {
        struct sockaddr_in addr;
        memset(addr.sin_zero, 0, sizeof(addr.sin_zero));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(port);

        if (bind(*rtpSocket,
                 (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
            continue;
        }

        addr.sin_port = htons(port + 1);

        if (bind(*rtcpSocket,
                 (const struct sockaddr *)&addr, sizeof(addr)) == 0) {
            *rtpPort = port;
            return;
        } else {
            // we should recreate a RTP socket to avoid bind other port in same RTP socket
            close(*rtpSocket);

            *rtpSocket = socket(AF_INET, SOCK_DGRAM, 0);
            CHECK_GE(*rtpSocket, 0);
            bumpSocketBufferSize(*rtpSocket);
        }
    }

    TRESPASS();
}

// static
void ARTPConnection::MakeRTPSocketPair(
        int *rtpSocket, int *rtcpSocket, const char *localIp, const char *remoteIp,
        unsigned localPort, unsigned remotePort) {
    bool isIPv6 = false;
    if (strchr(localIp, ':') != NULL)
        isIPv6 = true;

    *rtpSocket = socket(isIPv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    CHECK_GE(*rtpSocket, 0);

    bumpSocketBufferSize(*rtpSocket);

    *rtcpSocket = socket(isIPv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    CHECK_GE(*rtcpSocket, 0);

    bumpSocketBufferSize(*rtcpSocket);

    struct sockaddr *addr;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;

    if (isIPv6) {
        addr = (struct sockaddr *)&addr6;
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, localIp, &addr6.sin6_addr);
        addr6.sin6_port = htons((uint16_t)localPort);
    } else {
        addr = (struct sockaddr *)&addr4;
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_addr.s_addr = inet_addr(localIp);
        addr4.sin_port = htons((uint16_t)localPort);
    }

    int sockopt = 1;
    setsockopt(*rtpSocket, SOL_SOCKET, SO_REUSEPORT, (int *)&sockopt, sizeof(sockopt));
    setsockopt(*rtcpSocket, SOL_SOCKET, SO_REUSEPORT, (int *)&sockopt, sizeof(sockopt));

    int sizeSockSt = isIPv6 ? sizeof(addr6) : sizeof(addr4);

    if (bind(*rtpSocket, addr, sizeSockSt) == 0) {
        ALOGI("rtp socket successfully binded. addr=%s:%d", localIp, localPort);
    } else {
        ALOGE("failed to bind rtp socket addr=%s:%d err=%s", localIp, localPort, strerror(errno));
        return;
    }

    if (isIPv6)
        addr6.sin6_port = htons(localPort + 1);
    else
        addr4.sin_port = htons(localPort + 1);

    if (bind(*rtcpSocket, addr, sizeSockSt) == 0) {
        ALOGI("rtcp socket successfully binded. addr=%s:%d", localIp, localPort + 1);
    } else {
        ALOGE("failed to bind rtcp socket addr=%s:%d err=%s", localIp,
                localPort + 1, strerror(errno));
    }

    // Re uses addr variable as remote addr.
    if (isIPv6) {
        memset(&addr6, 0, sizeof(addr6));
        addr6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, remoteIp, &addr6.sin6_addr);
        addr6.sin6_port = htons((uint16_t)remotePort);
    } else {
        memset(&addr4, 0, sizeof(addr4));
        addr4.sin_family = AF_INET;
        addr4.sin_addr.s_addr = inet_addr(remoteIp);
        addr4.sin_port = htons((uint16_t)remotePort);
    }
    if (connect(*rtpSocket, addr, sizeSockSt) == 0) {
        ALOGI("rtp socket successfully connected to remote=%s:%d", remoteIp, remotePort);
    } else {
        ALOGE("failed to connect rtp socket to remote addr=%s:%d err=%s", remoteIp,
                remotePort, strerror(errno));
        return;
    }

    if (isIPv6)
        addr6.sin6_port = htons(remotePort + 1);
    else
        addr4.sin_port = htons(remotePort + 1);

    if (connect(*rtcpSocket, addr, sizeSockSt) == 0) {
        ALOGI("rtcp socket successfully connected to remote=%s:%d", remoteIp, remotePort + 1);
    } else {
        ALOGE("failed to connect rtcp socket addr=%s:%d err=%s", remoteIp,
                remotePort + 1, strerror(errno));
        return;
    }
}

void ARTPConnection::onMessageReceived(const sp<AMessage> &msg) {
    switch (msg->what()) {
        case kWhatAddStream:
        {
            onAddStream(msg);
            break;
        }

        case kWhatRemoveStream:
        {
            onRemoveStream(msg);
            break;
        }

        case kWhatPollStreams:
        {
            onPollStreams();
            break;
        }

        case kWhatInjectPacket:
        {
            onInjectPacket(msg);
            break;
        }

        default:
        {
            TRESPASS();
            break;
        }
    }
}

void ARTPConnection::onAddStream(const sp<AMessage> &msg) {
    mStreams.push_back(StreamInfo());
    StreamInfo *info = &*--mStreams.end();

    int32_t s;
    CHECK(msg->findInt32("rtp-socket", &s));
    info->mRTPSocket = s;
    CHECK(msg->findInt32("rtcp-socket", &s));
    info->mRTCPSocket = s;

    int32_t injected;
    CHECK(msg->findInt32("injected", &injected));

    info->mIsInjected = injected;

    sp<RefBase> obj;
    CHECK(msg->findObject("session-desc", &obj));
    info->mSessionDesc = static_cast<ASessionDescription *>(obj.get());

    CHECK(msg->findSize("index", &info->mIndex));
    CHECK(msg->findMessage("notify", &info->mNotifyMsg));

    info->mNumRTCPPacketsReceived = 0;
    info->mNumRTPPacketsReceived = 0;
    memset(&info->mRemoteRTCPAddr, 0, sizeof(info->mRemoteRTCPAddr));
    memset(&info->mRemoteRTCPAddr6, 0, sizeof(info->mRemoteRTCPAddr6));

    if (!injected) {
        postPollEvent();
    }
}

void ARTPConnection::onRemoveStream(const sp<AMessage> &msg) {
    int32_t rtpSocket, rtcpSocket;
    CHECK(msg->findInt32("rtp-socket", &rtpSocket));
    CHECK(msg->findInt32("rtcp-socket", &rtcpSocket));

    List<StreamInfo>::iterator it = mStreams.begin();
    while (it != mStreams.end()
           && (it->mRTPSocket != rtpSocket || it->mRTCPSocket != rtcpSocket)) {
        ++it;
    }

    if (it == mStreams.end()) {
        return;
    }

    mStreams.erase(it);
}

void ARTPConnection::postPollEvent() {
    if (mPollEventPending) {
        return;
    }

    sp<AMessage> msg = new AMessage(kWhatPollStreams, this);
    msg->post();

    mPollEventPending = true;
}

void ARTPConnection::onPollStreams() {
    mPollEventPending = false;

    if (mStreams.empty()) {
        return;
    }

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = kSelectTimeoutUs;

    fd_set rs;
    FD_ZERO(&rs);

    int maxSocket = -1;
    for (List<StreamInfo>::iterator it = mStreams.begin();
         it != mStreams.end(); ++it) {
        if ((*it).mIsInjected) {
            continue;
        }

        FD_SET(it->mRTPSocket, &rs);
        FD_SET(it->mRTCPSocket, &rs);

        if (it->mRTPSocket > maxSocket) {
            maxSocket = it->mRTPSocket;
        }
        if (it->mRTCPSocket > maxSocket) {
            maxSocket = it->mRTCPSocket;
        }
    }

    if (maxSocket == -1) {
        return;
    }

    int res = select(maxSocket + 1, &rs, NULL, NULL, &tv);

    if (res > 0) {
        List<StreamInfo>::iterator it = mStreams.begin();
        while (it != mStreams.end()) {
            if ((*it).mIsInjected) {
                ++it;
                continue;
            }

            status_t err = OK;
            if (FD_ISSET(it->mRTPSocket, &rs)) {
                err = receive(&*it, true);
            }
            if (err == OK && FD_ISSET(it->mRTCPSocket, &rs)) {
                err = receive(&*it, false);
            }

            if (err == -ECONNRESET) {
                // socket failure, this stream is dead, Jim.

                ALOGW("failed to receive RTP/RTCP datagram.");
                it = mStreams.erase(it);
                continue;
            }

            ++it;
        }
    }

    int64_t nowUs = ALooper::GetNowUs();
    if (mLastReceiverReportTimeUs <= 0
            || mLastReceiverReportTimeUs + 5000000LL <= nowUs) {
        sp<ABuffer> buffer = new ABuffer(kMaxUDPSize);
        List<StreamInfo>::iterator it = mStreams.begin();
        while (it != mStreams.end()) {
            StreamInfo *s = &*it;

            if (s->mIsInjected) {
                ++it;
                continue;
            }

            if (s->mNumRTCPPacketsReceived == 0) {
                // We have never received any RTCP packets on this stream,
                // we don't even know where to send a report.
                ++it;
                continue;
            }

            buffer->setRange(0, 0);

            for (size_t i = 0; i < s->mSources.size(); ++i) {
                sp<ARTPSource> source = s->mSources.valueAt(i);

                source->addReceiverReport(buffer);

                if (mFlags & kRegularlyRequestFIR) {
                    source->addFIR(buffer);
                }
            }

            if (buffer->size() > 0) {
                ALOGV("Sending RR...");

                struct sockaddr* pRemoteRTCPAddr;
                int sizeSockSt;
                if (s->isIPv6) {
                    pRemoteRTCPAddr = (struct sockaddr *)&s->mRemoteRTCPAddr6;
                    sizeSockSt = sizeof(struct sockaddr_in6);
                } else {
                    pRemoteRTCPAddr = (struct sockaddr *)&s->mRemoteRTCPAddr;
                    sizeSockSt = sizeof(struct sockaddr_in);
                }

                ssize_t n;
                do {
                    n = sendto(
                            s->mRTCPSocket, buffer->data(), buffer->size(), 0,
                            pRemoteRTCPAddr, sizeSockSt);
                } while (n < 0 && errno == EINTR);

                if (n <= 0) {
                    ALOGW("failed to send RTCP receiver report (%s).",
                         n == 0 ? "connection gone" : strerror(errno));

                    it = mStreams.erase(it);
                    continue;
                }

                CHECK_EQ(n, (ssize_t)buffer->size());

                mLastReceiverReportTimeUs = nowUs;
            }

            ++it;
        }
    }

    if (!mStreams.empty()) {
        postPollEvent();
    }
}

status_t ARTPConnection::receive(StreamInfo *s, bool receiveRTP) {
    ALOGV("receiving %s", receiveRTP ? "RTP" : "RTCP");

    CHECK(!s->mIsInjected);

    sp<ABuffer> buffer = new ABuffer(65536);

    struct sockaddr *pRemoteRTCPAddr;
    int sizeSockSt;
    if (s->isIPv6) {
        pRemoteRTCPAddr = (struct sockaddr *)&s->mRemoteRTCPAddr6;
        sizeSockSt = sizeof(struct sockaddr_in6);
    } else {
        pRemoteRTCPAddr = (struct sockaddr *)&s->mRemoteRTCPAddr;
        sizeSockSt = sizeof(struct sockaddr_in);
    }
    socklen_t remoteAddrLen =
        (!receiveRTP && s->mNumRTCPPacketsReceived == 0)
            ? sizeSockSt : 0;

    ssize_t nbytes;
    do {
        nbytes = recvfrom(
            receiveRTP ? s->mRTPSocket : s->mRTCPSocket,
            buffer->data(),
            buffer->capacity(),
            0,
            remoteAddrLen > 0 ? pRemoteRTCPAddr : NULL,
            remoteAddrLen > 0 ? &remoteAddrLen : NULL);
    } while (nbytes < 0 && errno == EINTR);

    if (nbytes <= 0) {
        return -ECONNRESET;
    }

    buffer->setRange(0, nbytes);

    // ALOGI("received %d bytes.", buffer->size());

    status_t err;
    if (receiveRTP) {
        err = parseRTP(s, buffer);
    } else {
        err = parseRTCP(s, buffer);
    }

    return err;
}

status_t ARTPConnection::parseRTP(StreamInfo *s, const sp<ABuffer> &buffer) {
    if (s->mNumRTPPacketsReceived++ == 0) {
        sp<AMessage> notify = s->mNotifyMsg->dup();
        notify->setInt32("first-rtp", true);
        notify->post();
    }

    size_t size = buffer->size();

    if (size < 12) {
        // Too short to be a valid RTP header.
        return -1;
    }

    const uint8_t *data = buffer->data();

    if ((data[0] >> 6) != 2) {
        // Unsupported version.
        return -1;
    }

    if (data[0] & 0x20) {
        // Padding present.

        size_t paddingLength = data[size - 1];

        if (paddingLength + 12 > size) {
            // If we removed this much padding we'd end up with something
            // that's too short to be a valid RTP header.
            return -1;
        }

        size -= paddingLength;
    }

    int numCSRCs = data[0] & 0x0f;

    size_t payloadOffset = 12 + 4 * numCSRCs;

    if (size < payloadOffset) {
        // Not enough data to fit the basic header and all the CSRC entries.
        return -1;
    }

    if (data[0] & 0x10) {
        // Header eXtension present.

        if (size < payloadOffset + 4) {
            // Not enough data to fit the basic header, all CSRC entries
            // and the first 4 bytes of the extension header.

            return -1;
        }

        const uint8_t *extensionData = &data[payloadOffset];

        size_t extensionLength =
            4 * (extensionData[2] << 8 | extensionData[3]);

        if (size < payloadOffset + 4 + extensionLength) {
            return -1;
        }

        payloadOffset += 4 + extensionLength;
    }

    uint32_t srcId = u32at(&data[8]);

    sp<ARTPSource> source = findSource(s, srcId);

    uint32_t rtpTime = u32at(&data[4]);

    sp<AMessage> meta = buffer->meta();
    meta->setInt32("ssrc", srcId);
    meta->setInt32("rtp-time", rtpTime);
    meta->setInt32("PT", data[1] & 0x7f);
    meta->setInt32("M", data[1] >> 7);

    buffer->setInt32Data(u16at(&data[2]));
    buffer->setRange(payloadOffset, size - payloadOffset);

    source->processRTPPacket(buffer);

    return OK;
}

status_t ARTPConnection::parseRTCP(StreamInfo *s, const sp<ABuffer> &buffer) {
    if (s->mNumRTCPPacketsReceived++ == 0) {
        sp<AMessage> notify = s->mNotifyMsg->dup();
        notify->setInt32("first-rtcp", true);
        notify->post();
    }

    const uint8_t *data = buffer->data();
    size_t size = buffer->size();

    while (size > 0) {
        if (size < 8) {
            // Too short to be a valid RTCP header
            return -1;
        }

        if ((data[0] >> 6) != 2) {
            // Unsupported version.
            return -1;
        }

        if (data[0] & 0x20) {
            // Padding present.

            size_t paddingLength = data[size - 1];

            if (paddingLength + 12 > size) {
                // If we removed this much padding we'd end up with something
                // that's too short to be a valid RTP header.
                return -1;
            }

            size -= paddingLength;
        }

        size_t headerLength = 4 * (data[2] << 8 | data[3]) + 4;

        if (size < headerLength) {
            // Only received a partial packet?
            return -1;
        }

        switch (data[1]) {
            case 200:
            {
                parseSR(s, data, headerLength);
                break;
            }

            case 201:  // RR
            case 202:  // SDES
            case 204:  // APP
                break;

            case 205:  // TSFB (transport layer specific feedback)
                parseTSFB(s, data, headerLength);
                break;
            case 206:  // PSFB (payload specific feedback)
                // hexdump(data, headerLength);
                parsePSFB(s, data, headerLength);
                ALOGI("RTCP packet type %u of size %zu", (unsigned)data[1], headerLength);
                break;

            case 203:
            {
                parseBYE(s, data, headerLength);
                break;
            }

            default:
            {
                ALOGW("Unknown RTCP packet type %u of size %zu",
                     (unsigned)data[1], headerLength);
                break;
            }
        }

        data += headerLength;
        size -= headerLength;
    }

    return OK;
}

status_t ARTPConnection::parseBYE(
        StreamInfo *s, const uint8_t *data, size_t size) {
    size_t SC = data[0] & 0x3f;

    if (SC == 0 || size < (4 + SC * 4)) {
        // Packet too short for the minimal BYE header.
        return -1;
    }

    uint32_t id = u32at(&data[4]);

    sp<ARTPSource> source = findSource(s, id);

    source->byeReceived();

    return OK;
}

status_t ARTPConnection::parseSR(
        StreamInfo *s, const uint8_t *data, size_t size) {
    size_t RC = data[0] & 0x1f;

    if (size < (7 + RC * 6) * 4) {
        // Packet too short for the minimal SR header.
        return -1;
    }

    uint32_t id = u32at(&data[4]);
    uint64_t ntpTime = u64at(&data[8]);
    uint32_t rtpTime = u32at(&data[16]);

#if 0
    ALOGI("XXX timeUpdate: ssrc=0x%08x, rtpTime %u == ntpTime %.3f",
         id,
         rtpTime,
         (ntpTime >> 32) + (double)(ntpTime & 0xffffffff) / (1ll << 32));
#endif

    sp<ARTPSource> source = findSource(s, id);

    source->timeUpdate(rtpTime, ntpTime);

    return 0;
}

status_t ARTPConnection::parseTSFB(
        StreamInfo *s, const uint8_t *data, size_t size) {
    uint8_t msgType = data[0] & 0x1f;
    uint32_t id = u32at(&data[4]);

    if (size < 12) {
        // broken packet
        return -1;
    }

    const uint8_t *ptr = &data[12];
    size -= 12;

    using namespace std;
    size_t FCISize;
    switch(msgType) {
        case 1:     // Generic NACK
        {
            FCISize = 4;
            while (size >= FCISize) {
                uint16_t PID = u16at(&ptr[0]);  // lost packet RTP number
                uint16_t BLP = u16at(&ptr[2]);  // Bitmask of following Lost Packets

                size -= FCISize;
                ptr += FCISize;

                AString list_of_losts;
                list_of_losts.append(PID);
                for (int i=0 ; i<16 ; i++) {
                    bool is_lost = BLP & (0x1 << i);
                    if (is_lost) {
                        list_of_losts.append(", ");
                        list_of_losts.append(PID + i);
                    }
                }
                ALOGI("Opponent losts packet of RTP %s", list_of_losts.c_str());
            }
            break;
        }
        case 3:     // TMMBR
        case 4:     // TMMBN
        {
            FCISize = 8;
            while (size >= FCISize) {
                uint32_t MxTBR = u32at(&ptr[4]);
                uint32_t MxTBRExp = MxTBR >> 26;
                uint32_t MxTBRMantissa = (MxTBR >> 9) & 0x01FFFF;
                uint32_t overhead = MxTBR & 0x01FF;

                size -= FCISize;
                ptr += FCISize;

                uint32_t bitRate = (1 << MxTBRExp) * MxTBRMantissa;

                if (msgType == 3)
                    ALOGI("Op -> UE Req Tx bitrate : %d X 2^%d = %d",
                        MxTBRMantissa, MxTBRExp, bitRate);
                else if (msgType == 4)
                    ALOGI("OP -> UE Noti Rx bitrate : %d X 2^%d = %d",
                        MxTBRMantissa, MxTBRExp, bitRate);

                sp<AMessage> notify = s->mNotifyMsg->dup();
                notify->setInt32("IMS-Rx-notice", 1);
                notify->setInt32("payload-type", 205);
                notify->setInt32("feedback-type", msgType);
                notify->setInt32("sender", id);
                notify->setInt32("bit-rate", bitRate);
                notify->post();
                ALOGI("overhead : %d", overhead);
            }
            break;
        }
        default:
        {
            ALOGI("Not supported TSFB type %d", msgType);
            break;
        }
    }

    return 0;
}

status_t ARTPConnection::parsePSFB(
        StreamInfo *s, const uint8_t *data, size_t size) {
    uint8_t msgType = data[0] & 0x1f;
    uint32_t id = u32at(&data[4]);

    if (size < 12) {
        // broken packet
        return -1;
    }

    size -= 12;

    using namespace std;
    switch(msgType) {
        case 1:     // Picture Loss Indication (PLI)
        {
            CHECK(size == 0);   // PLI does not need parameters
            sp<AMessage> notify = s->mNotifyMsg->dup();
            notify->setInt32("IMS-Rx-notice", 1);
            notify->setInt32("payload-type", 206);
            notify->setInt32("feedback-type", msgType);
            notify->setInt32("sender", id);
            notify->post();
            ALOGI("PLI detected.");
            break;
        }
        default:
        {
            ALOGI("Not supported PSFB type %d", msgType);
            break;
        }
    }

    return 0;
}
sp<ARTPSource> ARTPConnection::findSource(StreamInfo *info, uint32_t srcId) {
    sp<ARTPSource> source;
    ssize_t index = info->mSources.indexOfKey(srcId);
    if (index < 0) {
        index = info->mSources.size();

        source = new ARTPSource(
                srcId, info->mSessionDesc, info->mIndex, info->mNotifyMsg);

        info->mSources.add(srcId, source);
    } else {
        source = info->mSources.valueAt(index);
    }

    return source;
}

void ARTPConnection::injectPacket(int index, const sp<ABuffer> &buffer) {
    sp<AMessage> msg = new AMessage(kWhatInjectPacket, this);
    msg->setInt32("index", index);
    msg->setBuffer("buffer", buffer);
    msg->post();
}

void ARTPConnection::onInjectPacket(const sp<AMessage> &msg) {
    int32_t index;
    CHECK(msg->findInt32("index", &index));

    sp<ABuffer> buffer;
    CHECK(msg->findBuffer("buffer", &buffer));

    List<StreamInfo>::iterator it = mStreams.begin();
    while (it != mStreams.end()
           && it->mRTPSocket != index && it->mRTCPSocket != index) {
        ++it;
    }

    if (it == mStreams.end()) {
        TRESPASS();
    }

    StreamInfo *s = &*it;

    if (it->mRTPSocket == index) {
        parseRTP(s, buffer);
    } else {
        parseRTCP(s, buffer);
    }
}

}  // namespace android

