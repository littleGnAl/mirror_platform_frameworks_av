/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef PLAYLIST_FETCHER_H_

#define PLAYLIST_FETCHER_H_

#include <media/stagefright/foundation/AHandler.h>

#include "mpeg2ts/ATSParser.h"
#include "LiveSession.h"

namespace android {

struct ABuffer;
struct AnotherPacketSource;
struct DataSource;
struct HTTPBase;
struct LiveDataSource;
struct M3UParser;
class String8;

struct PlaylistFetcher : public AHandler {
    enum {
        kWhatStarted,
        kWhatPaused,
        kWhatStopped,
        kWhatError,
        kWhatDurationUpdate,
        kWhatTemporarilyDoneFetching,
        kWhatPrepared,
        kWhatPreparationFailed,
        kWhatStartedAt,
    };

    PlaylistFetcher(
            const sp<AMessage> &notify,
            const sp<LiveSession> &session,
            const char *uri,
            int32_t subtitleGeneration);

    sp<DataSource> getDataSource();

    void startAsync(
            const sp<AnotherPacketSource> &audioSource,
            const sp<AnotherPacketSource> &videoSource,
            const sp<AnotherPacketSource> &subtitleSource,
            int64_t startTimeUs = -1ll,         // starting timestamps
            int64_t fetcherStartTimeUs = -1ll, // starting position when fetcher is created
            int32_t startDiscontinuitySeq = 0,
            bool adaptive = false);

    void pauseAsync();

    void stopAsync(bool clear = true);

    void resumeUntilAsync(const sp<AMessage> &params);

    uint32_t getStreamTypeMask() const {
        return mStreamTypeMask;
    }

    void postMonitorQueue(int64_t delayUs = 0, int64_t minDelayUs = 0);

protected:
    virtual ~PlaylistFetcher();
    virtual void onMessageReceived(const sp<AMessage> &msg);

private:
    enum {
        kMaxNumRetries         = 5,
    };

    enum {
        kWhatStart          = 'strt',
        kWhatPause          = 'paus',
        kWhatStop           = 'stop',
        kWhatMonitorQueue   = 'moni',
        kWhatResumeUntil    = 'rsme',
        kWhatDownloadNext   = 'dlnx',
    };

    static const int64_t kMinBufferedDurationUs;
    static const int64_t kMaxMonitorDelayUs;
    static const int32_t kDownloadBlockSize;
    static const int32_t kNumSkipFrames;

    static bool bufferStartsWithTsSyncByte(const sp<ABuffer>& buffer);
    static bool bufferStartsWithWebVTTMagicSequence(const sp<ABuffer>& buffer);

    // notifications to mSession
    sp<AMessage> mNotify;
    sp<AMessage> mStartTimeUsNotify;

    sp<LiveSession> mSession;
    AString mURI;

    uint32_t mStreamTypeMask;
    uint32_t mCheckSyncMask;
    int64_t mStartTimeUs;

    ssize_t mDiscontinuitySeq;
    bool mStartTimeUsRelative;
    sp<AMessage> mStopParams; // message containing the latest timestamps we should fetch.

    KeyedVector<LiveSession::StreamType, sp<AnotherPacketSource> >
        mPacketSources;

    KeyedVector<AString, sp<ABuffer> > mAESKeyForURI;

    int64_t mLastPlaylistFetchTimeUs;
    sp<M3UParser> mPlaylist;
    int32_t mSeqNumber;
    int32_t mNumRetries;
    bool mStartup;
    bool mAdaptive;
    bool mPrepared;
    int64_t mNextPTSTimeUs;

    int32_t mMonitorQueueGeneration;
    const int32_t mSubtitleGeneration;

    enum RefreshState {
        INITIAL_MINIMUM_RELOAD_DELAY,
        FIRST_UNCHANGED_RELOAD_ATTEMPT,
        SECOND_UNCHANGED_RELOAD_ATTEMPT,
        THIRD_UNCHANGED_RELOAD_ATTEMPT
    };
    RefreshState mRefreshState;

    uint8_t mPlaylistHash[16];

    sp<ATSParser> mTSParser;

    bool mFirstPTSValid;
    uint64_t mFirstPTS;
    int64_t mFirstTimeUs;
    int64_t mAbsoluteTimeAnchorUs;
    sp<AnotherPacketSource> mVideoBuffer;
    bool mCheckBandwidth;
    int64_t mFetcherStartTimeUs;

    // Stores the initialization vector to decrypt the next block of cipher text, which can
    // either be derived from the sequence number, read from the manifest, or copied from
    // the last block of cipher text (cipher-block chaining).
    unsigned char mAESInitVec[16];

    // Set first to true if decrypting the first segment of a playlist segment. When
    // first is true, reset the initialization vector based on the available
    // information in the manifest; otherwise, use the initialization vector as
    // updated by the last call to AES_cbc_encrypt.
    //
    // For the input to decrypt correctly, decryptBuffer must be called on
    // consecutive byte ranges on block boundaries, e.g. 0..15, 16..47, 48..63,
    // and so on.
    status_t decryptBuffer(
            size_t playlistIndex, const sp<ABuffer> &buffer,
            bool first = true);
    status_t checkDecryptPadding(const sp<ABuffer> &buffer);

    void cancelMonitorQueue();

    int64_t delayUsToRefreshPlaylist() const;
    status_t refreshPlaylist();

    // Returns the media time in us of the segment specified by seqNumber.
    // This is computed by summing the durations of all segments before it.
    int64_t getSegmentStartTimeUs(int32_t seqNumber) const;

    status_t onStart(const sp<AMessage> &msg);
    void onPause();
    void onStop(const sp<AMessage> &msg);
    void onMonitorQueue();
    void onDownloadNext();

    // Resume a fetcher to continue until the stopping point stored in msg.
    status_t onResumeUntil(const sp<AMessage> &msg);

    const sp<ABuffer> &setAccessUnitProperties(
            const sp<ABuffer> &accessUnit,
            const sp<AnotherPacketSource> &source,
            bool discard = false);
    status_t extractAndQueueAccessUnitsFromTs(const sp<ABuffer> &buffer);

    status_t extractAndQueueAccessUnits(
            const sp<ABuffer> &buffer, const sp<AMessage> &itemMeta);

    void notifyError(status_t err);

    void queueDiscontinuity(
            ATSParser::DiscontinuityType type, const sp<AMessage> &extra);

    int32_t getSynchronizedSeqValues(int64_t firstTimeUs, int64_t &sequenceStartTimeUs);
    int32_t getSeqNumberForDiscontinuity(size_t discontinuitySeq) const;
    int32_t getSeqNumberForTime(int64_t timeUs) const;
    size_t getDiscontinuityForSeqNumber(size_t seq) const;

    void updateDuration();

    // Before resuming a fetcher in onResume, check the remaining duration is longer than that
    // returned by resumeThreshold.
    int64_t resumeThreshold(const sp<AMessage> &msg);

    void synchronizeSeqNumber(int64_t timeUs);

    bool adjustSequenceNumberIfNeeded(int64_t startTimeUs = -1);

    void sendNotify();

    int64_t getSegmentDuration(int32_t seqNumber);

    void getPlaylistBorders(int32_t &first, int32_t &last);

    void updateStartTime(int64_t firstTimeUs, const LiveSession::StreamType stream);

    bool checkVideoLost();

    bool fetcherContainsVideo();

    int64_t getLowestStartTimeUs();

    DISALLOW_EVIL_CONSTRUCTORS(PlaylistFetcher);
};

}  // namespace android

#endif  // PLAYLIST_FETCHER_H_

