/*
 * Copyright (C) 2019 The Android Open Source Project
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

package com.android.media.benchmark.library;

import android.media.MediaCodec;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.util.Log;

import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.ByteBuffer;

public class Extractor {
    private static final String TAG = "Extractor";
    private static final int kMaxBufSize = 1024 * 1024 * 16;
    private MediaExtractor mExtractor;
    private ByteBuffer mFrameBuffer;
    private MediaCodec.BufferInfo mBufferInfo;
    private Stats mStats;
    private long mDurationUs;

    public Extractor() {
        mFrameBuffer = ByteBuffer.allocate(kMaxBufSize);
        mBufferInfo = new MediaCodec.BufferInfo();
        mStats = new Stats();
    }

    public int setUpExtractor(FileDescriptor fileDescriptor) throws IOException {
        long sTime = mStats.getCurTime();
        mExtractor = new MediaExtractor();
        mExtractor.setDataSource(fileDescriptor);
        long eTime = mStats.getCurTime();
        long timeTaken = mStats.getTimeDiff(sTime, eTime);
        mStats.setInitTime(timeTaken);
        return mExtractor.getTrackCount();
    }

    public MediaFormat getFormat(int trackID) { return mExtractor.getTrackFormat(trackID); }

    public ByteBuffer getFrameBuffer() { return this.mFrameBuffer; }

    public MediaCodec.BufferInfo getBufferInfo() { return this.mBufferInfo; }

    public long getClipDuration() { return this.mDurationUs; }

    public int getFrameSample() {
        int sampleSize = mExtractor.readSampleData(mFrameBuffer, 0);
        if (sampleSize < 0) {
            mBufferInfo.flags = MediaCodec.BUFFER_FLAG_END_OF_STREAM;
            mBufferInfo.size = 0;
        } else {
            mBufferInfo.size = sampleSize;
            mBufferInfo.offset = 0;
            mBufferInfo.flags = mExtractor.getSampleFlags();
            mBufferInfo.presentationTimeUs = mExtractor.getSampleTime();
            mExtractor.advance();
        }
        return sampleSize;
    }

    public int selectExtractorTrack(int trackId) {
        MediaFormat trackFormat = mExtractor.getTrackFormat(trackId);
        mDurationUs = trackFormat.getLong(MediaFormat.KEY_DURATION);
        if (mDurationUs < 0) {
            Log.e(TAG, "Invalid Clip");
            return -1;
        }
        mExtractor.selectTrack(trackId);
        return 0;
    }

    public void unselectExtractorTrack(int trackId) { mExtractor.unselectTrack(trackId); }

    public void deinitExtractor() {
        long sTime = mStats.getCurTime();
        mExtractor.release();
        long eTime = mStats.getCurTime();
        long timeTaken = mStats.getTimeDiff(sTime, eTime);
        mStats.setDeInitTime(timeTaken);
    }

    public int extractSample(int currentTrack) {
        int status;
        status = selectExtractorTrack(currentTrack);
        if (status == -1) {
            Log.e(TAG, "Failed to select track");
            return -1;
        }
        mStats.setStartTime();
        while (true) {
            int readSampleSize = getFrameSample();
            if (readSampleSize <= 0) {
                break;
            }
            mStats.addOutputTime();
            mStats.addFrameSize(readSampleSize);
        }
        unselectExtractorTrack(currentTrack);
        return 0;
    }

    public void dumpStatistics(String inputReference) {
        String operation = "extract";
        mStats.dumpStatistics(operation, inputReference, mDurationUs);
    }
}