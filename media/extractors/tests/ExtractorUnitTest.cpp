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

//#define LOG_NDEBUG 0
#define LOG_TAG "ExtractorUnitTest"
#include <utils/Log.h>

#include <datasource/FileSource.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/MetaDataUtils.h>
#include <media/stagefright/MediaDefs.h>

#include <utils/RefBase.h>

#include "aac/AACExtractor.h"
#include "amr/AMRExtractor.h"
#include "flac/FLACExtractor.h"
#include "midi/MidiExtractor.h"
#include "mkv/MatroskaExtractor.h"
#include "mp3/MP3Extractor.h"
#include "mpeg2/MPEG2PSExtractor.h"
#include "mpeg2/MPEG2TSExtractor.h"
#include "ogg/OggExtractor.h"
#include "wav/WAVExtractor.h"
// #include "mp4/MPEG4Extractor.h"

#include "ExtractorTestEnvironment.h"

using namespace android;

struct trackMetaData {
    char mime[128];
    int32_t width;
    int32_t height;
    int32_t sampleRate;
    int32_t channelCount;
};

// LookUpTable of clips and metadata for component testing
static const struct InputData {
    const char *mime;
    string inputFile;
    int32_t firstParam;
    int32_t secondParam;
} kInputData[] = {
        {MEDIA_MIMETYPE_AUDIO_AAC, "loudsoftaac.aac", 44100, 1},
        {MEDIA_MIMETYPE_AUDIO_AMR_NB, "testamr.amr", 8000, 1},
        {MEDIA_MIMETYPE_AUDIO_AMR_WB, "amrwb.wav", 16000, 1},
        {MEDIA_MIMETYPE_AUDIO_VORBIS,  "john_cage.ogg", 8000, 1},
        {MEDIA_MIMETYPE_AUDIO_MSGSM, "monotestgsm.wav", 8000, 1},
        {MEDIA_MIMETYPE_AUDIO_AAC, "segment000001.ts", 22050, 1},
        {MEDIA_MIMETYPE_AUDIO_FLAC, "sinesweepflac.flac", 44100, 2},
        {MEDIA_MIMETYPE_AUDIO_OPUS, "testopus.opus", 48000, 2},
        {MEDIA_MIMETYPE_AUDIO_VORBIS, "sinesweepvorbis.mkv", 48000, 2},
        {MEDIA_MIMETYPE_AUDIO_MPEG, "sinesweepmp3lame.mp3", 44100, 2},
        {MEDIA_MIMETYPE_VIDEO_VP9, "swirl_144x136_vp9.webm", 144, 136},
        {MEDIA_MIMETYPE_VIDEO_VP8, "swirl_144x136_vp8.webm", 144, 136},
        {MEDIA_MIMETYPE_VIDEO_MPEG2, "swirl_144x136_mpeg2.mpg", 144, 136},
};

static ExtractorTestEnvironment *gEnv = nullptr;

class ExtractorUnitTest : public ::testing::TestWithParam<pair<string, int32_t>> {
  public:
    virtual void SetUp() override {
        mDataSource = nullptr;
        mExtractor = nullptr;
        mExtractorName = unknown_comp;
        mDisableTest = false;

        std::map<std::string, standardExtractors> mapExtractor = {
                {"aac", AAC},     {"amr", AMR},         {"mp3", MP3},        {"ogg", OGG},
                {"wav", WAV},     {"mkv", MKV},         {"flac", FLAC},      {"midi", MIDI},
                {"mpeg4", MPEG4}, {"mpeg2Ts", MPEG2TS}, {"mpeg2Ps", MPEG2PS}};
        // Find the component type
        string writerFormat = GetParam().first;
        if (mapExtractor.find(writerFormat) != mapExtractor.end()) {
            mExtractorName = mapExtractor[writerFormat];
        }
        if (mExtractorName == standardExtractors::unknown_comp) {
            cout << "[   WARN   ] Test Skipped. Invalid extractor\n";
            mDisableTest = true;
        }
    }

    virtual void TearDown() override {
        if (mInputFp) fclose(mInputFp);
        if (mDataSource) mDataSource.clear();
        if (mExtractor) delete mExtractor;
    }

    int32_t setDataSource(string inputFileName);

    int32_t createExtractor();

    enum standardExtractors {
        AAC,
        AMR,
        MP3,
        OGG,
        WAV,
        MKV,
        FLAC,
        MIDI,
        MPEG4,
        MPEG2TS,
        MPEG2PS,
        unknown_comp,
    };

    bool mDisableTest;
    standardExtractors mExtractorName;

    FILE *mInputFp;
    sp<DataSource> mDataSource;
    MediaExtractorPluginHelper *mExtractor;
};

int32_t ExtractorUnitTest::setDataSource(string inputFileName) {
    struct stat buf;
    stat(inputFileName.c_str(), &buf);
    int32_t fd = fileno(mInputFp);
    mDataSource = new FileSource(dup(fd), 0, buf.st_size);
    if (!mDataSource) return -1;
    return 0;
}

int32_t ExtractorUnitTest::createExtractor() {
    switch (mExtractorName) {
        case AAC:
            mExtractor = new AACExtractor(new DataSourceHelper(mDataSource->wrap()), 0);
            break;
        case AMR:
            mExtractor = new AMRExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MP3:
            mExtractor = new MP3Extractor(new DataSourceHelper(mDataSource->wrap()), nullptr);
            break;
        case OGG:
            mExtractor = new OggExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case WAV:
            mExtractor = new WAVExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MKV:
            mExtractor = new MatroskaExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case FLAC:
            mExtractor = new FLACExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        // TODO: Enable MIDI. Test fails for midi currently
        // case MIDI: {
        //     mExtractor = new MidiExtractor(mDataSource->wrap());
        //     break;
        // }
        // TODO: Enable MP4. Build fails currently for mp4 libraries
        // case MPEG4:
        //     mExtractor = new MPEG4Extractor(new DataSourceHelper(mDataSource->wrap()));
        //     break;
        case MPEG2TS:
            mExtractor = new MPEG2TSExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        case MPEG2PS:
            mExtractor = new MPEG2PSExtractor(new DataSourceHelper(mDataSource->wrap()));
            break;
        default:
            return -1;
    }
    if (!mExtractor) return -1;
    return 0;
}

void getFileDetails(string &inputFilePath, trackMetaData &metaData, int32_t streamIndex) {
    if (streamIndex >= sizeof(kInputData) / sizeof(kInputData[0])) {
        return;
    }
    inputFilePath += kInputData[streamIndex].inputFile;
    strcpy(metaData.mime, kInputData[streamIndex].mime);
    if (!strncmp(metaData.mime, "audio/", 7)) {
        metaData.sampleRate = kInputData[streamIndex].firstParam;
        metaData.channelCount = kInputData[streamIndex].secondParam;
    } else {
        metaData.width = kInputData[streamIndex].firstParam;
        metaData.height = kInputData[streamIndex].secondParam;
    }
    return;
}

TEST_P(ExtractorUnitTest, CreateExtractorTest) {
    if (mDisableTest) return;

    ALOGV("Checks if a valid extractor is created for a given input file");
    string inputFileName = gEnv->getRes();
    int32_t inputFileIdx = GetParam().second;
    trackMetaData metaData;
    getFileDetails(inputFileName, metaData, inputFileIdx);
    if (!inputFileName.compare(gEnv->getRes())) {
        ALOGV("No input file specified");
        return;
    }

    mInputFp = fopen(inputFileName.c_str(), "rb");
    if (!mInputFp) {
        cout << "[   WARN   ] Test Skipped. Unable to open input file for reading \n";
        return;
    }
    int32_t status = setDataSource(inputFileName);
    if (status != 0) {
        ALOGE("SetDataSource failed");
        ASSERT_TRUE(false);
    }
    status = createExtractor();
    if (status != 0) {
        ALOGE("Extractor creation failed");
        ASSERT_TRUE(false);
    }

    // A valid extractor instace should return success for following calls
    int32_t numTracks = mExtractor->countTracks();
    ASSERT_GT(numTracks, 0);

    AMediaFormat *format = AMediaFormat_new();
    status = mExtractor->getMetaData(format);
    ASSERT_EQ(status, AMEDIA_OK);
}


TEST_P(ExtractorUnitTest, ExtractorTest) {
    if (mDisableTest) return;

    ALOGV("Validates Extractors for a given input file");
    string inputFileName = gEnv->getRes();
    int32_t inputFileIdx = GetParam().second;
    trackMetaData metaData;
    getFileDetails(inputFileName, metaData, inputFileIdx);
    if (!inputFileName.compare(gEnv->getRes())) {
        ALOGV("No input file specified");
        return;
    }

    mInputFp = fopen(inputFileName.c_str(), "rb");
    if (!mInputFp) {
        cout << "[   WARN   ] Test Skipped. Unable to open input file for reading \n";
        return;
    }
    int32_t status = setDataSource(inputFileName);
    if (status != 0) {
        ALOGE("SetDataSource failed");
        ASSERT_TRUE(false);
    }
    status = createExtractor();
    if (status != 0) {
        ALOGE("Extractor creation failed");
        ASSERT_TRUE(false);
    }

    int32_t numTracks = mExtractor->countTracks();
    ASSERT_GT(numTracks, 0);
    MediaTrackHelper *track;
    for (int32_t idx = 0; idx < numTracks; idx++) {
        track = mExtractor->getTrack(idx);
        if (!track) {
            ALOGE("Failed to get track for %s", inputFileName.c_str());
            ASSERT_TRUE(false);
        }
        CMediaTrack *cTrack = wrap(track);
        if (!cTrack) {
            ALOGE("Failed to get track for %s", inputFileName.c_str());
            ASSERT_TRUE(false);
        }
        MediaBufferGroup *bufferGroup = new MediaBufferGroup();
        status = cTrack->start(track, bufferGroup->wrap());
        ASSERT_EQ(OK, (media_status_t)status) << "Failed to start the track";

        FILE *outFp = fopen(("extractorOutput" + to_string(idx)).c_str(), "wb");
        if (!outFp) {
            ALOGW("Unable to open output file for dumping extracted stream");
        }

        while (status != AMEDIA_ERROR_END_OF_STREAM) {
            MediaBufferHelper *buffer = nullptr;
            status = track->read(&buffer);
            ALOGD("track->read Status = %d buffer %p", status, buffer);
            if (buffer) {
                ALOGV("buffer->data %p buffer->size() %zu buffer->range_length() %zu",
                      buffer->data(), buffer->size(), buffer->range_length());
                if (outFp) fwrite(buffer->data(), 1, buffer->range_length(), outFp);
                buffer->release();
            }
        }
        if (outFp) fclose(outFp);
        ASSERT_EQ(OK, cTrack->stop(track)) << "Failed to stop the track";
    }
}

INSTANTIATE_TEST_SUITE_P(
        ExtractorUnitTestAll, ExtractorUnitTest,
        ::testing::Values(make_pair("aac", 0), make_pair("amr", 1), make_pair("wav", 2), make_pair("ogg", 3),
                          make_pair("wav", 4), make_pair("mpeg2Ts", 5), make_pair("flac", 6), make_pair("ogg", 7),
                          make_pair("mkv", 8), make_pair("mp3",9), make_pair("mkv", 10), make_pair("mkv", 11),
                          make_pair("mpeg2Ps", 12)));

int main(int argc, char **argv) {
    gEnv = new ExtractorTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
