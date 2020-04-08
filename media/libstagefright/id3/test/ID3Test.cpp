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

//#define LOG_NDEBUG 0
#define LOG_TAG "ID3Test"
#include <utils/Log.h>

#include <ctype.h>
#include <string>
#include <map>
#include <sys/stat.h>
#include <datasource/FileSource.h>

#include <media/stagefright/foundation/hexdump.h>
#include <ID3.h>

#include "ID3TestEnvironment.h"

using namespace android;

static ID3TestEnvironment *gEnv = nullptr;

class ID3tagTest : public ::testing::TestWithParam<string> {};

class ID3versionTest : public ::testing::TestWithParam<tuple<string, int, int>> {
  public:
    ID3versionTest() {
        mVersionMap.insert(pair<uint8_t, pair<uint8_t, uint8_t>>(0, make_pair(0, 0)));
        mVersionMap.insert(pair<uint8_t, pair<uint8_t, uint8_t>>(1, make_pair(1, 0)));
        mVersionMap.insert(pair<uint8_t, pair<uint8_t, uint8_t>>(2, make_pair(1, 1)));
        mVersionMap.insert(pair<uint8_t, pair<uint8_t, uint8_t>>(3, make_pair(2, 2)));
        mVersionMap.insert(pair<uint8_t, pair<uint8_t, uint8_t>>(4, make_pair(2, 3)));
        mVersionMap.insert(pair<uint8_t, pair<uint8_t, uint8_t>>(5, make_pair(2, 4)));
    }

    map</*versionValue*/ uint8_t, /*pair(majorVersion, minorVersion)*/ pair<uint8_t, uint8_t>>
            mVersionMap;
};

class ID3textTagTest : public ::testing::TestWithParam<pair<string, int>> {};

class ID3albumArtTest : public ::testing::TestWithParam<pair<string, bool>> {};

class ID3multiAlbumArtTest : public ::testing::TestWithParam<pair<string, int>> {};

TEST_P(ID3tagTest, TagTest) {
    string path = gEnv->getRes() + GetParam();
    sp<FileSource> file = new FileSource(path.c_str());
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";
    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path.c_str() << "\n";

    ID3::Iterator it(tag, nullptr);
    while (!it.done()) {
        String8 id;
        it.getID(&id);
        ASSERT_GT(id.length(), 0) << "No ID tag found! \n";
        ALOGV("Found ID tag: %s\n", String8(id).c_str());
        it.next();
    }
}

TEST_P(ID3versionTest, VersionTest) {
    tuple<string, int, int> params = GetParam();
    int majorVersionNumber = get<1>(params);
    int minorVersionNumber = get<2>(params);
    string path = gEnv->getRes() + get<0>(params);
    sp<android::FileSource> file = new FileSource(path.c_str());
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path.c_str() << "\n";

    pair<uint8_t, uint8_t> version = mVersionMap[tag.version()];

    uint8_t majorVersion = version.first;
    uint8_t minorVersion = version.second;
    ASSERT_EQ(majorVersion, majorVersionNumber) << "Expected major version: " << majorVersionNumber
                                                << " Found major version: " << majorVersion;

    ASSERT_EQ(minorVersion, minorVersionNumber) << "Expected minor version: " << minorVersionNumber
                                                << " Found minor version: " << minorVersion;
}

TEST_P(ID3textTagTest, TextTagTest) {
    int numTextFrames = GetParam().second;
    string path = gEnv->getRes() + GetParam().first;
    sp<android::FileSource> file = new FileSource(path.c_str());
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path.c_str() << "\n";
    int countTextFrames = 0;
    ID3::Iterator it(tag, nullptr);
    // if the version is v1 or v1_1
    if (tag.version() == 1 || tag.version() == 2) {
        while (!it.done()) {
            String8 id;
            String8 text;
            it.getID(&id);
            ASSERT_GT(id.length(), 0);

            it.getString(&text);
            // if the tag has a value
            if (strcmp(text.string(), "")) {
                countTextFrames++;
                ALOGV("ID: %s\n", id.c_str());
                ALOGV("Text string: %s\n", text.string());
            }
            it.next();
        }
    } else {
        while (!it.done()) {
            String8 id;
            it.getID(&id);
            ASSERT_GT(id.length(), 0);

            if (id[0] == 'T') {
                String8 text;
                countTextFrames++;
                it.getString(&text);
                ALOGV("Found text frame %s : %s \n", id.string(), text.string());
            }
            it.next();
        }
    }
    ASSERT_EQ(countTextFrames, numTextFrames)
            << "Expected " << numTextFrames << " text frames, found " << countTextFrames;
}

TEST_P(ID3albumArtTest, AlbumArtTest) {
    bool albumArtPresent = GetParam().second;
    string path = gEnv->getRes() + GetParam().first;
    sp<android::FileSource> file = new FileSource(path.c_str());
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path.c_str() << "\n";
    size_t dataSize;
    String8 mime;
    const void *data = tag.getAlbumArt(&dataSize, &mime);

    if (albumArtPresent) {
        if (data) {
            ALOGV("Found album art: size = %zu mime = %s \n", dataSize, mime.string());
        }
        ASSERT_NE(data, nullptr) << "Expected album art, found none!" << path;
    } else {
        ASSERT_EQ(data, nullptr) << "Found album art when expected none!";
    }
#if (LOG_NDEBUG == 0)
    hexdump(data, dataSize > 128 ? 128 : dataSize);
#endif
}

TEST_P(ID3multiAlbumArtTest, MultiAlbumArtTest) {
    int numAlbumArt = GetParam().second;
    string path = gEnv->getRes() + GetParam().first;
    sp<android::FileSource> file = new FileSource(path.c_str());
    ASSERT_EQ(file->initCheck(), (status_t)OK) << "File initialization failed! \n";

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path.c_str() << "\n";
    int count = 0;
    ID3::Iterator it(tag, nullptr);
    while (!it.done()) {
        String8 id;
        it.getID(&id);
        ASSERT_GT(id.length(), 0);
        // Check if the tag is an "APIC/PIC" tag.
        if (String8(id) == "APIC" || String8(id) == "PIC") {
            count++;
            size_t dataSize;
            String8 mime;
            const void *data = tag.getAlbumArt(&dataSize, &mime);
            if (data) {
                ALOGV("Found album art: size = %zu mime = %s \n", dataSize, mime.string());
#if (LOG_NDEBUG == 0)
                hexdump(data, dataSize > 128 ? 128 : dataSize);
#endif
            }
            ASSERT_NE(data, nullptr) << "Expected album art, found none!" << path;
        }
        it.next();
    }
    ASSERT_EQ(count, numAlbumArt) << "Found " << count << " album arts, expected " << numAlbumArt
                                  << " album arts! \n";
}

INSTANTIATE_TEST_SUITE_P(id3TestAll, ID3tagTest,
                         ::testing::Values("bbb_44100hz_2ch_128kbps_1sec_v23.mp3",
                                           "bbb_44100hz_2ch_128kbps_1sec_1_image.mp3",
                                           "bbb_44100hz_2ch_128kbps_1sec_2_image.mp3",
                                           "bbb_44100hz_2ch_128kbps_2sec_v24.mp3",
                                           "bbb_44100hz_2ch_128kbps_2sec_1_image.mp3",
                                           "bbb_44100hz_2ch_128kbps_2sec_2_image.mp3",
                                           "bbb_44100hz_2ch_128kbps_2sec_largeSize.mp3",
                                           "bbb_44100hz_2ch_128kbps_1sec_v23_3tags.mp3",
                                           "bbb_44100hz_2ch_128kbps_1sec_v1_5tags.mp3"));

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3versionTest,
        ::testing::Values(make_tuple("bbb_44100hz_2ch_128kbps_1sec_v23.mp3", 2, 3),
                          make_tuple("bbb_44100hz_2ch_128kbps_1sec_1_image.mp3", 2, 3),
                          make_tuple("bbb_44100hz_2ch_128kbps_1sec_2_image.mp3", 2, 3),
                          make_tuple("bbb_44100hz_2ch_128kbps_2sec_v24.mp3", 2, 4),
                          make_tuple("bbb_44100hz_2ch_128kbps_2sec_1_image.mp3", 2, 4),
                          make_tuple("bbb_44100hz_2ch_128kbps_2sec_2_image.mp3", 2, 4),
                          make_tuple("bbb_44100hz_2ch_128kbps_2sec_largeSize.mp3", 2, 4),
                          make_tuple("bbb_44100hz_2ch_128kbps_1sec_v23_3tags.mp3", 2, 3),
                          make_tuple("bbb_44100hz_2ch_128kbps_1sec_v1_5tags.mp3", 1, 1)));

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3textTagTest,
        ::testing::Values(make_pair("bbb_44100hz_2ch_128kbps_1sec_v23.mp3", 1),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_1_image.mp3", 1),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_2_image.mp3", 1),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_v24.mp3", 1),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_1_image.mp3", 1),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_2_image.mp3", 1),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_largeSize.mp3", 1),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_v23_3tags.mp3", 3),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_v1_5tags.mp3", 5),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_v1_3tags.mp3", 3)));

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3albumArtTest,
        ::testing::Values(make_pair("bbb_44100hz_2ch_128kbps_1sec_v23.mp3", false),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_1_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_2_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_v24.mp3", false),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_1_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_2_image.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_2sec_largeSize.mp3", true),
                          make_pair("bbb_44100hz_2ch_128kbps_1sec_v1_5tags.mp3", false)));

INSTANTIATE_TEST_SUITE_P(id3TestAll, ID3multiAlbumArtTest,
                         ::testing::Values(make_pair("bbb_44100hz_2ch_128kbps_1sec_v23.mp3", 0),
                                           make_pair("bbb_44100hz_2ch_128kbps_2sec_v24.mp3", 0),
                                           make_pair("bbb_44100hz_2ch_128kbps_1sec_1_image.mp3", 1),
                                           make_pair("bbb_44100hz_2ch_128kbps_2sec_1_image.mp3", 1),
                                           make_pair("bbb_44100hz_2ch_128kbps_1sec_2_image.mp3", 2),
                                           make_pair("bbb_44100hz_2ch_128kbps_2sec_2_image.mp3", 2),
                                           make_pair("bbb_44100hz_2ch_128kbps_2sec_largeSize.mp3",
                                                     3)));

int main(int argc, char **argv) {
    gEnv = new ID3TestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGI("ID3 Test result = %d\n", status);
    }
    return status;
}
