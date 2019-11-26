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
#include <sys/stat.h>
#include <datasource/FileSource.h>

#include <media/stagefright/foundation/hexdump.h>
#include <ID3.h>

#include "ID3TestEnvironment.h"

using namespace android;

static ID3TestEnvironment *gEnv = nullptr;

class ID3Test : public ::testing::TestWithParam<tuple<string, int, bool, bool, bool>> {

  public:
    virtual void SetUp() override {
        mDisableTest = false;
        tuple<string /* InputFile */, int /* VersionNumber */, bool /* textFramePresent */,
              bool /* sizeRestriction */, bool /* multiAlbumArt*/>
                params = ID3Test::GetParam();
        const char *path = (gEnv->getRes() + get<0>(params)).c_str();
        struct stat st;
        // Check if it's a valid regular file
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            cout << "[   WARN   ] Test Skipped. The file " << path
                 << " is not a valid file! \n";
            mDisableTest = true;
        }
    }

    bool mDisableTest;
};

TEST_P(ID3Test, getID3tagTest) {
    if (mDisableTest) return;
    tuple<string /* InputFile */, int /* VersionNumber */, bool /* textFramePresent */,
          bool /* sizeRestriction */, bool /* multiAlbumArt*/>
            params = ID3Test::GetParam();
    const char *path = (gEnv->getRes() + get<0>(params)).c_str();
    sp<FileSource> file = new FileSource(path);
    if (file->initCheck() != (status_t)OK) {
        cout << "[   WARN   ] Test Skipped. File initialization failed! \n";
        return;
    }
    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path << "\n";
    int tagCount = 0;
    ID3::Iterator it(tag, nullptr);
    while (!it.done()) {
        String8 id;
        it.getID(&id);
        if (id.length() > 0) {
            ALOGV("Found ID tag: %s\n", String8(id).c_str());
            tagCount++;
        }
        ASSERT_TRUE(tagCount != 0) << "No ID tag found! \n";
        it.next();
    }
}

TEST_P(ID3Test, getID3versionTest) {
    if (mDisableTest) return;
    tuple<string /* InputFile */, int /* VersionNumber */, bool /* textFramePresent */,
          bool /* sizeRestriction */, bool /* multiAlbumArt*/>
            params = ID3Test::GetParam();
    int versionNumber = get<1>(params);
    const char *path = (gEnv->getRes() + get<0>(params)).c_str();
    sp<android::FileSource> file = new FileSource(path);
    if (file->initCheck() != (status_t)OK) {
        cout << "[   WARN   ] Test Skipped. File initialization failed! \n";
        return;
    };

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path << "\n";
    ASSERT_TRUE(tag.version() >= versionNumber) << "Found lower version tag! \n";
    ALOGV("Version: %d", tag.version());
}

TEST_P(ID3Test, getID3frameTest) {
    if (mDisableTest) return;
    tuple<string /* InputFile */, int /* VersionNumber */, bool /* textFramePresent */,
          bool /* sizeRestriction */, bool /* multiAlbumArt*/>
            params = ID3Test::GetParam();
    bool textFrame = get<2>(params);
    const char *path = (gEnv->getRes() + get<0>(params)).c_str();
    sp<android::FileSource> file = new FileSource(path);
    if (file->initCheck() != (status_t)OK) {
        cout << "[   WARN   ] Test Skipped. File initialization failed! \n";
        return;
    }

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path << "\n";
    int textFrameFlag = 0;
    ID3::Iterator it(tag, nullptr);
    while (!it.done()) {
        String8 id;
        it.getID(&id);

        ASSERT_GT(id.length(), 0);
        if (!textFrame) {
            ASSERT_EQ(id[0], 'T') << "Expected no text frame, found one!\n";
        } else if (textFrame && id[0] == 'T') {
            String8 text;
            textFrameFlag = 1;
            it.getString(&text);
            ALOGV("Found text frame %s : %s \n", id.string(), text.string());
        } else {
            ASSERT_EQ(textFrameFlag, 1);
        }
        it.next();
    }
    return;
}

TEST_P(ID3Test, getID3albumArtTest) {
    if (mDisableTest) return;
    tuple<string /* InputFile */, int /* VersionNumber */, bool /* textFramePresent */,
          bool /* sizeRestriction */, bool /* multiAlbumArt*/>
            params = ID3Test::GetParam();
    bool sizeRestriction = get<3>(params);
    const char *path = (gEnv->getRes() + get<0>(params)).c_str();
    sp<android::FileSource> file = new FileSource(path);
    if (file->initCheck() != (status_t)OK) {
        cout << "[   WARN   ] Test Skipped. File initialization failed! \n";
        return;
    }

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path << "\n";
    size_t dataSize;
    String8 mime;
    const void *data = tag.getAlbumArt(&dataSize, &mime);

    // No sizeRestriction means the size can also be zero i.e. no album art.
    if (!sizeRestriction) {
        return;
    }
    ASSERT_TRUE(data) << "No album art found for file " << path;
    // kMaxMetadataSize = 3 * 1024 * 1024 i.e. 3MB limit set by the ID3 library
    static const size_t kMaxMetadataSize = 3 * 1024 * 1024;
    ASSERT_TRUE(dataSize < kMaxMetadataSize)
            << "Album art size more than specifications i.e. 3MB! \n";
    ALOGV("Found album art: size = %zu mime = %s \n", dataSize, mime.string());

    hexdump(data, dataSize > 128 ? 128 : dataSize);
}

TEST_P(ID3Test, getID3multiAlbumArtTest) {
    if (mDisableTest) return;
    tuple<string /* InputFile */, int /* VersionNumber */, bool /* textFramePresent */,
          bool /* sizeRestriction */, bool /* multiAlbumArt*/>
            params = ID3Test::GetParam();
    bool multiAlbumArt = get<4>(params);
    const char *path = (gEnv->getRes() + get<0>(params)).c_str();
    sp<android::FileSource> file = new FileSource(path);
    if (file->initCheck() != (status_t)OK) {
        cout << "[   WARN   ] Test Skipped. File initialization failed! \n";
        return;
    }

    ID3 tag(file.get());
    ASSERT_TRUE(tag.isValid()) << "No valid ID3 tag found for " << path << "\n";
    int count = 0;
    ID3::Iterator it(tag, nullptr);
    while (!it.done()) {
        String8 id;
        it.getID(&id);
        ASSERT_GT(id.length(), 0);
        // Check if the tag is an "APIC/PIC" tag.
        if (String8(id) == "APIC" || String8(id) == "PIC") count++;
        it.next();
    }
    // No multiAlbumArt means there can be 0 or 1 album arts.
    if (!multiAlbumArt) {
        ASSERT_TRUE(count < 2) << "Found " << count
                               << "album arts, expected one or no album art! \n";
        if (count == 1) {
            ALOGV("Found a single album art! \n");
            return;
        } else
            return;
    }
    ASSERT_TRUE(count >= 2) << "Found " << count << " album art, expected 2 or more album arts! \n";
    ALOGV("Found %d album arts! \n", count);
}

INSTANTIATE_TEST_SUITE_P(
        id3TestAll, ID3Test,
        ::testing::Values(
                make_tuple("bbb_44100hz_2ch_128kbps_mp3_30sec.mp3", 4, true, false, false),
                make_tuple("bbb_44100hz_2ch_128kbps_mp3_30sec_1_image.mp3", 4, true, true, false),
                make_tuple("bbb_44100hz_2ch_128kbps_mp3_30sec_2_image.mp3", 4, true, true, true),
                make_tuple("bbb_44100hz_2ch_128kbps_mp3_5mins.mp3", 4, true, false, false),
                make_tuple("bbb_44100hz_2ch_128kbps_mp3_5mins_1_image.mp3", 4, true, true, false),
                make_tuple("bbb_44100hz_2ch_128kbps_mp3_5mins_2_image.mp3", 4, true, true, true)));

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