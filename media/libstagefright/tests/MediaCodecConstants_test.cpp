/*
 * Copyright 2020 The Android Open Source Project
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
 *
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaCodecConstantsTest"

#include <gtest/gtest.h>
#include <media/stagefright/MediaCodecConstants.h>

class MediaCodecConstantsTest : public ::testing::Test {
};

TEST_F(MediaCodecConstantsTest, ConstTest) {

    static_assert(AACObjectELD == 0x27);
    static_assert(AACObjectERLC == 0x11);
    static_assert(AACObjectERScalable == 0x14);
    static_assert(AACObjectHE == 0x5);
    static_assert(AACObjectHE_PS == 0x1d);
    static_assert(AACObjectLC == 0x2);
    static_assert(AACObjectLD == 0x17);
    static_assert(AACObjectLTP == 0x4);
    static_assert(AACObjectMain == 0x1);
    static_assert(AACObjectSSR == 0x3);
    static_assert(AACObjectScalable == 0x6);
    static_assert(AACObjectXHE == 0x2a);
    EXPECT_STREQ("ELD", asString_AACObject(AACObjectELD));
    EXPECT_STREQ("ERLC", asString_AACObject(AACObjectERLC));
    EXPECT_STREQ("ERScalable", asString_AACObject(AACObjectERScalable));
    EXPECT_STREQ("HE", asString_AACObject(AACObjectHE));
    EXPECT_STREQ("HE_PS", asString_AACObject(AACObjectHE_PS));
    EXPECT_STREQ("LC", asString_AACObject(AACObjectLC));
    EXPECT_STREQ("LD", asString_AACObject(AACObjectLD));
    EXPECT_STREQ("LTP", asString_AACObject(AACObjectLTP));
    EXPECT_STREQ("Main", asString_AACObject(AACObjectMain));
    EXPECT_STREQ("SSR", asString_AACObject(AACObjectSSR));
    EXPECT_STREQ("Scalable", asString_AACObject(AACObjectScalable));
    EXPECT_STREQ("XHE", asString_AACObject(AACObjectXHE));

    static_assert(AV1Level2 == 0x1);
    static_assert(AV1Level21 == 0x2);
    static_assert(AV1Level22 == 0x4);
    static_assert(AV1Level23 == 0x8);
    static_assert(AV1Level3 == 0x10);
    static_assert(AV1Level31 == 0x20);
    static_assert(AV1Level32 == 0x40);
    static_assert(AV1Level33 == 0x80);
    static_assert(AV1Level4 == 0x100);
    static_assert(AV1Level41 == 0x200);
    static_assert(AV1Level42 == 0x400);
    static_assert(AV1Level43 == 0x800);
    static_assert(AV1Level5 == 0x1000);
    static_assert(AV1Level51 == 0x2000);
    static_assert(AV1Level52 == 0x4000);
    static_assert(AV1Level53 == 0x8000);
    static_assert(AV1Level6 == 0x10000);
    static_assert(AV1Level61 == 0x20000);
    static_assert(AV1Level62 == 0x40000);
    static_assert(AV1Level63 == 0x80000);
    static_assert(AV1Level7 == 0x100000);
    static_assert(AV1Level71 == 0x200000);
    static_assert(AV1Level72 == 0x400000);
    static_assert(AV1Level73 == 0x800000);
    EXPECT_STREQ("2", asString_AV1Level(AV1Level2));
    EXPECT_STREQ("2.1", asString_AV1Level(AV1Level21));
    EXPECT_STREQ("2.2", asString_AV1Level(AV1Level22));
    EXPECT_STREQ("2.3", asString_AV1Level(AV1Level23));
    EXPECT_STREQ("3", asString_AV1Level(AV1Level3));
    EXPECT_STREQ("3.1", asString_AV1Level(AV1Level31));
    EXPECT_STREQ("3.2", asString_AV1Level(AV1Level32));
    EXPECT_STREQ("3.3", asString_AV1Level(AV1Level33));
    EXPECT_STREQ("4", asString_AV1Level(AV1Level4));
    EXPECT_STREQ("4.1", asString_AV1Level(AV1Level41));
    EXPECT_STREQ("4.2", asString_AV1Level(AV1Level42));
    EXPECT_STREQ("4.3", asString_AV1Level(AV1Level43));
    EXPECT_STREQ("5", asString_AV1Level(AV1Level5));
    EXPECT_STREQ("5.1", asString_AV1Level(AV1Level51));
    EXPECT_STREQ("5.2", asString_AV1Level(AV1Level52));
    EXPECT_STREQ("5.3", asString_AV1Level(AV1Level53));
    EXPECT_STREQ("6", asString_AV1Level(AV1Level6));
    EXPECT_STREQ("6.1", asString_AV1Level(AV1Level61));
    EXPECT_STREQ("6.2", asString_AV1Level(AV1Level62));
    EXPECT_STREQ("6.3", asString_AV1Level(AV1Level63));
    EXPECT_STREQ("7", asString_AV1Level(AV1Level7));
    EXPECT_STREQ("7.1", asString_AV1Level(AV1Level71));
    EXPECT_STREQ("7.2", asString_AV1Level(AV1Level72));
    EXPECT_STREQ("7.3", asString_AV1Level(AV1Level73));

    static_assert(AV1ProfileMain10 == 0x2);
    static_assert(AV1ProfileMain10HDR10 == 0x1000);
    static_assert(AV1ProfileMain10HDR10Plus == 0x2000);
    static_assert(AV1ProfileMain8 == 0x1);
    EXPECT_STREQ("Main10", asString_AV1Profile(AV1ProfileMain10));
    EXPECT_STREQ("Main10HDR", asString_AV1Profile(AV1ProfileMain10HDR10));
    EXPECT_STREQ("Main10HDRPlus", asString_AV1Profile(AV1ProfileMain10HDR10Plus));
    EXPECT_STREQ("Main8", asString_AV1Profile(AV1ProfileMain8));

    static_assert(AVCLevel1 == 0x1);
    static_assert(AVCLevel11 == 0x4);
    static_assert(AVCLevel12 == 0x8);
    static_assert(AVCLevel13 == 0x10);
    static_assert(AVCLevel1b == 0x2);
    static_assert(AVCLevel2 == 0x20);
    static_assert(AVCLevel21 == 0x40);
    static_assert(AVCLevel22 == 0x80);
    static_assert(AVCLevel3 == 0x100);
    static_assert(AVCLevel31 == 0x200);
    static_assert(AVCLevel32 == 0x400);
    static_assert(AVCLevel4 == 0x800);
    static_assert(AVCLevel41 == 0x1000);
    static_assert(AVCLevel42 == 0x2000);
    static_assert(AVCLevel5 == 0x4000);
    static_assert(AVCLevel51 == 0x8000);
    static_assert(AVCLevel52 == 0x10000);
    static_assert(AVCLevel6 == 0x20000);
    static_assert(AVCLevel61 == 0x40000);
    static_assert(AVCLevel62 == 0x80000);
    EXPECT_STREQ("1", asString_AVCLevel(AVCLevel1));
    EXPECT_STREQ("1.1", asString_AVCLevel(AVCLevel11));
    EXPECT_STREQ("1.2", asString_AVCLevel(AVCLevel12));
    EXPECT_STREQ("1.3", asString_AVCLevel(AVCLevel13));
    EXPECT_STREQ("1b", asString_AVCLevel(AVCLevel1b));
    EXPECT_STREQ("2", asString_AVCLevel(AVCLevel2));
    EXPECT_STREQ("2.1", asString_AVCLevel(AVCLevel21));
    EXPECT_STREQ("2.2", asString_AVCLevel(AVCLevel22));
    EXPECT_STREQ("3", asString_AVCLevel(AVCLevel3));
    EXPECT_STREQ("3.1", asString_AVCLevel(AVCLevel31));
    EXPECT_STREQ("3.2", asString_AVCLevel(AVCLevel32));
    EXPECT_STREQ("4", asString_AVCLevel(AVCLevel4));
    EXPECT_STREQ("4.1", asString_AVCLevel(AVCLevel41));
    EXPECT_STREQ("4.2", asString_AVCLevel(AVCLevel42));
    EXPECT_STREQ("5", asString_AVCLevel(AVCLevel5));
    EXPECT_STREQ("5.1", asString_AVCLevel(AVCLevel51));
    EXPECT_STREQ("5.2", asString_AVCLevel(AVCLevel52));
    EXPECT_STREQ("6", asString_AVCLevel(AVCLevel6));
    EXPECT_STREQ("6.1", asString_AVCLevel(AVCLevel61));
    EXPECT_STREQ("6.2", asString_AVCLevel(AVCLevel62));

    static_assert(AVCProfileBaseline == 0x1);
    static_assert(AVCProfileConstrainedBaseline == 0x10000);
    static_assert(AVCProfileConstrainedHigh == 0x80000);
    static_assert(AVCProfileExtended == 0x4);
    static_assert(AVCProfileHigh == 0x8);
    static_assert(AVCProfileHigh10 == 0x10);
    static_assert(AVCProfileHigh422 == 0x20);
    static_assert(AVCProfileHigh444 == 0x40);
    static_assert(AVCProfileMain == 0x2);
    EXPECT_STREQ("Baseline", asString_AVCProfile(AVCProfileBaseline));
    EXPECT_STREQ("ConstrainedBaseline", asString_AVCProfile(AVCProfileConstrainedBaseline));
    EXPECT_STREQ("ConstrainedHigh", asString_AVCProfile(AVCProfileConstrainedHigh));
    EXPECT_STREQ("Extended", asString_AVCProfile(AVCProfileExtended));
    EXPECT_STREQ("High", asString_AVCProfile(AVCProfileHigh));
    EXPECT_STREQ("High10", asString_AVCProfile(AVCProfileHigh10));
    EXPECT_STREQ("High422", asString_AVCProfile(AVCProfileHigh422));
    EXPECT_STREQ("High444", asString_AVCProfile(AVCProfileHigh444));
    EXPECT_STREQ("Main", asString_AVCProfile(AVCProfileMain));

    static_assert(BITRATE_MODE_CBR == 0x2);
    static_assert(BITRATE_MODE_CQ == 0x0);
    static_assert(BITRATE_MODE_VBR == 0x1);
    EXPECT_STREQ("CBR", asString_BitrateMode(BITRATE_MODE_CBR));
    EXPECT_STREQ("CQ", asString_BitrateMode(BITRATE_MODE_CQ));
    EXPECT_STREQ("VBR", asString_BitrateMode(BITRATE_MODE_VBR));

    static_assert(BUFFER_FLAG_CODEC_CONFIG == 0x2);
    static_assert(BUFFER_FLAG_END_OF_STREAM == 0x4);
    static_assert(BUFFER_FLAG_KEY_FRAME == 0x1);
    static_assert(BUFFER_FLAG_MUXER_DATA == 0x10); // hidden
    static_assert(BUFFER_FLAG_PARTIAL_FRAME == 0x8);
    static_assert(BUFFER_FLAG_SYNC_FRAME == 0x1); // deprecated
    EXPECT_STREQ("CODEC_CONFIG", asString_BufferFlag(BUFFER_FLAG_CODEC_CONFIG));
    EXPECT_STREQ("END_OF_STREAM", asString_BufferFlag(BUFFER_FLAG_END_OF_STREAM));
    EXPECT_STREQ("KEY_FRAME", asString_BufferFlag(BUFFER_FLAG_KEY_FRAME));
    EXPECT_STREQ("KEY_FRAME", asString_BufferFlag(BUFFER_FLAG_SYNC_FRAME)); // deprecated, value collision
    EXPECT_STREQ("MUXER_DATA", asString_BufferFlag(BUFFER_FLAG_MUXER_DATA)); // hidden
    EXPECT_STREQ("PARTIAL_FRAME", asString_BufferFlag(BUFFER_FLAG_PARTIAL_FRAME));

    static_assert(COLOR_Format12bitRGB444 == 0x3); // deprecated
    static_assert(COLOR_Format16bitARGB1555 == 0x5); // deprecated
    static_assert(COLOR_Format16bitARGB4444 == 0x4); // deprecated
    static_assert(COLOR_Format16bitBGR565 == 0x7); // deprecated
    static_assert(COLOR_Format16bitRGB565 == 0x6);
    static_assert(COLOR_Format18BitBGR666 == 0x29); // deprecated
    static_assert(COLOR_Format18bitARGB1665 == 0x9); // deprecated
    static_assert(COLOR_Format18bitRGB666 == 0x8); // deprecated
    static_assert(COLOR_Format19bitARGB1666 == 0xa); // deprecated
    static_assert(COLOR_Format24BitABGR6666 == 0x2b); // deprecated
    static_assert(COLOR_Format24BitARGB6666 == 0x2a); // deprecated
    static_assert(COLOR_Format24bitARGB1887 == 0xd); // deprecated
    static_assert(COLOR_Format24bitBGR888 == 0xc);
    static_assert(COLOR_Format24bitRGB888 == 0xb); // deprecated
    static_assert(COLOR_Format25bitARGB1888 == 0xe); // deprecated
    static_assert(COLOR_Format32bitABGR8888 == 0x7f00a000);
    static_assert(COLOR_Format32bitARGB8888 == 0x10); // deprecated
    static_assert(COLOR_Format32bitBGRA8888 == 0xf); // deprecated
    static_assert(COLOR_Format8bitRGB332 == 0x2); // deprecated
    static_assert(COLOR_FormatCbYCrY == 0x1b); // deprecated
    static_assert(COLOR_FormatCrYCbY == 0x1c); // deprecated
    static_assert(COLOR_FormatL16 == 0x24);
    static_assert(COLOR_FormatL2 == 0x21); // deprecated
    static_assert(COLOR_FormatL24 == 0x25); // deprecated
    static_assert(COLOR_FormatL32 == 0x26); // deprecated
    static_assert(COLOR_FormatL4 == 0x22); // deprecated
    static_assert(COLOR_FormatL8 == 0x23);
    static_assert(COLOR_FormatMonochrome == 0x1); // deprecated
    static_assert(COLOR_FormatRGBAFlexible == 0x7f36a888);
    static_assert(COLOR_FormatRGBFlexible == 0x7f36b888);
    static_assert(COLOR_FormatRawBayer10bit == 0x1f);
    static_assert(COLOR_FormatRawBayer8bit == 0x1e);
    static_assert(COLOR_FormatRawBayer8bitcompressed == 0x20);
    static_assert(COLOR_FormatSurface == 0x7f000789);
    static_assert(COLOR_FormatYCbYCr == 0x19); // deprecated
    static_assert(COLOR_FormatYCrYCb == 0x1a); // deprecated
    static_assert(COLOR_FormatYUV411PackedPlanar == 0x12); // deprecated
    static_assert(COLOR_FormatYUV411Planar == 0x11); // deprecated
    static_assert(COLOR_FormatYUV420Flexible == 0x7f420888);
    static_assert(COLOR_FormatYUV420PackedPlanar == 0x14); // deprecated
    static_assert(COLOR_FormatYUV420PackedSemiPlanar == 0x27); // deprecated
    static_assert(COLOR_FormatYUV420Planar == 0x13); // deprecated
    static_assert(COLOR_FormatYUV420SemiPlanar == 0x15); // deprecated
    static_assert(COLOR_FormatYUV422Flexible == 0x7f422888);
    static_assert(COLOR_FormatYUV422PackedPlanar == 0x17); // deprecated
    static_assert(COLOR_FormatYUV422PackedSemiPlanar == 0x28); // deprecated
    static_assert(COLOR_FormatYUV422Planar == 0x16); // deprecated
    static_assert(COLOR_FormatYUV422SemiPlanar == 0x18); // deprecated
    static_assert(COLOR_FormatYUV444Flexible == 0x7f444888);
    static_assert(COLOR_FormatYUV444Interleaved == 0x1d); // deprecated
    static_assert(COLOR_QCOM_FormatYUV420SemiPlanar == 0x7fa30c00); // deprecated
    static_assert(COLOR_TI_FormatYUV420PackedSemiPlanar == 0x7f000100); // deprecated
    EXPECT_STREQ("12bitRGB444", asString_ColorFormat(COLOR_Format12bitRGB444)); // deprecated
    EXPECT_STREQ("16bitARGB1555", asString_ColorFormat(COLOR_Format16bitARGB1555)); // deprecated
    EXPECT_STREQ("16bitARGB4444", asString_ColorFormat(COLOR_Format16bitARGB4444)); // deprecated
    EXPECT_STREQ("16bitBGR565", asString_ColorFormat(COLOR_Format16bitBGR565)); // deprecated
    EXPECT_STREQ("16bitRGB565", asString_ColorFormat(COLOR_Format16bitRGB565));
    EXPECT_STREQ("18BitBGR666", asString_ColorFormat(COLOR_Format18BitBGR666)); // deprecated
    EXPECT_STREQ("18bitARGB1665", asString_ColorFormat(COLOR_Format18bitARGB1665)); // deprecated
    EXPECT_STREQ("18bitRGB666", asString_ColorFormat(COLOR_Format18bitRGB666)); // deprecated
    EXPECT_STREQ("19bitARGB1666", asString_ColorFormat(COLOR_Format19bitARGB1666)); // deprecated
    EXPECT_STREQ("24BitABGR6666", asString_ColorFormat(COLOR_Format24BitABGR6666)); // deprecated
    EXPECT_STREQ("24BitARGB6666", asString_ColorFormat(COLOR_Format24BitARGB6666)); // deprecated
    EXPECT_STREQ("24bitARGB1887", asString_ColorFormat(COLOR_Format24bitARGB1887)); // deprecated
    EXPECT_STREQ("24bitBGR888", asString_ColorFormat(COLOR_Format24bitBGR888));
    EXPECT_STREQ("24bitRGB888", asString_ColorFormat(COLOR_Format24bitRGB888)); // deprecated
    EXPECT_STREQ("25bitARGB1888", asString_ColorFormat(COLOR_Format25bitARGB1888)); // deprecated
    EXPECT_STREQ("32bitABGR8888", asString_ColorFormat(COLOR_Format32bitABGR8888));
    EXPECT_STREQ("32bitARGB8888", asString_ColorFormat(COLOR_Format32bitARGB8888)); // deprecated
    EXPECT_STREQ("32bitBGRA8888", asString_ColorFormat(COLOR_Format32bitBGRA8888)); // deprecated
    EXPECT_STREQ("8bitRGB332", asString_ColorFormat(COLOR_Format8bitRGB332)); // deprecated
    EXPECT_STREQ("CbYCrY", asString_ColorFormat(COLOR_FormatCbYCrY)); // deprecated
    EXPECT_STREQ("CrYCbY", asString_ColorFormat(COLOR_FormatCrYCbY)); // deprecated
    EXPECT_STREQ("L16", asString_ColorFormat(COLOR_FormatL16));
    EXPECT_STREQ("L2", asString_ColorFormat(COLOR_FormatL2)); // deprecated
    EXPECT_STREQ("L24", asString_ColorFormat(COLOR_FormatL24)); // deprecated
    EXPECT_STREQ("L32", asString_ColorFormat(COLOR_FormatL32)); // deprecated
    EXPECT_STREQ("L4", asString_ColorFormat(COLOR_FormatL4)); // deprecated
    EXPECT_STREQ("L8", asString_ColorFormat(COLOR_FormatL8));
    EXPECT_STREQ("Monochrome", asString_ColorFormat(COLOR_FormatMonochrome)); // deprecated
    EXPECT_STREQ("QCOM_YUV420SemiPlanar", asString_ColorFormat(COLOR_QCOM_FormatYUV420SemiPlanar)); // deprecated
    EXPECT_STREQ("RGBAFlexible", asString_ColorFormat(COLOR_FormatRGBAFlexible));
    EXPECT_STREQ("RGBFlexible", asString_ColorFormat(COLOR_FormatRGBFlexible));
    EXPECT_STREQ("RawBayer10bit", asString_ColorFormat(COLOR_FormatRawBayer10bit));
    EXPECT_STREQ("RawBayer8bit", asString_ColorFormat(COLOR_FormatRawBayer8bit));
    EXPECT_STREQ("RawBayer8bitcompressed", asString_ColorFormat(COLOR_FormatRawBayer8bitcompressed));
    EXPECT_STREQ("Surface", asString_ColorFormat(COLOR_FormatSurface));
    EXPECT_STREQ("TI_YUV420PackedSemiPlanar", asString_ColorFormat(COLOR_TI_FormatYUV420PackedSemiPlanar)); // deprecated
    EXPECT_STREQ("YCbYCr", asString_ColorFormat(COLOR_FormatYCbYCr)); // deprecated
    EXPECT_STREQ("YCrYCb", asString_ColorFormat(COLOR_FormatYCrYCb)); // deprecated
    EXPECT_STREQ("YUV411PackedPlanar", asString_ColorFormat(COLOR_FormatYUV411PackedPlanar)); // deprecated
    EXPECT_STREQ("YUV411Planar", asString_ColorFormat(COLOR_FormatYUV411Planar)); // deprecated
    EXPECT_STREQ("YUV420Flexible", asString_ColorFormat(COLOR_FormatYUV420Flexible));
    EXPECT_STREQ("YUV420PackedPlanar", asString_ColorFormat(COLOR_FormatYUV420PackedPlanar)); // deprecated
    EXPECT_STREQ("YUV420PackedSemiPlanar", asString_ColorFormat(COLOR_FormatYUV420PackedSemiPlanar)); // deprecated
    EXPECT_STREQ("YUV420Planar", asString_ColorFormat(COLOR_FormatYUV420Planar)); // deprecated
    EXPECT_STREQ("YUV420SemiPlanar", asString_ColorFormat(COLOR_FormatYUV420SemiPlanar)); // deprecated
    EXPECT_STREQ("YUV422Flexible", asString_ColorFormat(COLOR_FormatYUV422Flexible));
    EXPECT_STREQ("YUV422PackedPlanar", asString_ColorFormat(COLOR_FormatYUV422PackedPlanar)); // deprecated
    EXPECT_STREQ("YUV422PackedSemiPlanar", asString_ColorFormat(COLOR_FormatYUV422PackedSemiPlanar)); // deprecated
    EXPECT_STREQ("YUV422Planar", asString_ColorFormat(COLOR_FormatYUV422Planar)); // deprecated
    EXPECT_STREQ("YUV422SemiPlanar", asString_ColorFormat(COLOR_FormatYUV422SemiPlanar)); // deprecated
    EXPECT_STREQ("YUV444Flexible", asString_ColorFormat(COLOR_FormatYUV444Flexible));
    EXPECT_STREQ("YUV444Interleaved", asString_ColorFormat(COLOR_FormatYUV444Interleaved)); // deprecated

    static_assert(COLOR_RANGE_FULL == 0x1);
    static_assert(COLOR_RANGE_LIMITED == 0x2);
    EXPECT_STREQ("FULL", asString_ColorRange(COLOR_RANGE_FULL));
    EXPECT_STREQ("LIMITED", asString_ColorRange(COLOR_RANGE_LIMITED));

    static_assert(COLOR_STANDARD_BT2020 == 0x6);
    static_assert(COLOR_STANDARD_BT601_NTSC == 0x4);
    static_assert(COLOR_STANDARD_BT601_PAL == 0x2);
    static_assert(COLOR_STANDARD_BT709 == 0x1);
    EXPECT_STREQ("BT2020", asString_ColorStandard(COLOR_STANDARD_BT2020));
    EXPECT_STREQ("BT601_NTSC", asString_ColorStandard(COLOR_STANDARD_BT601_NTSC));
    EXPECT_STREQ("BT601_PAL", asString_ColorStandard(COLOR_STANDARD_BT601_PAL));
    EXPECT_STREQ("BT709", asString_ColorStandard(COLOR_STANDARD_BT709));

    static_assert(COLOR_TRANSFER_HLG == 0x7);
    static_assert(COLOR_TRANSFER_LINEAR == 0x1);
    static_assert(COLOR_TRANSFER_SDR_VIDEO == 0x3);
    static_assert(COLOR_TRANSFER_ST2084 == 0x6);
    EXPECT_STREQ("HLG", asString_ColorTransfer(COLOR_TRANSFER_HLG));
    EXPECT_STREQ("LINEAR", asString_ColorTransfer(COLOR_TRANSFER_LINEAR));
    EXPECT_STREQ("SDR_VIDEO", asString_ColorTransfer(COLOR_TRANSFER_SDR_VIDEO));
    EXPECT_STREQ("ST2084", asString_ColorTransfer(COLOR_TRANSFER_ST2084));

    static_assert(CONFIGURE_FLAG_ENCODE == 0x1);
    static_assert(CONFIGURE_FLAG_USE_BLOCK_MODEL == 0x2);
    EXPECT_STREQ("ENCODE", asString_ConfigureFlag(CONFIGURE_FLAG_ENCODE));
    EXPECT_STREQ("USE_BLOCK_MODEL", asString_ConfigureFlag(CONFIGURE_FLAG_USE_BLOCK_MODEL));

    static_assert(CRYPTO_MODE_AES_CBC == 0x2);
    static_assert(CRYPTO_MODE_AES_CTR == 0x1);
    static_assert(CRYPTO_MODE_UNENCRYPTED == 0x0);
    EXPECT_STREQ("AES_CBC", asString_CryptoMode(CRYPTO_MODE_AES_CBC));
    EXPECT_STREQ("AES_CTR", asString_CryptoMode(CRYPTO_MODE_AES_CTR));
    EXPECT_STREQ("UNENCRYPTED", asString_CryptoMode(CRYPTO_MODE_UNENCRYPTED));

    static_assert(DolbyVisionLevelFhd24 == 0x4);
    static_assert(DolbyVisionLevelFhd30 == 0x8);
    static_assert(DolbyVisionLevelFhd60 == 0x10);
    static_assert(DolbyVisionLevelHd24 == 0x1);
    static_assert(DolbyVisionLevelHd30 == 0x2);
    static_assert(DolbyVisionLevelUhd24 == 0x20);
    static_assert(DolbyVisionLevelUhd30 == 0x40);
    static_assert(DolbyVisionLevelUhd48 == 0x80);
    static_assert(DolbyVisionLevelUhd60 == 0x100);
    EXPECT_STREQ("Fhd24", asString_DolbyVisionLevel(DolbyVisionLevelFhd24));
    EXPECT_STREQ("Fhd30", asString_DolbyVisionLevel(DolbyVisionLevelFhd30));
    EXPECT_STREQ("Fhd60", asString_DolbyVisionLevel(DolbyVisionLevelFhd60));
    EXPECT_STREQ("Hd24", asString_DolbyVisionLevel(DolbyVisionLevelHd24));
    EXPECT_STREQ("Hd30", asString_DolbyVisionLevel(DolbyVisionLevelHd30));
    EXPECT_STREQ("Uhd24", asString_DolbyVisionLevel(DolbyVisionLevelUhd24));
    EXPECT_STREQ("Uhd30", asString_DolbyVisionLevel(DolbyVisionLevelUhd30));
    EXPECT_STREQ("Uhd48", asString_DolbyVisionLevel(DolbyVisionLevelUhd48));
    EXPECT_STREQ("Uhd60", asString_DolbyVisionLevel(DolbyVisionLevelUhd60));

    static_assert(DolbyVisionProfileDvav110 == 0x400);
    static_assert(DolbyVisionProfileDvavPen == 0x2);
    static_assert(DolbyVisionProfileDvavPer == 0x1);
    static_assert(DolbyVisionProfileDvavSe == 0x200);
    static_assert(DolbyVisionProfileDvheDen == 0x8);
    static_assert(DolbyVisionProfileDvheDer == 0x4);
    static_assert(DolbyVisionProfileDvheDtb == 0x80);
    static_assert(DolbyVisionProfileDvheDth == 0x40);
    static_assert(DolbyVisionProfileDvheDtr == 0x10);
    static_assert(DolbyVisionProfileDvheSt == 0x100);
    static_assert(DolbyVisionProfileDvheStn == 0x20);
    EXPECT_STREQ("Dvav110", asString_DolbyVisionProfile(DolbyVisionProfileDvav110));
    EXPECT_STREQ("DvavPen", asString_DolbyVisionProfile(DolbyVisionProfileDvavPen));
    EXPECT_STREQ("DvavPer", asString_DolbyVisionProfile(DolbyVisionProfileDvavPer));
    EXPECT_STREQ("DvavSe", asString_DolbyVisionProfile(DolbyVisionProfileDvavSe));
    EXPECT_STREQ("DvheDen", asString_DolbyVisionProfile(DolbyVisionProfileDvheDen));
    EXPECT_STREQ("DvheDer", asString_DolbyVisionProfile(DolbyVisionProfileDvheDer));
    EXPECT_STREQ("DvheDtb", asString_DolbyVisionProfile(DolbyVisionProfileDvheDtb));
    EXPECT_STREQ("DvheDth", asString_DolbyVisionProfile(DolbyVisionProfileDvheDth));
    EXPECT_STREQ("DvheDtr", asString_DolbyVisionProfile(DolbyVisionProfileDvheDtr));
    EXPECT_STREQ("DvheSt", asString_DolbyVisionProfile(DolbyVisionProfileDvheSt));
    EXPECT_STREQ("DvheStn", asString_DolbyVisionProfile(DolbyVisionProfileDvheStn));

    static_assert(ERROR_INSUFFICIENT_RESOURCE == 0x44c);
    static_assert(ERROR_RECLAIMED == 0x44d);
    EXPECT_STREQ("INSUFFICIENT_RESOURCE", asString_CodecException_Error(ERROR_INSUFFICIENT_RESOURCE));
    EXPECT_STREQ("RECLAIMED", asString_CodecException_Error(ERROR_RECLAIMED));

    static_assert(ERROR_FRAME_TOO_LARGE == 0x8);
    static_assert(ERROR_INSUFFICIENT_OUTPUT_PROTECTION == 0x4);
    static_assert(ERROR_INSUFFICIENT_SECURITY == 0x7);
    static_assert(ERROR_KEY_EXPIRED == 0x2);
    static_assert(ERROR_LOST_STATE == 0x9);
    static_assert(ERROR_NO_KEY == 0x1);
    static_assert(ERROR_RESOURCE_BUSY == 0x3);
    static_assert(ERROR_SESSION_NOT_OPENED == 0x5);
    static_assert(ERROR_UNSUPPORTED_OPERATION == 0x6);
    EXPECT_STREQ("FRAME_TOO_LARGE", asString_CryptoException_Error(ERROR_FRAME_TOO_LARGE));
    EXPECT_STREQ("INSUFFICIENT_OUTPUT_PROTECTION", asString_CryptoException_Error(ERROR_INSUFFICIENT_OUTPUT_PROTECTION));
    EXPECT_STREQ("INSUFFICIENT_SECURITY", asString_CryptoException_Error(ERROR_INSUFFICIENT_SECURITY));
    EXPECT_STREQ("KEY_EXPIRED", asString_CryptoException_Error(ERROR_KEY_EXPIRED));
    EXPECT_STREQ("LOST_STATE", asString_CryptoException_Error(ERROR_LOST_STATE));
    EXPECT_STREQ("NO_KEY", asString_CryptoException_Error(ERROR_NO_KEY));
    EXPECT_STREQ("RESOURCE_BUSY", asString_CryptoException_Error(ERROR_RESOURCE_BUSY));
    EXPECT_STREQ("SESSION_NOT_OPENED", asString_CryptoException_Error(ERROR_SESSION_NOT_OPENED));
    EXPECT_STREQ("UNSUPPORTED_OPERATION", asString_CryptoException_Error(ERROR_UNSUPPORTED_OPERATION));

    static_assert(H263Level10 == 0x1);
    static_assert(H263Level20 == 0x2);
    static_assert(H263Level30 == 0x4);
    static_assert(H263Level40 == 0x8);
    static_assert(H263Level45 == 0x10);
    static_assert(H263Level50 == 0x20);
    static_assert(H263Level60 == 0x40);
    static_assert(H263Level70 == 0x80);
    EXPECT_STREQ("10", asString_H263Level(H263Level10));
    EXPECT_STREQ("20", asString_H263Level(H263Level20));
    EXPECT_STREQ("30", asString_H263Level(H263Level30));
    EXPECT_STREQ("40", asString_H263Level(H263Level40));
    EXPECT_STREQ("45", asString_H263Level(H263Level45));
    EXPECT_STREQ("50", asString_H263Level(H263Level50));
    EXPECT_STREQ("60", asString_H263Level(H263Level60));
    EXPECT_STREQ("70", asString_H263Level(H263Level70));

    static_assert(H263ProfileBackwardCompatible == 0x4);
    static_assert(H263ProfileBaseline == 0x1);
    static_assert(H263ProfileH320Coding == 0x2);
    static_assert(H263ProfileHighCompression == 0x20);
    static_assert(H263ProfileHighLatency == 0x100);
    static_assert(H263ProfileISWV2 == 0x8);
    static_assert(H263ProfileISWV3 == 0x10);
    static_assert(H263ProfileInterlace == 0x80);
    static_assert(H263ProfileInternet == 0x40);
    EXPECT_STREQ("BackwardCompatible", asString_H263Profile(H263ProfileBackwardCompatible));
    EXPECT_STREQ("Baseline", asString_H263Profile(H263ProfileBaseline));
    EXPECT_STREQ("H320Coding", asString_H263Profile(H263ProfileH320Coding));
    EXPECT_STREQ("HighCompression", asString_H263Profile(H263ProfileHighCompression));
    EXPECT_STREQ("HighLatency", asString_H263Profile(H263ProfileHighLatency));
    EXPECT_STREQ("ISWV2", asString_H263Profile(H263ProfileISWV2));
    EXPECT_STREQ("ISWV3", asString_H263Profile(H263ProfileISWV3));
    EXPECT_STREQ("Interlace", asString_H263Profile(H263ProfileInterlace));
    EXPECT_STREQ("Internet", asString_H263Profile(H263ProfileInternet));

    static_assert(HEVCProfileMain == 0x1);
    static_assert(HEVCProfileMain10 == 0x2);
    static_assert(HEVCProfileMain10HDR10 == 0x1000);
    static_assert(HEVCProfileMain10HDR10Plus == 0x2000);
    static_assert(HEVCProfileMainStill == 0x4);
    EXPECT_STREQ("Main", asString_HEVCProfile(HEVCProfileMain));
    EXPECT_STREQ("Main10", asString_HEVCProfile(HEVCProfileMain10));
    EXPECT_STREQ("Main10HDR", asString_HEVCProfile(HEVCProfileMain10HDR10));
    EXPECT_STREQ("Main10HDRPlus", asString_HEVCProfile(HEVCProfileMain10HDR10Plus));
    EXPECT_STREQ("MainStill", asString_HEVCProfile(HEVCProfileMainStill));

    static_assert(HEVCHighTierLevel1 == 0x2);
    static_assert(HEVCHighTierLevel2 == 0x8);
    static_assert(HEVCHighTierLevel21 == 0x20);
    static_assert(HEVCHighTierLevel3 == 0x80);
    static_assert(HEVCHighTierLevel31 == 0x200);
    static_assert(HEVCHighTierLevel4 == 0x800);
    static_assert(HEVCHighTierLevel41 == 0x2000);
    static_assert(HEVCHighTierLevel5 == 0x8000);
    static_assert(HEVCHighTierLevel51 == 0x20000);
    static_assert(HEVCHighTierLevel52 == 0x80000);
    static_assert(HEVCHighTierLevel6 == 0x200000);
    static_assert(HEVCHighTierLevel61 == 0x800000);
    static_assert(HEVCHighTierLevel62 == 0x2000000);
    static_assert(HEVCMainTierLevel1 == 0x1);
    static_assert(HEVCMainTierLevel2 == 0x4);
    static_assert(HEVCMainTierLevel21 == 0x10);
    static_assert(HEVCMainTierLevel3 == 0x40);
    static_assert(HEVCMainTierLevel31 == 0x100);
    static_assert(HEVCMainTierLevel4 == 0x400);
    static_assert(HEVCMainTierLevel41 == 0x1000);
    static_assert(HEVCMainTierLevel5 == 0x4000);
    static_assert(HEVCMainTierLevel51 == 0x10000);
    static_assert(HEVCMainTierLevel52 == 0x40000);
    static_assert(HEVCMainTierLevel6 == 0x100000);
    static_assert(HEVCMainTierLevel61 == 0x400000);
    static_assert(HEVCMainTierLevel62 == 0x1000000);
    EXPECT_STREQ("High 1", asString_HEVCTierLevel(HEVCHighTierLevel1));
    EXPECT_STREQ("High 2", asString_HEVCTierLevel(HEVCHighTierLevel2));
    EXPECT_STREQ("High 2.1", asString_HEVCTierLevel(HEVCHighTierLevel21));
    EXPECT_STREQ("High 3", asString_HEVCTierLevel(HEVCHighTierLevel3));
    EXPECT_STREQ("High 3.1", asString_HEVCTierLevel(HEVCHighTierLevel31));
    EXPECT_STREQ("High 4", asString_HEVCTierLevel(HEVCHighTierLevel4));
    EXPECT_STREQ("High 4.1", asString_HEVCTierLevel(HEVCHighTierLevel41));
    EXPECT_STREQ("High 5", asString_HEVCTierLevel(HEVCHighTierLevel5));
    EXPECT_STREQ("High 5.1", asString_HEVCTierLevel(HEVCHighTierLevel51));
    EXPECT_STREQ("High 5.2", asString_HEVCTierLevel(HEVCHighTierLevel52));
    EXPECT_STREQ("High 6", asString_HEVCTierLevel(HEVCHighTierLevel6));
    EXPECT_STREQ("High 6.1", asString_HEVCTierLevel(HEVCHighTierLevel61));
    EXPECT_STREQ("High 6.2", asString_HEVCTierLevel(HEVCHighTierLevel62));
    EXPECT_STREQ("Main 1", asString_HEVCTierLevel(HEVCMainTierLevel1));
    EXPECT_STREQ("Main 2", asString_HEVCTierLevel(HEVCMainTierLevel2));
    EXPECT_STREQ("Main 2.1", asString_HEVCTierLevel(HEVCMainTierLevel21));
    EXPECT_STREQ("Main 3", asString_HEVCTierLevel(HEVCMainTierLevel3));
    EXPECT_STREQ("Main 3.1", asString_HEVCTierLevel(HEVCMainTierLevel31));
    EXPECT_STREQ("Main 4", asString_HEVCTierLevel(HEVCMainTierLevel4));
    EXPECT_STREQ("Main 4.1", asString_HEVCTierLevel(HEVCMainTierLevel41));
    EXPECT_STREQ("Main 5", asString_HEVCTierLevel(HEVCMainTierLevel5));
    EXPECT_STREQ("Main 5.1", asString_HEVCTierLevel(HEVCMainTierLevel51));
    EXPECT_STREQ("Main 5.2", asString_HEVCTierLevel(HEVCMainTierLevel52));
    EXPECT_STREQ("Main 6", asString_HEVCTierLevel(HEVCMainTierLevel6));
    EXPECT_STREQ("Main 6.1", asString_HEVCTierLevel(HEVCMainTierLevel61));
    EXPECT_STREQ("Main 6.2", asString_HEVCTierLevel(HEVCMainTierLevel62));

    static_assert(INFO_OUTPUT_BUFFERS_CHANGED == -0x3); // deprecated
    static_assert(INFO_OUTPUT_FORMAT_CHANGED == -0x2);
    static_assert(INFO_TRY_AGAIN_LATER == -0x1);
    EXPECT_STREQ("OUTPUT_BUFFERS_CHANGED", asString_Info(INFO_OUTPUT_BUFFERS_CHANGED)); // deprecated
    EXPECT_STREQ("OUTPUT_FORMAT_CHANGED", asString_Info(INFO_OUTPUT_FORMAT_CHANGED));
    EXPECT_STREQ("TRY_AGAIN_LATER", asString_Info(INFO_TRY_AGAIN_LATER));

    static_assert(MPEG2LevelH14 == 0x2);
    static_assert(MPEG2LevelHL == 0x3);
    static_assert(MPEG2LevelHP == 0x4);
    static_assert(MPEG2LevelLL == 0x0);
    static_assert(MPEG2LevelML == 0x1);
    EXPECT_STREQ("H14", asString_MPEG2Level(MPEG2LevelH14));
    EXPECT_STREQ("HL", asString_MPEG2Level(MPEG2LevelHL));
    EXPECT_STREQ("HP", asString_MPEG2Level(MPEG2LevelHP));
    EXPECT_STREQ("LL", asString_MPEG2Level(MPEG2LevelLL));
    EXPECT_STREQ("ML", asString_MPEG2Level(MPEG2LevelML));

    static_assert(MPEG2Profile422 == 0x2);
    static_assert(MPEG2ProfileHigh == 0x5);
    static_assert(MPEG2ProfileMain == 0x1);
    static_assert(MPEG2ProfileSNR == 0x3);
    static_assert(MPEG2ProfileSimple == 0x0);
    static_assert(MPEG2ProfileSpatial == 0x4);
    EXPECT_STREQ("422", asString_MPEG2Profile(MPEG2Profile422));
    EXPECT_STREQ("High", asString_MPEG2Profile(MPEG2ProfileHigh));
    EXPECT_STREQ("Main", asString_MPEG2Profile(MPEG2ProfileMain));
    EXPECT_STREQ("SNR", asString_MPEG2Profile(MPEG2ProfileSNR));
    EXPECT_STREQ("Simple", asString_MPEG2Profile(MPEG2ProfileSimple));
    EXPECT_STREQ("Spatial", asString_MPEG2Profile(MPEG2ProfileSpatial));

    static_assert(MPEG4Level0 == 0x1);
    static_assert(MPEG4Level0b == 0x2);
    static_assert(MPEG4Level1 == 0x4);
    static_assert(MPEG4Level2 == 0x8);
    static_assert(MPEG4Level3 == 0x10);
    static_assert(MPEG4Level3b == 0x18);
    static_assert(MPEG4Level4 == 0x20);
    static_assert(MPEG4Level4a == 0x40);
    static_assert(MPEG4Level5 == 0x80);
    static_assert(MPEG4Level6 == 0x100);
    EXPECT_STREQ("0", asString_MPEG4Level(MPEG4Level0));
    EXPECT_STREQ("0b", asString_MPEG4Level(MPEG4Level0b));
    EXPECT_STREQ("1", asString_MPEG4Level(MPEG4Level1));
    EXPECT_STREQ("2", asString_MPEG4Level(MPEG4Level2));
    EXPECT_STREQ("3", asString_MPEG4Level(MPEG4Level3));
    EXPECT_STREQ("3b", asString_MPEG4Level(MPEG4Level3b));
    EXPECT_STREQ("4", asString_MPEG4Level(MPEG4Level4));
    EXPECT_STREQ("4a", asString_MPEG4Level(MPEG4Level4a));
    EXPECT_STREQ("5", asString_MPEG4Level(MPEG4Level5));
    EXPECT_STREQ("6", asString_MPEG4Level(MPEG4Level6));

    static_assert(MPEG4ProfileAdvancedCoding == 0x1000);
    static_assert(MPEG4ProfileAdvancedCore == 0x2000);
    static_assert(MPEG4ProfileAdvancedRealTime == 0x400);
    static_assert(MPEG4ProfileAdvancedScalable == 0x4000);
    static_assert(MPEG4ProfileAdvancedSimple == 0x8000);
    static_assert(MPEG4ProfileBasicAnimated == 0x100);
    static_assert(MPEG4ProfileCore == 0x4);
    static_assert(MPEG4ProfileCoreScalable == 0x800);
    static_assert(MPEG4ProfileHybrid == 0x200);
    static_assert(MPEG4ProfileMain == 0x8);
    static_assert(MPEG4ProfileNbit == 0x10);
    static_assert(MPEG4ProfileScalableTexture == 0x20);
    static_assert(MPEG4ProfileSimple == 0x1);
    static_assert(MPEG4ProfileSimpleFBA == 0x80);
    static_assert(MPEG4ProfileSimpleFace == 0x40);
    static_assert(MPEG4ProfileSimpleScalable == 0x2);
    EXPECT_STREQ("AdvancedCoding", asString_MPEG4Profile(MPEG4ProfileAdvancedCoding));
    EXPECT_STREQ("AdvancedCore", asString_MPEG4Profile(MPEG4ProfileAdvancedCore));
    EXPECT_STREQ("AdvancedRealTime", asString_MPEG4Profile(MPEG4ProfileAdvancedRealTime));
    EXPECT_STREQ("AdvancedScalable", asString_MPEG4Profile(MPEG4ProfileAdvancedScalable));
    EXPECT_STREQ("AdvancedSimple", asString_MPEG4Profile(MPEG4ProfileAdvancedSimple));
    EXPECT_STREQ("BasicAnimated", asString_MPEG4Profile(MPEG4ProfileBasicAnimated));
    EXPECT_STREQ("Core", asString_MPEG4Profile(MPEG4ProfileCore));
    EXPECT_STREQ("CoreScalable", asString_MPEG4Profile(MPEG4ProfileCoreScalable));
    EXPECT_STREQ("Hybrid", asString_MPEG4Profile(MPEG4ProfileHybrid));
    EXPECT_STREQ("Main", asString_MPEG4Profile(MPEG4ProfileMain));
    EXPECT_STREQ("Nbit", asString_MPEG4Profile(MPEG4ProfileNbit));
    EXPECT_STREQ("ScalableTexture", asString_MPEG4Profile(MPEG4ProfileScalableTexture));
    EXPECT_STREQ("Simple", asString_MPEG4Profile(MPEG4ProfileSimple));
    EXPECT_STREQ("SimpleFBA", asString_MPEG4Profile(MPEG4ProfileSimpleFBA));
    EXPECT_STREQ("SimpleFace", asString_MPEG4Profile(MPEG4ProfileSimpleFace));
    EXPECT_STREQ("SimpleScalable", asString_MPEG4Profile(MPEG4ProfileSimpleScalable));

    static_assert(TYPE_BYTE_BUFFER == 0x5);
    static_assert(TYPE_FLOAT == 0x3);
    static_assert(TYPE_INTEGER == 0x1);
    static_assert(TYPE_LONG == 0x2);
    static_assert(TYPE_NULL == 0x0);
    static_assert(TYPE_STRING == 0x4);
    EXPECT_STREQ("BYTE_BUFFER", asString_Type(TYPE_BYTE_BUFFER));
    EXPECT_STREQ("FLOAT", asString_Type(TYPE_FLOAT));
    EXPECT_STREQ("INTEGER", asString_Type(TYPE_INTEGER));
    EXPECT_STREQ("LONG", asString_Type(TYPE_LONG));
    EXPECT_STREQ("NULL", asString_Type(TYPE_NULL));
    EXPECT_STREQ("STRING", asString_Type(TYPE_STRING));

    static_assert(VP8Level_Version0 == 0x1);
    static_assert(VP8Level_Version1 == 0x2);
    static_assert(VP8Level_Version2 == 0x4);
    static_assert(VP8Level_Version3 == 0x8);
    EXPECT_STREQ("V0", asString_VP8Level(VP8Level_Version0));
    EXPECT_STREQ("V1", asString_VP8Level(VP8Level_Version1));
    EXPECT_STREQ("V2", asString_VP8Level(VP8Level_Version2));
    EXPECT_STREQ("V3", asString_VP8Level(VP8Level_Version3));

    static_assert(VP8ProfileMain == 0x1);
    EXPECT_STREQ("Main", asString_VP8Profile(VP8ProfileMain));

    static_assert(VP9Level1 == 0x1);
    static_assert(VP9Level11 == 0x2);
    static_assert(VP9Level2 == 0x4);
    static_assert(VP9Level21 == 0x8);
    static_assert(VP9Level3 == 0x10);
    static_assert(VP9Level31 == 0x20);
    static_assert(VP9Level4 == 0x40);
    static_assert(VP9Level41 == 0x80);
    static_assert(VP9Level5 == 0x100);
    static_assert(VP9Level51 == 0x200);
    static_assert(VP9Level52 == 0x400);
    static_assert(VP9Level6 == 0x800);
    static_assert(VP9Level61 == 0x1000);
    static_assert(VP9Level62 == 0x2000);
    EXPECT_STREQ("1", asString_VP9Level(VP9Level1));
    EXPECT_STREQ("1.1", asString_VP9Level(VP9Level11));
    EXPECT_STREQ("2", asString_VP9Level(VP9Level2));
    EXPECT_STREQ("2.1", asString_VP9Level(VP9Level21));
    EXPECT_STREQ("3", asString_VP9Level(VP9Level3));
    EXPECT_STREQ("3.1", asString_VP9Level(VP9Level31));
    EXPECT_STREQ("4", asString_VP9Level(VP9Level4));
    EXPECT_STREQ("4.1", asString_VP9Level(VP9Level41));
    EXPECT_STREQ("5", asString_VP9Level(VP9Level5));
    EXPECT_STREQ("5.1", asString_VP9Level(VP9Level51));
    EXPECT_STREQ("5.2", asString_VP9Level(VP9Level52));
    EXPECT_STREQ("6", asString_VP9Level(VP9Level6));
    EXPECT_STREQ("6.1", asString_VP9Level(VP9Level61));
    EXPECT_STREQ("6.2", asString_VP9Level(VP9Level62));

    static_assert(VP9Profile0 == 0x1);
    static_assert(VP9Profile1 == 0x2);
    static_assert(VP9Profile2 == 0x4);
    static_assert(VP9Profile2HDR == 0x1000);
    static_assert(VP9Profile2HDR10Plus == 0x4000);
    static_assert(VP9Profile3 == 0x8);
    static_assert(VP9Profile3HDR == 0x2000);
    static_assert(VP9Profile3HDR10Plus == 0x8000);
    EXPECT_STREQ("0", asString_VP9Profile(VP9Profile0));
    EXPECT_STREQ("1", asString_VP9Profile(VP9Profile1));
    EXPECT_STREQ("2", asString_VP9Profile(VP9Profile2));
    EXPECT_STREQ("2HDR", asString_VP9Profile(VP9Profile2HDR));
    EXPECT_STREQ("2HDR10Plus", asString_VP9Profile(VP9Profile2HDR10Plus));
    EXPECT_STREQ("3", asString_VP9Profile(VP9Profile3));
    EXPECT_STREQ("3HDR", asString_VP9Profile(VP9Profile3HDR));
    EXPECT_STREQ("3HDR10Plus", asString_VP9Profile(VP9Profile3HDR10Plus));

    static_assert(VIDEO_SCALING_MODE_SCALE_TO_FIT == 0x1);
    static_assert(VIDEO_SCALING_MODE_SCALE_TO_FIT_WITH_CROPPING == 0x2);
    EXPECT_STREQ("SCALE_TO_FIT", asString_VideoScalingMode(VIDEO_SCALING_MODE_SCALE_TO_FIT));
    EXPECT_STREQ("SCALE_TO_FIT_WITH_CROPPING", asString_VideoScalingMode(VIDEO_SCALING_MODE_SCALE_TO_FIT_WITH_CROPPING));


    EXPECT_STREQ("android.media.mediacodec.codec", CODEC);
    EXPECT_STREQ("android.media.mediacodec.encoder", ENCODER);
    EXPECT_STREQ("adaptive-playback", FEATURE_AdaptivePlayback);
    EXPECT_STREQ("dynamic-timestamp", FEATURE_DynamicTimestamp);
    EXPECT_STREQ("frame-parsing", FEATURE_FrameParsing);
    EXPECT_STREQ("intra-refresh", FEATURE_IntraRefresh);
    EXPECT_STREQ("low-latency", FEATURE_LowLatency);
    EXPECT_STREQ("multiple-frames", FEATURE_MultipleFrames);
    EXPECT_STREQ("partial-frame", FEATURE_PartialFrame);
    EXPECT_STREQ("secure-playback", FEATURE_SecurePlayback);
    EXPECT_STREQ("tunneled-playback", FEATURE_TunneledPlayback);
    EXPECT_STREQ("android.media.mediacodec.height", HEIGHT);
    EXPECT_STREQ("aac-drc-album-mode", KEY_AAC_DRC_ALBUM_MODE);
    EXPECT_STREQ("aac-drc-cut-level", KEY_AAC_DRC_ATTENUATION_FACTOR);
    EXPECT_STREQ("aac-drc-boost-level", KEY_AAC_DRC_BOOST_FACTOR);
    EXPECT_STREQ("aac-drc-effect-type", KEY_AAC_DRC_EFFECT_TYPE);
    EXPECT_STREQ("aac-drc-heavy-compression", KEY_AAC_DRC_HEAVY_COMPRESSION);
    EXPECT_STREQ("aac-drc-output-loudness", KEY_AAC_DRC_OUTPUT_LOUDNESS);
    EXPECT_STREQ("aac-target-ref-level", KEY_AAC_DRC_TARGET_REFERENCE_LEVEL);
    EXPECT_STREQ("aac-encoded-target-level", KEY_AAC_ENCODED_TARGET_LEVEL);
    EXPECT_STREQ("aac-max-output-channel_count", KEY_AAC_MAX_OUTPUT_CHANNEL_COUNT);
    EXPECT_STREQ("aac-profile", KEY_AAC_PROFILE);
    EXPECT_STREQ("aac-sbr-mode", KEY_AAC_SBR_MODE);
    EXPECT_STREQ("audio-hw-sync", KEY_AUDIO_HW_SYNC); // hidden
    EXPECT_STREQ("audio-session-id", KEY_AUDIO_SESSION_ID);
    EXPECT_STREQ("bitrate-mode", KEY_BITRATE_MODE);
    EXPECT_STREQ("bitrate", KEY_BIT_RATE);
    EXPECT_STREQ("caption-service-number", KEY_CAPTION_SERVICE_NUMBER);
    EXPECT_STREQ("capture-rate", KEY_CAPTURE_RATE);
    EXPECT_STREQ("ca-private-data", KEY_CA_PRIVATE_DATA); // hidden
    EXPECT_STREQ("ca-session-id", KEY_CA_SESSION_ID); // hidden
    EXPECT_STREQ("ca-system-id", KEY_CA_SYSTEM_ID); // hidden
    EXPECT_STREQ("channel-count", KEY_CHANNEL_COUNT);
    EXPECT_STREQ("channel-mask", KEY_CHANNEL_MASK);
    EXPECT_STREQ("codecs-string", KEY_CODECS_STRING);
    EXPECT_STREQ("color-format", KEY_COLOR_FORMAT);
    EXPECT_STREQ("color-range", KEY_COLOR_RANGE);
    EXPECT_STREQ("color-standard", KEY_COLOR_STANDARD);
    EXPECT_STREQ("color-transfer", KEY_COLOR_TRANSFER);
    EXPECT_STREQ("complexity", KEY_COMPLEXITY);
    EXPECT_STREQ("create-input-buffers-suspended", KEY_CREATE_INPUT_SURFACE_SUSPENDED);
    EXPECT_STREQ("durationUs", KEY_DURATION);
    EXPECT_STREQ("encoder-delay", KEY_ENCODER_DELAY);
    EXPECT_STREQ("encoder-padding", KEY_ENCODER_PADDING);
    EXPECT_STREQ("feature-", KEY_FEATURE_); // hidden
    EXPECT_STREQ("flac-compression-level", KEY_FLAC_COMPRESSION_LEVEL);
    EXPECT_STREQ("frame-rate", KEY_FRAME_RATE);
    EXPECT_STREQ("grid-cols", KEY_GRID_COLUMNS);
    EXPECT_STREQ("grid-rows", KEY_GRID_ROWS);
    EXPECT_STREQ("haptic-channel-count", KEY_HAPTIC_CHANNEL_COUNT);
    EXPECT_STREQ("hw-av-sync-id", KEY_HARDWARE_AV_SYNC_ID);
    EXPECT_STREQ("hdr10-plus-info", KEY_HDR10_PLUS_INFO);
    EXPECT_STREQ("hdr-static-info", KEY_HDR_STATIC_INFO);
    EXPECT_STREQ("height", KEY_HEIGHT);
    EXPECT_STREQ("intra-refresh-period", KEY_INTRA_REFRESH_PERIOD);
    EXPECT_STREQ("is-adts", KEY_IS_ADTS);
    EXPECT_STREQ("is-autoselect", KEY_IS_AUTOSELECT);
    EXPECT_STREQ("is-default", KEY_IS_DEFAULT);
    EXPECT_STREQ("is-forced-subtitle", KEY_IS_FORCED_SUBTITLE);
    EXPECT_STREQ("is-timed-text", KEY_IS_TIMED_TEXT); // hidden
    EXPECT_STREQ("i-frame-interval", KEY_I_FRAME_INTERVAL);
    EXPECT_STREQ("language", KEY_LANGUAGE);
    EXPECT_STREQ("latency", KEY_LATENCY);
    EXPECT_STREQ("level", KEY_LEVEL);
    EXPECT_STREQ("low-latency", KEY_LOW_LATENCY);
    EXPECT_STREQ("max-bitrate", KEY_MAX_BIT_RATE); // hidden
    EXPECT_STREQ("max-bframes", KEY_MAX_B_FRAMES);
    EXPECT_STREQ("max-fps-to-encoder", KEY_MAX_FPS_TO_ENCODER);
    EXPECT_STREQ("max-height", KEY_MAX_HEIGHT);
    EXPECT_STREQ("max-input-size", KEY_MAX_INPUT_SIZE);
    EXPECT_STREQ("max-pts-gap-to-encoder", KEY_MAX_PTS_GAP_TO_ENCODER);
    EXPECT_STREQ("max-width", KEY_MAX_WIDTH);
    EXPECT_STREQ("mime", KEY_MIME);
    EXPECT_STREQ("operating-rate", KEY_OPERATING_RATE);
    EXPECT_STREQ("output-reorder-depth", KEY_OUTPUT_REORDER_DEPTH);
    EXPECT_STREQ("pcm-encoding", KEY_PCM_ENCODING);
    EXPECT_STREQ("sar-height", KEY_PIXEL_ASPECT_RATIO_HEIGHT);
    EXPECT_STREQ("sar-width", KEY_PIXEL_ASPECT_RATIO_WIDTH);
    EXPECT_STREQ("prepend-sps-pps-to-idr-frames", KEY_PREPEND_HEADER_TO_SYNC_FRAMES);
    EXPECT_STREQ("priority", KEY_PRIORITY);
    EXPECT_STREQ("profile", KEY_PROFILE);
    EXPECT_STREQ("push-blank-buffers-on-shutdown", KEY_PUSH_BLANK_BUFFERS_ON_STOP);
    EXPECT_STREQ("quality", KEY_QUALITY);
    EXPECT_STREQ("repeat-previous-frame-after", KEY_REPEAT_PREVIOUS_FRAME_AFTER);
    EXPECT_STREQ("rotation-degrees", KEY_ROTATION);
    EXPECT_STREQ("sample-rate", KEY_SAMPLE_RATE);
    EXPECT_STREQ("slice-height", KEY_SLICE_HEIGHT);
    EXPECT_STREQ("stride", KEY_STRIDE);
    EXPECT_STREQ("ts-schema", KEY_TEMPORAL_LAYERING);
    EXPECT_STREQ("tile-height", KEY_TILE_HEIGHT);
    EXPECT_STREQ("tile-width", KEY_TILE_WIDTH);
    EXPECT_STREQ("track-id", KEY_TRACK_ID);
    EXPECT_STREQ("width", KEY_WIDTH);
    EXPECT_STREQ("audio/mp4a-latm", MIMETYPE_AUDIO_AAC);
    EXPECT_STREQ("audio/ac3", MIMETYPE_AUDIO_AC3);
    EXPECT_STREQ("audio/ac4", MIMETYPE_AUDIO_AC4);
    EXPECT_STREQ("audio/3gpp", MIMETYPE_AUDIO_AMR_NB);
    EXPECT_STREQ("audio/amr-wb", MIMETYPE_AUDIO_AMR_WB);
    EXPECT_STREQ("audio/eac3", MIMETYPE_AUDIO_EAC3);
    EXPECT_STREQ("audio/eac3-joc", MIMETYPE_AUDIO_EAC3_JOC);
    EXPECT_STREQ("audio/flac", MIMETYPE_AUDIO_FLAC);
    EXPECT_STREQ("audio/g711-alaw", MIMETYPE_AUDIO_G711_ALAW);
    EXPECT_STREQ("audio/g711-mlaw", MIMETYPE_AUDIO_G711_MLAW);
    EXPECT_STREQ("audio/mpeg", MIMETYPE_AUDIO_MPEG);
    EXPECT_STREQ("audio/gsm", MIMETYPE_AUDIO_MSGSM);
    EXPECT_STREQ("audio/opus", MIMETYPE_AUDIO_OPUS);
    EXPECT_STREQ("audio/qcelp", MIMETYPE_AUDIO_QCELP);
    EXPECT_STREQ("audio/raw", MIMETYPE_AUDIO_RAW);
    EXPECT_STREQ("audio/scrambled", MIMETYPE_AUDIO_SCRAMBLED);
    EXPECT_STREQ("audio/vorbis", MIMETYPE_AUDIO_VORBIS);
    EXPECT_STREQ("image/vnd.android.heic", MIMETYPE_IMAGE_ANDROID_HEIC);
    EXPECT_STREQ("text/cea-608", MIMETYPE_TEXT_CEA_608);
    EXPECT_STREQ("text/cea-708", MIMETYPE_TEXT_CEA_708);
    EXPECT_STREQ("application/x-subrip", MIMETYPE_TEXT_SUBRIP);
    EXPECT_STREQ("text/vtt", MIMETYPE_TEXT_VTT);
    EXPECT_STREQ("video/av01", MIMETYPE_VIDEO_AV1);
    EXPECT_STREQ("video/avc", MIMETYPE_VIDEO_AVC);
    EXPECT_STREQ("video/dolby-vision", MIMETYPE_VIDEO_DOLBY_VISION);
    EXPECT_STREQ("video/3gpp", MIMETYPE_VIDEO_H263);
    EXPECT_STREQ("video/hevc", MIMETYPE_VIDEO_HEVC);
    EXPECT_STREQ("video/mpeg2", MIMETYPE_VIDEO_MPEG2);
    EXPECT_STREQ("video/mp4v-es", MIMETYPE_VIDEO_MPEG4);
    EXPECT_STREQ("video/raw", MIMETYPE_VIDEO_RAW);
    EXPECT_STREQ("video/scrambled", MIMETYPE_VIDEO_SCRAMBLED);
    EXPECT_STREQ("video/x-vnd.on2.vp8", MIMETYPE_VIDEO_VP8);
    EXPECT_STREQ("video/x-vnd.on2.vp9", MIMETYPE_VIDEO_VP9);
    EXPECT_STREQ("android.media.mediacodec.mime", MIME_TYPE);
    EXPECT_STREQ("android.media.mediacodec.mode", MODE);
    EXPECT_STREQ("audio", MODE_AUDIO);
    EXPECT_STREQ("video", MODE_VIDEO);
    EXPECT_STREQ("hdr10-plus-info", PARAMETER_KEY_HDR10_PLUS_INFO);
    EXPECT_STREQ("low-latency", PARAMETER_KEY_LOW_LATENCY);
    EXPECT_STREQ("time-offset-us", PARAMETER_KEY_OFFSET_TIME);
    EXPECT_STREQ("request-sync", PARAMETER_KEY_REQUEST_SYNC_FRAME);
    EXPECT_STREQ("drop-input-frames", PARAMETER_KEY_SUSPEND);
    EXPECT_STREQ("drop-start-time-us", PARAMETER_KEY_SUSPEND_TIME);
    EXPECT_STREQ("video-bitrate", PARAMETER_KEY_VIDEO_BITRATE);
    EXPECT_STREQ("android.media.mediacodec.rotation", ROTATION);
    EXPECT_STREQ("android.media.mediacodec.secure", SECURE);
    EXPECT_STREQ("android.media.mediacodec.width", WIDTH);
}
