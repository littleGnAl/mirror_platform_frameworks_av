# Codec2 VTS Hal @ 1.0 tests #

## master :
Functionality of master is to enumerate all the Codec2 components available in C2 media service.

usage: `atest VtsHalMediaC2V1_0TargetMasterTest`

## component :
Functionality of component test is to validate common functionality across all the Codec2 components available in C2 media service. For a standard C2 component, these tests are expected to pass.

usage: `atest VtsHalMediaC2V1_0TargetComponentTest`

## audio :
Functionality of audio test is to validate audio specific functionality of Codec2 components. The resource files for this test are taken from `frameworks/av/media/codec2/hidl/1.0/vts/functional/res`. The path to these files on the device can be specified with `-P`. (If the device path is omitted, `/data/local/tmp/media/` is the default value.)

usage: `atest VtsHalMediaC2V1_0TargetAudioDecTest`

usage: `atest VtsHalMediaC2V1_0TargetAudioEncTest`

## video :
Functionality of video test is to validate video specific functionality of Codec2 components. The resource files for this test are taken from `frameworks/av/media/codec2/hidl/1.0/vts/functional/res`. The path to these files on the device can be specified with `-P`. (If the device path is omitted, `/data/local/tmp/media/` is the default value.)

usage: `atest VtsHalMediaC2V1_0TargetVideoDecTest`
usage: `atest VtsHalMediaC2V1_0TargetVideoEncTest`

## custom_codecs:
VTS tests have provision for running not only the default test vectors (test vectors present in res folder) but also additional test vectors. For this, vendor needs to push the test vectors for testing custom codecs to /data/local/tmp/media folder on the device and create two files VideoDec.txt and AudioDec.txt (example files are in vts/functional/res/). The contents of the file should follow the same pattern as the pattern of actual parameters present at the default location

There are two formats in which we can give the text file to the decoder tests.

### MediaExtractor supports the custom codec being tested
To decode an input for a custom codec which is supported in AMediaExtractor(), just specify the file name. Test calls extractor using AMediaExtractor API to get the required data.

Syntax for such cases is:

inputClip1
inputClip2

e.g:

For Audio Decoder: `bbb_mono_16kHz_128kbps_1s.mp4`
For Video Decoder: `bbb_520x390_30fps_avc.mp4`

### MediaExtractor doesn't support the custom codec being tested
When AMediaExtractor doesn't support a codec that needs to be tested, raw bitstream can be given in a binary file along with a mime and a text file describing the properties of each decodable unit

Syntax for such cases is:

inputClip1 inputInfo1 mime1
inputClip2 inputInfo2 mime2

e.g:

For Audio Decoder: `bbb_aac_stereo_128kbps_48000hz.aac bbb_aac_stereo_128kbps_48000hz.info audio/mp4a-latm`
For Video Decoder: `bbb_avc_176x144_300kbps_60fps.h264 bbb_avc_176x144_300kbps_60fps.info video/avc`

The inputInfo file should contain one line per decodable unit in the following format
framesize flags timestamp

the values of flag can be:
32 for CSD data
1 for SYNC/IDR Frame
0 for P/B Frames

### VtsHalMediaC2V1_0TargetVideoDecTest:
The video decoder test parses text file in resourceFolder/VideoDecTest.txt for additional parameters. The text file can give inputs in any of the two formats mentioned [custom_codecs](#custom_codecs).

### VtsHalMediaC2V1_0TargetAudioDecTest:
The audio decoder test parses text file in resourceFolder/AudioDecTest.txt for additional parameters. The text file can give inputs in any of the two formats mentioned [custom_codecs](#custom_codecs).
