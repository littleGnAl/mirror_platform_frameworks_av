## Media Testing ##
---

#### Mpeg4H263Encoder :
The Mpeg4H263Encoder Test Suite validates the Mpeg4 and H263 encoder available in libstagefright.
Run the following steps to build the test suite:
```
m Mpeg4H263EncoderTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/
The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/Mpeg4H263EncoderTest/Mpeg4H263EncoderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/Mpeg4H263EncoderTest/Mpeg4H263EncoderTest /data/local/tmp/
```

The resource file for the tests is taken from [here] https://drive.google.com/drive/folders/12NMVyf_Hbw5da-bq5zSY_BXz87k8cvad
Download Mpeg4H263Encoder folder and push all the files in this folder to /data/local/tmp/ on the device for testing.
```
adb push Mpeg4H263Encoder/. /data/local/tmp/
```
usage: Mpeg4H263EncoderTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/Mpeg4H263EncoderTest -P /data/local/tmp/
```
