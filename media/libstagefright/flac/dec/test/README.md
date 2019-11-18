## Media Testing ##
---
#### FlacDecoder :
The FlacDecoder Test Suite validates the FlacDecoder available in libstagefright.

Run the following steps to build the test suite:
```
m FlacDecoderTest
```

The 32-bit binaries will be created in the following path : ${OUT}/data/nativetest/

The 64-bit binaries will be created in the following path : ${OUT}/data/nativetest64/

To test 64-bit binary push binaries from nativetest64.
```
adb push ${OUT}/data/nativetest64/FlacDecoderTest/FlacDecoderTest /data/local/tmp/
```

To test 32-bit binary push binaries from nativetest.
```
adb push ${OUT}/data/nativetest/FlacDecoderTest/FlacDecoderTest /data/local/tmp/
```

The resource file for the tests is taken from [here](https://drive.google.com/drive/folders/13cM4tAaVFrmr-zGFqaAzFBbKs75pnm9b).
Download Flac folder and push all the files in this folder to /data/local/tmp/ on the device for testing.
```
adb push Flac/. /data/local/tmp/
```

usage: FlacDecoderTest -P \<path_to_folder\>
```
adb shell /data/local/tmp/FlacDecoderTest -P /data/local/tmp/