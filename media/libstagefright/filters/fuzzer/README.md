# Fuzzer for libstagefright_filters

## Table of contents
+ [libstagefright_mediafilter_fuzzer](#mediafilter)
+ [libstagefright_colorconvert_fuzzer](#colorconvert)

# <a name="mediafilter"></a> Fuzzer for libstagefright_mediafilter
libstagefright_mediafilter supports the following parameters:
1. Component names(parameter name: "kComponentNames")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`kComponentNames`| 1.`android.filter.zerofilter`, 2.`android.filter.saturation`, 3.`android.filter.intrinsicblur`, 4.`android.filter.RenderScript` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
$ mm -j$(nproc) libstagefright_mediafilter_fuzzer
```
2. Run on device
```
$ adb sync data
$ adb shell /data/fuzz/arm64/libstagefright_mediafilter_fuzzer/libstagefright_mediafilter_fuzzer
```
# <a name="colorconvert"></a> Fuzzer for libstagefright_colorconvert
libstagefright_colorconvert supports the following parameters:
1. Width (parameter name:"width")
2. Height (parameter name:"height")
3. Stride (parameter name:"stride")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`width`|Integer from `2` to `255` |Value obtained from FuzzedDataProvider|
|`height`|Integer from `2` to `255` |Value obtained from FuzzedDataProvider|
|`stride`|Integer from `width` to `2*255` |Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
$ mm -j$(nproc) libstagefright_colorconvert_fuzzer
```
2. Run on device
```
$ adb sync data
$ adb shell /data/fuzz/arm64/libstagefright_colorconvert_fuzzer/libstagefright_colorconvert_fuzzer
```
