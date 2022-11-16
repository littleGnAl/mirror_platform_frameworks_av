# Fuzzer for libstagefright_filters

## Table of contents
+ [libstagefright_mediafilter_fuzzer](#mediafilter)
+ [libstagefright_colorconvert_fuzzer](#colorconvert)
+ [libstagefright_graphicBufferListener_fuzzer](#graphicBufferListener)

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

# <a name="graphicBufferListener"></a> Fuzzer for libstagefright_graphicBufferListener
libstagefright_graphicBufferListener supports the following parameters:
1. Dataspace (parameter name:"kDataSpaces")
2. Scaling mode (parameter name:"kScalingModes")
3. API (parameter name:"kSelectAPI")
4. Usage type (parameter name:"kUsageTypes")
5. Pixel format (parameter name:"kPixelFormatTypes")

| Parameter| Valid Values| Configured Value|
|------------- |-------------| ----- |
|`kDataSpaces`|1.`HAL_DATASPACE_UNKNOWN`,<br/> 2.`HAL_DATASPACE_ARBITRARY`,<br/> 3.`HAL_DATASPACE_STANDARD_SHIFT`,<br/> 4.`HAL_DATASPACE_STANDARD_MASK`,<br/> 5.`HAL_DATASPACE_STANDARD_UNSPECIFIED`,<br/> 6.`HAL_DATASPACE_STANDARD_BT709`,<br/> 7.`HAL_DATASPACE_STANDARD_BT601_625`,<br/> 8.`HAL_DATASPACE_STANDARD_BT601_625_UNADJUSTED`,<br/> 9.`HAL_DATASPACE_STANDARD_BT601_525`,<br/> 10.`HAL_DATASPACE_STANDARD_BT601_525_UNADJUSTED`,<br/> 11.`HAL_DATASPACE_STANDARD_BT2020`,<br/> 12.`HAL_DATASPACE_STANDARD_BT2020_CONSTANT_LUMINANCE`,<br/> 13.`HAL_DATASPACE_STANDARD_BT470M`,<br/> 14.`HAL_DATASPACE_STANDARD_FILM`,<br/> 15.`HAL_DATASPACE_STANDARD_DCI_P3`,<br/> 16.`HAL_DATASPACE_STANDARD_ADOBE_RGB`,<br/> 17.`HAL_DATASPACE_TRANSFER_SHIFT`,<br/> 18.`HAL_DATASPACE_TRANSFER_MASK`,<br/> 19.`HAL_DATASPACE_TRANSFER_UNSPECIFIED`,<br/> 20.`HAL_DATASPACE_TRANSFER_LINEAR`,<br/> 21.`HAL_DATASPACE_TRANSFER_SRGB`,<br/> 22.`HAL_DATASPACE_TRANSFER_SMPTE_170M`,<br/> 23.`HAL_DATASPACE_TRANSFER_GAMMA2_2`,<br/> 24.`HAL_DATASPACE_TRANSFER_GAMMA2_6`,<br/> 25.`HAL_DATASPACE_TRANSFER_GAMMA2_8`,<br/> 26.`HAL_DATASPACE_TRANSFER_ST2084`,<br/> 27.`HAL_DATASPACE_TRANSFER_HLG`,<br/> 28.`HAL_DATASPACE_RANGE_SHIFT`,<br/> 29.`HAL_DATASPACE_RANGE_MASK`,<br/> 30.`HAL_DATASPACE_RANGE_UNSPECIFIED`,<br/> 31.`HAL_DATASPACE_RANGE_FULL`,<br/> 32.`HAL_DATASPACE_RANGE_LIMITED`,<br/> 33.`HAL_DATASPACE_RANGE_EXTENDED`,<br/> 34.`HAL_DATASPACE_SRGB_LINEAR`,<br/> 35.`HAL_DATASPACE_V0_SRGB_LINEAR`,<br/> 36.`HAL_DATASPACE_V0_SCRGB_LINEAR`,<br/> 37.`HAL_DATASPACE_SRGB`,<br/> 38.`HAL_DATASPACE_V0_SCRGB`,<br/> 39.`HAL_DATASPACE_JFIF`,<br/> 40.`HAL_DATASPACE_V0_JFIF`,<br/> 41.`HAL_DATASPACE_BT601_625`,<br/> 42.`HAL_DATASPACE_V0_BT601_625`,<br/> 43.`HAL_DATASPACE_BT601_525`,<br/> 44.`HAL_DATASPACE_V0_BT601_525`,<br/> 45.`HAL_DATASPACE_BT709`,<br/> 46.`HAL_DATASPACE_V0_BT709`,<br/> 47.`HAL_DATASPACE_DCI_P3_LINEAR`,<br/> 48.`HAL_DATASPACE_DCI_P3`,<br/> 49.`HAL_DATASPACE_DISPLAY_P3_LINEAR`,<br/> 50.`HAL_DATASPACE_DISPLAY_P3`,<br/> 51.`HAL_DATASPACE_ADOBE_RGB`,<br/> 52.`HAL_DATASPACE_BT2020_LINEAR`,<br/> 53.`HAL_DATASPACE_BT2020`,<br/> 54.`HAL_DATASPACE_BT2020_PQ`,<br/> 55.`HAL_DATASPACE_DEPTH`,<br/> 56.`HAL_DATASPACE_SENSOR` |Value obtained from FuzzedDataProvider|
|`kScalingModes`|1.`NATIVE_WINDOW_SCALING_MODE_FREEZE`,<br/> 2.`NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW`,<br/> 3.`NATIVE_WINDOW_SCALING_MODE_SCALE_CROP`,<br/> 4.`NATIVE_WINDOW_SCALING_MODE_NO_SCALE_CROP` |Value obtained from FuzzedDataProvider|
|`kSelectAPI`|1.`NATIVE_WINDOW_API_EGL`,<br/> 2.`NATIVE_WINDOW_API_CPU`,<br/> 3.`NATIVE_WINDOW_API_MEDIA`,<br/> 4.`NATIVE_WINDOW_API_CAMERA`,<br/> |Value obtained from FuzzedDataProvider|
|`kUsageTypes`|1.`GRALLOC_USAGE_SW_READ_NEVER`,<br/> 2.`GRALLOC_USAGE_SW_READ_RARELY`,<br/> 3.`GRALLOC_USAGE_SW_READ_OFTEN`,<br/> 4.`GRALLOC_USAGE_SW_READ_MASK`,<br/> 5.`GRALLOC_USAGE_SW_WRITE_NEVER`,<br/> 6.`GRALLOC_USAGE_SW_WRITE_RARELY`,<br/> 7.`GRALLOC_USAGE_SW_WRITE_OFTEN`,<br/> 8.`GRALLOC_USAGE_SW_WRITE_MASK`|Value obtained from FuzzedDataProvider|
|`kPixelFormatTypes`| 1.`PIXEL_FORMAT_UNKNOWN`,<br/> 2.`PIXEL_FORMAT_NONE`,<br/> 3.`PIXEL_FORMAT_CUSTOM`,<br/> 4.`PIXEL_FORMAT_TRANSLUCENT`,<br/> 5.`PIXEL_FORMAT_TRANSPARENT`,<br/> 6.`PIXEL_FORMAT_OPAQUE`,<br/> 7.`PIXEL_FORMAT_RGBA_8888`|Value obtained from FuzzedDataProvider|

#### Steps to run
1. Build the fuzzer
```
$ mm -j$(nproc) libstagefright_graphicBufferListener_fuzzer
```
2. Run on device
```
$ adb sync data
$ adb shell /data/fuzz/arm64/libstagefright_graphicBufferListener_fuzzer/libstagefright_graphicBufferListener_fuzzer
