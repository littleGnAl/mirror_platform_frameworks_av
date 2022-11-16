/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include <filters/ColorConvert.h>
#include <fuzzer/FuzzedDataProvider.h>

using namespace android;

constexpr uint32_t kColorDimMin = 2;
constexpr uint32_t kColorDimMax = 255;
constexpr uint32_t kColorARGBMultiplier = 4;
constexpr uint32_t kColorRGB888Multiplier = 3;
constexpr int32_t kMinColorAPI = 0;
constexpr int32_t kMaxColorAPI = 2;

struct colorConvertElements {
    int32_t height;
    int32_t width;
    uint32_t sizeRequiredY;
    uint32_t sizeRequiredUV;
    uint32_t sizeRequiredDest;
    std::vector<uint8_t> vecDataY;
    std::vector<uint8_t> vecDataUV;
    std::vector<uint8_t> dest;
};

class ColorConvertFuzzer {
  public:
    ColorConvertFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

  private:
    void fixColorVectors(std::vector<uint8_t>& vec, uint32_t& size);
    void setupColorConvertAPIs(colorConvertElements& elements, uint32_t multiplier);
    FuzzedDataProvider mFdp;
};

void ColorConvertFuzzer::fixColorVectors(std::vector<uint8_t>& vec, uint32_t& size) {
    vec = mFdp.ConsumeBytes<uint8_t>(size);
    vec.resize(size, 0);
}

void ColorConvertFuzzer::setupColorConvertAPIs(colorConvertElements& elements,
                                               uint32_t multiplier) {
    elements.height = mFdp.ConsumeIntegralInRange<int32_t>(kColorDimMin, kColorDimMax);
    elements.width = mFdp.ConsumeIntegralInRange<int32_t>(kColorDimMin, kColorDimMax);
    elements.sizeRequiredY = elements.width * elements.height;
    elements.sizeRequiredUV = ((elements.width + 1) / 2) * ((elements.height + 1) / 2) * 2;
    elements.sizeRequiredDest = multiplier * elements.width * elements.height;
    fixColorVectors(elements.vecDataY, elements.sizeRequiredY);
    fixColorVectors(elements.vecDataUV, elements.sizeRequiredUV);
    fixColorVectors(elements.dest, elements.sizeRequiredDest);
}

void ColorConvertFuzzer::process() {
    while (mFdp.remaining_bytes()) {
        switch (mFdp.ConsumeIntegralInRange<size_t>(kMinColorAPI, kMaxColorAPI)) {
            case 0: {
                colorConvertElements elements;
                setupColorConvertAPIs(elements, kColorARGBMultiplier);
                convertYUV420spToARGB(elements.vecDataY.data(), elements.vecDataUV.data(),
                                      elements.width, elements.height, elements.dest.data());
                break;
            }
            case 1: {
                colorConvertElements elements;
                setupColorConvertAPIs(elements, kColorRGB888Multiplier);
                convertYUV420spToRGB888(elements.vecDataY.data(), elements.vecDataUV.data(),
                                        elements.width, elements.height, elements.dest.data());
                break;
            }
            case 2: {
                std::vector<uint8_t> vecDataSrc, vecDataDest;
                int32_t width = mFdp.ConsumeIntegralInRange<int32_t>(kColorDimMin, kColorDimMax);
                int32_t height = mFdp.ConsumeIntegralInRange<int32_t>(kColorDimMin, kColorDimMax);
                uint32_t stride = mFdp.ConsumeIntegralInRange<uint32_t>(width, 2 * kColorDimMax);
                uint32_t srcSize = 4 * stride * height;
                uint32_t destSize = 4 * width * height;
                fixColorVectors(vecDataSrc, srcSize);
                fixColorVectors(vecDataDest, destSize);
                convertRGBAToARGB(vecDataSrc.data(), width, height, stride, vecDataDest.data());
                break;
            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ColorConvertFuzzer colorConvertFuzzer(data, size);
    colorConvertFuzzer.process();
    return 0;
}
