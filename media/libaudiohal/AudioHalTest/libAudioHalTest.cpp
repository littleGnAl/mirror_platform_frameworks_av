/*
 * Copyright 2021 The Android Open Source Project
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
#include <cstdint>
#define LOG_TAG "libAudioHalTest"

#include <gtest/gtest.h>
#include <utils/RefBase.h>

#include <media/audiohal/DeviceHalInterface.h>
#include <media/audiohal/DevicesFactoryHalInterface.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>

namespace android {

class libAudioHalTest : public ::testing::Test {
};

// DevicesFactoryHalInterface
TEST(libAudioHalTest, createDevicesFactoryHalInterface) {
    ASSERT_NE(nullptr, DevicesFactoryHalInterface::create());
}

// EffectsFactoryHalInterface
TEST(libAudioHalTest, createEffectsFactoryHalInterface) {
    ASSERT_NE(nullptr, EffectsFactoryHalInterface::create());
}

TEST(libAudioHalTest, queryNumberEffects) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    uint32_t numEffects = 0;
    EXPECT_EQ(OK, factory->queryNumberEffects(&numEffects));
    EXPECT_NE(0ul, numEffects);
}

TEST(libAudioHalTest, getDescriptorById) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    uint32_t numEffects = 0;
    EXPECT_EQ(OK, factory->queryNumberEffects(&numEffects));
    EXPECT_NE(0ul, numEffects);

    effect_descriptor_t desc;
    for (uint32_t i = 0; i < numEffects; i++) {
        EXPECT_EQ(OK, factory->getDescriptor(i, &desc));
    }
}

TEST(libAudioHalTest, createEffect) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    uint32_t numEffects = 0;
    EXPECT_EQ(OK, factory->queryNumberEffects(&numEffects));
    EXPECT_NE(0ul, numEffects);

    effect_descriptor_t desc;
    for (uint32_t i = 0; i < numEffects; i++) {
        sp<EffectHalInterface> interface;
        EXPECT_EQ(OK, factory->getDescriptor(i, &desc));
        EXPECT_EQ(OK, factory->createEffect(&desc.uuid, 1, 1, 1, &interface));
    }
}

TEST(libAudioHalTest, dumpEffects) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    // TODO
}

TEST(libAudioHalTest, getHalVersion) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    auto version = factory->getHalVersion();
    EXPECT_NE(0, version.getMajorVersion());
}

// TODO: Add multi-thread testing

} // namespace android
