/*
 * Copyright 2022 The Android Open Source Project
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
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <utility>
#define LOG_TAG "EffectsFactoryHalInterfaceTest"

#include <aidl/android/media/audio/common/AudioUuid.h>
#include <media/AidlConversionCppNdk.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <system/audio_effects/audio_effects_utils.h>
#include <system/audio_effects/effect_aec.h>
#include <system/audio_effects/effect_agc2.h>
#include <system/audio_effects/effect_bassboost.h>
#include <system/audio_effects/effect_downmix.h>
#include <system/audio_effects/effect_dynamicsprocessing.h>
#include <system/audio_effect.h>

#include <gtest/gtest.h>
#include <utils/RefBase.h>

namespace android {

using effect::utils::EffectParamReader;
using effect::utils::EffectParamWriter;
using ::aidl::android::media::audio::common::AudioUuid;

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

TEST(libAudioHalTest, getDescriptorByNumber) {
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
        EXPECT_EQ(OK, factory->createEffect(&desc.uuid, 1 /* sessionId */, 1 /* ioId */,
                                            1 /* deviceId */, &interface));
    }
}

TEST(libAudioHalTest, getHalVersion) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    auto version = factory->getHalVersion();
    EXPECT_NE(0, version.getMajorVersion());
}

static constexpr size_t kMaxTestBufferLen = sizeof(effect_param_t) + 0xff;
uint8_t testDataBuffer[kMaxTestBufferLen] = {};
uint8_t testResponseBuffer[kMaxTestBufferLen] = {};

TEST(libAudioHalTest, agcNotInit) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    std::vector<effect_descriptor_t> descs;
    EXPECT_EQ(OK, factory->getDescriptors(&FX_IID_AEC_, &descs));
    for (const auto& desc : descs) {
        ASSERT_EQ(0, std::memcmp(&desc.type, &FX_IID_AEC_, sizeof(FX_IID_AEC_)));
        sp<EffectHalInterface> interface;
        EXPECT_EQ(OK, factory->createEffect(&desc.uuid, 1 /* sessionId */, 1 /* ioId */,
                                            1 /* deviceId */, &interface));
        EXPECT_NE(nullptr, interface);
        effect_param_t* param = (effect_param_t*)testDataBuffer;
        uint32_t type = AEC_PARAM_ECHO_DELAY, value = 0xbead;
        param->psize = sizeof(type);
        param->vsize = sizeof(value);
        EffectParamWriter writer(*param);
        EXPECT_EQ(OK, writer.writeToParameter(&type)) << writer.toString();
        EXPECT_EQ(OK, writer.writeToValue(&value)) << writer.toString();
        status_t reply = 0;
        uint32_t replySize = sizeof(reply);
        EXPECT_NE(OK, interface->command(EFFECT_CMD_SET_PARAM, (uint32_t)writer.getTotalSize(),
                                         param, &replySize, &reply));
        EXPECT_EQ(replySize, sizeof(reply));
        EXPECT_NE(OK, reply);
    }
}

// TODO: rethink about this test case to make it general for all types of effects
TEST(libAudioHalTest, aecInitSetAndGet) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    std::vector<effect_descriptor_t> descs;
    EXPECT_EQ(OK, factory->getDescriptors(&FX_IID_AEC_, &descs));
    static constexpr uint32_t delayValue = 0x20;
    for (const auto& desc : descs) {
        ASSERT_EQ(0, std::memcmp(&desc.type, &FX_IID_AEC_, sizeof(effect_uuid_t)));
        sp<EffectHalInterface> interface;
        EXPECT_EQ(OK, factory->createEffect(&desc.uuid, 1 /* sessionId */, 1 /* ioId */,
                                            1 /* deviceId */, &interface));
        EXPECT_NE(nullptr, interface);
        effect_param_t* param = (effect_param_t*)testDataBuffer;
        uint32_t type = AEC_PARAM_ECHO_DELAY, value = delayValue;
        param->psize = sizeof(type);
        param->vsize = sizeof(value);
        EffectParamWriter writer(*param);
        EXPECT_EQ(OK, writer.writeToParameter(&type)) << writer.toString();
        EXPECT_EQ(OK, writer.writeToValue(&value)) << writer.toString();
        status_t reply = 0;
        uint32_t replySize = sizeof(reply);
        EXPECT_EQ(OK, interface->command(EFFECT_CMD_INIT, 0, nullptr, &replySize, &reply));
        EXPECT_EQ(OK, interface->command(EFFECT_CMD_SET_PARAM, (uint32_t)writer.getTotalSize(),
                                         param, &replySize, &reply)) << writer.toString();
        EXPECT_EQ(replySize, sizeof(reply));
        EXPECT_EQ(OK, reply);

        effect_param_t* responseParam = (effect_param_t*)testResponseBuffer;
        param->psize = sizeof(type);
        param->vsize = sizeof(value);
        EffectParamWriter request(*param);
        EXPECT_EQ(OK, request.writeToParameter(&type)) << request.toString();
        replySize = request.getTotalSize();
        EXPECT_EQ(OK, interface->command(EFFECT_CMD_GET_PARAM, (uint32_t)writer.getTotalSize(),
                                         param, &replySize, responseParam));
        EffectParamReader response(*responseParam);
        EXPECT_EQ(replySize, response.getTotalSize()) << response.toString();
        EXPECT_EQ(OK, response.readFromValue(&value)) << response.toString();
        EXPECT_EQ(delayValue, value) << response.toString();
    }
}


class EffectParamCombination {
  public:
    template <typename P, typename V>
    void init(const P& p, const V& v, size_t len) {
        set = std::make_shared<EffectParamReader>(createEffectParam(setBuffer, p, v));
        expect = std::make_shared<EffectParamReader>(createEffectParam(expectBuffer, p, v));
        valueSize = len;
    }

    std::shared_ptr<EffectParamReader> set; /* setParameter */
    std::shared_ptr<EffectParamReader> expect; /* match with getParameter */
    size_t valueSize;   /* ValueSize expect to write in reply data buffer */

  private:
    static const size_t kMaxBufferLen = 0x20;
    uint8_t setBuffer[kMaxBufferLen];
    uint8_t expectBuffer[kMaxBufferLen];

    template <typename P, typename V>
    EffectParamReader createEffectParam(void* buf, const P& p, const V& v) {
        effect_param_t* paramRet = (effect_param_t*)buf;
        paramRet->psize = sizeof(P);
        paramRet->vsize = sizeof(V);
        EffectParamWriter writer(*paramRet);
        EXPECT_EQ(OK, writer.writeToParameter(&p));
        EXPECT_EQ(OK, writer.writeToValue(&v));
        writer.finishValueWrite();
        return writer;
    }
};

template <typename P, typename V>
std::shared_ptr<EffectParamCombination> createEffectParamCombination(const P& p, const V& v,
                                                                     size_t len) {
    auto comb = std::make_shared<EffectParamCombination>();
    comb->init(p, v, len);
    return comb;
}

enum ParamName { TUPLE_UUID, TUPLE_PARAM_COMBINATION };
using EffectParamTestTuple =
        std::tuple<const effect_uuid_t* /* type UUID */, std::shared_ptr<EffectParamCombination>>;

struct CMDWithOneParam {
    int32_t     status;     // Transaction status (unused for command, used for reply)
    uint32_t    psize;      // Parameter size
    uint32_t    vsize;      // Value size
    char        data[];     // Start of Parameter + Value data
};

std::vector<EffectParamTestTuple> testPairs = {
        std::make_tuple(FX_IID_AEC,
                        createEffectParamCombination(AEC_PARAM_ECHO_DELAY, 0xff, sizeof(int32_t))),
        std::make_tuple(FX_IID_AGC2, createEffectParamCombination(AGC2_PARAM_FIXED_DIGITAL_GAIN,
                                                                  0x20, sizeof(int32_t))),
        std::make_tuple(SL_IID_BASSBOOST, createEffectParamCombination(BASSBOOST_PARAM_STRENGTH,
                                                                       0x20, sizeof(int32_t))),
        std::make_tuple(EFFECT_UIID_DOWNMIX,
                        createEffectParamCombination(DOWNMIX_PARAM_TYPE, DOWNMIX_TYPE_FOLD,
                                                     sizeof(int32_t))),
        std::make_tuple(
                SL_IID_DYNAMICSPROCESSING,
                createEffectParamCombination(std::array<uint32_t, 2>({DP_PARAM_INPUT_GAIN, 0}), 30,
                                             sizeof(int32_t)))};

class libAudioHalEffectParamTest : public ::testing::TestWithParam<EffectParamTestTuple> {
  public:
    libAudioHalEffectParamTest()
        : mParamTuple(GetParam()),
          mFactory(EffectsFactoryHalInterface::create()),
          mTypeUuid(std::get<TUPLE_UUID>(mParamTuple)),
          mCombination(std::get<TUPLE_PARAM_COMBINATION>(mParamTuple)),
          mExpectedValue([&]() {
              std::vector<uint8_t> expectData;
              expectData.resize(mCombination->valueSize);
              mCombination->expect->readFromValue(expectData.data(), mCombination->valueSize);
              return expectData;
          }()),
          mDescs([&]() {
              std::vector<effect_descriptor_t> descs;
              if (mFactory && mTypeUuid && OK == mFactory->getDescriptors(mTypeUuid, &descs)) {
                  return descs;
              }
              return descs;
          }()) {}

    void SetUp() override {
        for (const auto& desc : mDescs) {
            sp<EffectHalInterface> interface = createEffectHal(desc);
            ASSERT_NE(nullptr, interface);
            mHalInterfaces.push_back(interface);

            uint32_t initReply = 0;
            uint32_t initReplySize = sizeof(initReply);
            ASSERT_EQ(OK,
                      interface->command(EFFECT_CMD_INIT, 0, nullptr, &initReplySize, &initReply));
        }
    }

    void TearDown() override {
        for (auto& interface : mHalInterfaces) {
            interface->close();
        }
    }

    sp<EffectHalInterface> createEffectHal(const effect_descriptor_t& desc) {
        sp<EffectHalInterface> interface = nullptr;
        if (0 == std::memcmp(&desc.type, mTypeUuid, sizeof(effect_uuid_t)) &&
            OK == mFactory->createEffect(&desc.uuid, 1 /* sessionId */, 1 /* ioId */,
                                         1 /* deviceId */, &interface)) {
            return interface;
        }
        return nullptr;
    }

    void setAndGetParameter(sp<EffectHalInterface> interface) {
        uint32_t replySize = sizeof(uint32_t);
        uint8_t reply[replySize];
        auto setReader = mCombination->set;
        ASSERT_EQ(OK, interface->command(EFFECT_CMD_SET_PARAM, (uint32_t)setReader->getTotalSize(),
                                         const_cast<effect_param_t*>(&setReader->getEffectParam()),
                                         &replySize, &reply))
                << setReader->toString();
        ASSERT_EQ(replySize, sizeof(uint32_t));

        effect_param_t* getParam = (effect_param_t*)testResponseBuffer;
        size_t maxReplySize = mCombination->valueSize + sizeof(effect_param_t) +
                              sizeof(setReader->getPaddedParameterSize());
        replySize = maxReplySize;
        EXPECT_EQ(OK, interface->command(EFFECT_CMD_GET_PARAM, (uint32_t)setReader->getTotalSize(),
                                         const_cast<effect_param_t*>(&setReader->getEffectParam()),
                                         &replySize, getParam));
        EffectParamReader getReader(*getParam);
        EXPECT_EQ(replySize, getReader.getTotalSize()) << getReader.toString();
        std::vector<uint8_t> response;
        response.resize(mCombination->valueSize);
        EXPECT_EQ(OK, getReader.readFromValue(response.data(), mCombination->valueSize))
                << getReader.toString();
        EXPECT_EQ(response, mExpectedValue);
    }

    const EffectParamTestTuple mParamTuple;
    const sp<EffectsFactoryHalInterface> mFactory;
    const effect_uuid_t* mTypeUuid;
    std::shared_ptr<EffectParamCombination> mCombination;
    const std::vector<uint8_t> mExpectedValue;
    const std::vector<effect_descriptor_t> mDescs;
    std::vector<sp<EffectHalInterface>> mHalInterfaces;
};

TEST_P(libAudioHalEffectParamTest, setAndGetParam) {
    for (auto& interface : mHalInterfaces) {
        EXPECT_NO_FATAL_FAILURE(setAndGetParameter(interface));
    }
}

INSTANTIATE_TEST_SUITE_P(
        libAudioHalEffectParamTest, libAudioHalEffectParamTest, ::testing::ValuesIn(testPairs),
        [](const testing::TestParamInfo<libAudioHalEffectParamTest::ParamType>& info) {
            AudioUuid uuid = VALUE_OR_FATAL(::aidl::android::legacy2aidl_audio_uuid_t_AudioUuid(
                    *std::get<TUPLE_UUID>(info.param)));
            std::string name = "UUID_" + uuid.toString();
            std::replace_if(
                    name.begin(), name.end(), [](const char c) { return !std::isalnum(c); }, '_');
            return name;
        });
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(libAudioHalEffectParamTest);

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

// TODO: b/263986405 Add multi-thread testing

} // namespace android
