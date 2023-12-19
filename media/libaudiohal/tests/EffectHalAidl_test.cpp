/*
 * Copyright 2023 The Android Open Source Project
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

#include <cstddef>
#define LOG_TAG "EffectHalAidlTest"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <EffectHalAidl.h>
#include <aidl/android/hardware/audio/effect/BnEffect.h>
#include <aidl/android/hardware/audio/effect/BnFactory.h>
#include <mediautils/TimeCheck.h>
#include <system/audio_effects/effect_uuid.h>
#include <utils/Log.h>

#include <unistd.h>
#include <memory>
// #include <string>
// #include <unordered_map>

/**
 * Test the effect conversion.
 */
namespace {

using ::aidl::android::hardware::audio::effect::BnEffect;
using ::aidl::android::hardware::audio::effect::BnFactory;
using ::aidl::android::hardware::audio::effect::CommandId;
using ::aidl::android::hardware::audio::effect::Descriptor;
using ::aidl::android::hardware::audio::effect::IEffect;
using ::aidl::android::hardware::audio::effect::Parameter;
using ::aidl::android::hardware::audio::effect::Processing;
using ::aidl::android::hardware::audio::effect::State;
using ::aidl::android::media::audio::common::AudioUuid;
using android::OK;
using android::effect::EffectHalAidl;
using testing::Eq;
using testing::Return;

class MockFactory : public BnFactory {
  public:
    MOCK_METHOD(ndk::ScopedAStatus, queryEffects,
                (const std::optional<AudioUuid>& in_type_uuid,
                 const std::optional<AudioUuid>& in_impl_uuid,
                 const std::optional<AudioUuid>& in_proxy_uuid,
                 std::vector<Descriptor>* _aidl_return),
                (override));

    MOCK_METHOD(ndk::ScopedAStatus, queryProcessing,
                (const std::optional<Processing::Type>& in_type,
                 std::vector<Processing>* _aidl_return),
                (override));

    MOCK_METHOD(ndk::ScopedAStatus, createEffect,
                (const AudioUuid& in_impl_uuid, std::shared_ptr<IEffect>* _aidl_return),
                (override));

    MOCK_METHOD(ndk::ScopedAStatus, destroyEffect, (const std::shared_ptr<IEffect>& in_handle),
                (override));

  private:
};

// template <typename TAG>
class MockEffect : public BnEffect {
  public:
    MOCK_METHOD(ndk::ScopedAStatus, open,
                (const Parameter::Common& common,
                 const std::optional<Parameter::Specific>& specific,
                 IEffect::OpenEffectReturn* ret),
                (override));
    MOCK_METHOD(ndk::ScopedAStatus, close, (), (override));
    MOCK_METHOD(binder_status_t, dump, (int fd, const char** args, uint32_t numArgs), (override));
    MOCK_METHOD(ndk::ScopedAStatus, command, (CommandId id), (override));
    MOCK_METHOD(ndk::ScopedAStatus, getState, (State * state), (override));
    MOCK_METHOD(ndk::ScopedAStatus, setParameter, (const Parameter& param), (override));
    MOCK_METHOD(ndk::ScopedAStatus, getParameter, (const Parameter::Id& id, Parameter* param),
                (override));
    // ndk::ScopedAStatus getParameter(const Parameter::Id&, Parameter*) override {
    //     ALOGE("XXXXXX");
    //     return ndk::ScopedAStatus::ok();
    // }

    MOCK_METHOD(ndk::ScopedAStatus, getDescriptor, (Descriptor * desc), (override));

  private:
};

class EffectHalAidlTest : public testing::Test {
  public:
    void SetUp() override {
        mMockFactory = ndk::SharedRefBase::make<MockFactory>();
        mMockEffect = ndk::SharedRefBase::make<MockEffect>();

        // mEffectHal = android::sp<EffectHalAidl>::make(nullptr, nullptr, sSessionId, sIoId,
        //                                               mMockDesc, false);
        ASSERT_NE(nullptr, mMockFactory);
        ASSERT_NE(nullptr, mMockEffect);
        // ASSERT_NE(nullptr, mEffectHal);
    }
    void TearDown() override {
        EXPECT_CALL(*mMockFactory, destroyEffect(Eq(std::ref(mMockEffect))))
                .Times(1)
                // .WillOnce(Return(EX_NONE));
                .WillOnce(Return(ndk::ScopedAStatus::ok()));
        mEffectHal.clear();
    }

    static constexpr int sSessionId = 11;
    static constexpr int sIoId = 22;
    const Descriptor sDescriptor = {
            .common.id.type =
                    ::aidl::android::hardware::audio::effect::getEffectTypeUuidSpatializer()};

    std::shared_ptr<MockFactory> mMockFactory;
    std::shared_ptr<MockEffect> mMockEffect;
    android::sp<EffectHalAidl> mEffectHal;
    Descriptor mMockDesc = {};
};

TEST_F(EffectHalAidlTest, createSpatializerAidlWithParameterDefined) {
    EXPECT_CALL(*mMockEffect, getParameter).Times(1).WillOnce(Return(ndk::ScopedAStatus::ok()));
    mEffectHal = android::sp<EffectHalAidl>::make(mMockFactory, mMockEffect, sSessionId, sIoId,
                                                  sDescriptor, false);
    EXPECT_NE(nullptr, mEffectHal);
    EXPECT_TRUE(mEffectHal->isEffectDefined());
}

TEST_F(EffectHalAidlTest, createSpatializerAidlWithoutParameterDefined) {
    EXPECT_CALL(*mMockEffect, getParameter)
            .Times(1)
            .WillOnce(Return(ndk::ScopedAStatus::fromStatus(STATUS_BAD_VALUE)));
    mEffectHal = android::sp<EffectHalAidl>::make(mMockFactory, mMockEffect, sSessionId, sIoId,
                                                  sDescriptor, false);
    EXPECT_NE(nullptr, mEffectHal);
    EXPECT_FALSE(mEffectHal->isEffectDefined());
}

TEST_F(EffectHalAidlTest, setAndVerifySpatializerAidlParamWithParameterDefined) {
    EXPECT_CALL(*mMockEffect, getParameter)
            .Times(1)
            .WillOnce(Return(ndk::ScopedAStatus::fromStatus(STATUS_BAD_VALUE)));
    mEffectHal = android::sp<EffectHalAidl>::make(mMockFactory, mMockEffect, sSessionId, sIoId,
                                                  sDescriptor, false);
    EXPECT_NE(nullptr, mEffectHal);
}

TEST_F(EffectHalAidlTest, setAndVerifySpatializerAidlParamWithoutParameterDefined) {
    EXPECT_CALL(*mMockEffect, getParameter)
            .Times(1)
            .WillOnce(Return(ndk::ScopedAStatus::fromStatus(STATUS_BAD_VALUE)));
    mEffectHal = android::sp<EffectHalAidl>::make(mMockFactory, mMockEffect, sSessionId, sIoId,
                                                  sDescriptor, false);
    EXPECT_NE(nullptr, mEffectHal);
}

TEST_F(EffectHalAidlTest, closeWithError) {
    EXPECT_CALL(*mMockEffect, getParameter).Times(1).WillOnce(Return(ndk::ScopedAStatus::ok()));
    mEffectHal = android::sp<EffectHalAidl>::make(mMockFactory, mMockEffect, sSessionId, sIoId,
                                                  sDescriptor, false);
    EXPECT_NE(nullptr, mEffectHal);
    EXPECT_CALL(*mMockEffect, close)
            .Times(1)
            .WillOnce(Return(ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_TRANSACTION_FAILED,
                                                                              "test")));
    EXPECT_EQ(android::FAILED_TRANSACTION, mEffectHal->close());
}

TEST_F(EffectHalAidlTest, closeSuccess) {
    EXPECT_CALL(*mMockEffect, getParameter).Times(1).WillOnce(Return(ndk::ScopedAStatus::ok()));
    mEffectHal = android::sp<EffectHalAidl>::make(mMockFactory, mMockEffect, sSessionId, sIoId,
                                                  sDescriptor, false);
    EXPECT_NE(nullptr, mEffectHal);
    EXPECT_CALL(*mMockEffect, close).Times(1).WillOnce(Return(ndk::ScopedAStatus::ok()));
    EXPECT_EQ(OK, mEffectHal->close());
}

TEST_F(EffectHalAidlTest, getParamSupportedLevels) {
    EXPECT_CALL(*mMockEffect, getParameter).Times(1).WillOnce(Return(ndk::ScopedAStatus::ok()));
    mEffectHal = android::sp<EffectHalAidl>::make(mMockFactory, mMockEffect, sSessionId, sIoId,
                                                  sDescriptor, false);
    EXPECT_NE(nullptr, mEffectHal);
    EXPECT_CALL(*mMockEffect, close).Times(1).WillOnce(Return(ndk::ScopedAStatus::ok()));
    EXPECT_EQ(OK, mEffectHal->close());
}

// TEST_F(EffectHalAidlTest, closeSuccess) {
//     //effect_descriptor_t desc;
//     // ON_CALL(*mMockEffect, getDescriptor).WillByDefault([&](effect_descriptor_t* desc) {
//     //     sleep(10);
//     //     *desc = {};
//     //     return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER, "test");
//     // });
//     ON_CALL(*mMockEffect, close).WillByDefault([]() {
//         sleep(10);
//         return ndk::ScopedAStatus::ok();
//         // return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER, "test");
//     });

//     EXPECT_EQ(OK, mEffectHal->close());
// }

// TEST_F(EffectHalAidlTest, closeWithError) {
//     ON_CALL(*mMockEffect, close).WillByDefault([]() {
//         sleep(10);
//         return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER, "test");
//     });

//     EXPECT_EQ(EX_NULL_POINTER, mEffectHal->close());
// }

}  // namespace