/*
 * Copyright 2018 The Android Open Source Project
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
#define LOG_TAG "Codec2-ComponentInterface"
#include <android-base/logging.h>

#include <codec2/hidl/1.0/Component.h>
#include <codec2/hidl/1.0/ComponentInterface.h>
#include <codec2/hidl/1.0/ComponentStore.h>

#include <hidl/HidlBinderSupport.h>
#include <utils/Timers.h>

#include <C2BqBufferPriv.h>
#include <C2Debug.h>
#include <C2PlatformSupport.h>

#include <chrono>
#include <thread>

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using namespace ::android;

namespace /* unnamed */ {

// Implementation of ConfigurableC2Intf based on C2ComponentInterface
struct CompIntf : public ConfigurableC2Intf {
    CompIntf(const std::shared_ptr<C2ComponentInterface>& intf,
        const std::shared_ptr<LargeBufferInterface>& largeBufferIntf):
        ConfigurableC2Intf{intf->getName(), intf->getId()},
        mIntf{intf}, mLargeBufferIntf{largeBufferIntf} {
    }

    virtual c2_status_t config(
            const std::vector<C2Param*>& params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures
            ) override {
        c2_status_t err = mIntf->config_vb(params, mayBlock, failures);
        if (err == C2_OK && mLargeBufferIntf) {
            err = mLargeBufferIntf->config(params, mayBlock, failures);
        }
        return err;
    }

    virtual c2_status_t query(
            const std::vector<C2Param::Index>& indices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const params
            ) const override {
        c2_status_t err = mIntf->query_vb({}, indices, mayBlock, params);
        if (err == C2_OK && mLargeBufferIntf) {
            mLargeBufferIntf->query({}, indices, mayBlock, params);
        }
        return err;

    }

    virtual c2_status_t querySupportedParams(
            std::vector<std::shared_ptr<C2ParamDescriptor>>* const params
            ) const override {
        c2_status_t err = mIntf->querySupportedParams_nb(params);
        if (err == C2_OK && mLargeBufferIntf != nullptr) {
            err =  mLargeBufferIntf->querySupportedParams(params);
        }
        return err;
    }

    virtual c2_status_t querySupportedValues(
            std::vector<C2FieldSupportedValuesQuery>& fields,
            c2_blocking_t mayBlock) const override {
        c2_status_t err = mIntf->querySupportedValues_vb(fields, mayBlock);
        if (err == C2_OK && mLargeBufferIntf != nullptr) {
            err = mLargeBufferIntf->querySupportedValues(fields, mayBlock);
        }
        return err;
    }

protected:
    std::shared_ptr<C2ComponentInterface> mIntf;
    std::shared_ptr<LargeBufferInterface> mLargeBufferIntf;
};

} // unnamed namespace

static C2R LargeFrameParamsSetter(
        bool mayBlock, C2InterfaceHelper::C2P<C2LargeFrame::output> &me) {
    (void)mayBlock;
    C2R res = C2R::Ok();
    if (!me.F(me.v.maxSize).supportsAtAll(me.v.maxSize)) {
        res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.maxSize)));
    } else if (!me.F(me.v.thresholdSize).supportsAtAll(me.v.thresholdSize)) {
        res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.thresholdSize)));
    } else if (me.v.maxSize < me.v.thresholdSize) {
        res = res.plus(C2SettingResultBuilder::BadValue(me.F(me.v.maxSize)));
    }
    std::vector<std::unique_ptr<C2SettingResult>> failures;
    res.retrieveFailures(&failures);
    if (failures.size() > 0) {
        me.set().maxSize = 0;
        me.set().thresholdSize = 0;
    }
    LOG(ERROR) << "LargeFrameInterface setter called.";
    return res;
}

LargeBufferInterface::LargeBufferInterface(
            const std::shared_ptr<C2ReflectorHelper> &helper)
        : C2InterfaceHelper(helper) {

        setDerivedInstance(this);

        addParameter(
                DefineParam(mLargeFrameParams, C2_PARAMKEY_OUTPUT_LARGE_FRAME)
                .withDefault(new C2LargeFrame::output(0u, 0, 0))
                .withFields({
                    C2F(mLargeFrameParams, maxSize).inRange(
                            0, 120 * 512000 * 8 * 2),
                    C2F(mLargeFrameParams, thresholdSize).inRange(
                            0, 120 * 512000 * 8 * 2)
                })
                .withSetter(LargeFrameParamsSetter)
                .build());
}

std::shared_ptr<C2LargeFrame::output> LargeBufferInterface::get() const {
    return mLargeFrameParams;
}

// ComponentInterface
ComponentInterface::ComponentInterface(
        const std::shared_ptr<C2ComponentInterface>& intf,
        const std::shared_ptr<ParameterCache>& cache):ComponentInterface(intf, nullptr, cache) {
}

ComponentInterface::ComponentInterface(
        const std::shared_ptr<C2ComponentInterface>& intf,
        const std::shared_ptr<LargeBufferInterface>& largeBufferIntf,
        const std::shared_ptr<ParameterCache>& cache)
      : mInterface{intf},
        mConfigurable{new CachedConfigurable(std::make_unique<CompIntf>(intf, largeBufferIntf))} {
    mInit = mConfigurable->init(cache);
}

c2_status_t ComponentInterface::status() const {
    return mInit;
}

Return<sp<IConfigurable>> ComponentInterface::getConfigurable() {
    return mConfigurable;
}

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android

