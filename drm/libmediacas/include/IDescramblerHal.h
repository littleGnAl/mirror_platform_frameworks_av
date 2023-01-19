/*
 * Copyright 2023, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <aidl/android/hardware/cas/IDescrambler.h>
#include <android/hardware/cas/native/1.0/BnHwDescrambler.h>
#include <android/hardware/cas/native/1.0/BpHwDescrambler.h>
#include <android/hardware/cas/native/1.0/IDescrambler.h>
#include <android/hardware/cas/native/1.0/types.h>
#include <utils/RefBase.h>
#include "jni.h"

namespace android {

using IDescramblerAidl = ::aidl::android::hardware::cas::IDescrambler;
using IDescramblerHidl = hardware::cas::native::V1_0::IDescrambler;
using hardware::hidl_vec;
using namespace ::aidl::android::hardware::cas;  // Default types from AIDL.
using DestinationBufferHidl = hardware::cas::native::V1_0::DestinationBuffer;
using ScramblingControlHidl = hardware::cas::native::V1_0::ScramblingControl;
using SharedBufferHidl = hardware::cas::native::V1_0::SharedBuffer;
using SubSampleHidl = hardware::cas::native::V1_0::SubSample;

struct IDescramblerHal : public RefBase {
  public:
    IDescramblerHal();
    ~IDescramblerHal();
    bool init(sp<hardware::IBinder> hwBinder);
    hardware::Return<void> descramble(ScramblingControlHidl scramblingControl,
                                      const hidl_vec<SubSampleHidl>& subSamples,
                                      SharedBufferHidl& srcBuffer, int64_t srcOffset,
                                      DestinationBufferHidl& dstBuffer, int64_t dstOffset,
                                      IDescramblerHidl::descramble_cb callback);

  private:
    std::shared_ptr<IDescramblerAidl> mDescramblerAidl;
    sp<IDescramblerHidl> mDescramblerHidl;
};
}  // namespace android
