/*
 * Copyright 2020 The Android Open Source Project
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

#include <binder/IBatteryStats.h>
#include <binder/IBinder.h>
#include <binder/IServiceManager.h>
#include <utils/String16.h>

#include "fuzzer/FuzzedDataProvider.h"
#include "mediautils/SchedulingPolicyService.h"

using android::IBatteryStats;
using android::IBinder;
using android::IServiceManager;
using android::sp;
using android::String16;

using android::defaultServiceManager;
using android::requestCpusetBoost;
using android::requestPriority;

sp<IBatteryStats> getBatteryService() {
    const sp<IServiceManager> sm(defaultServiceManager());
    const String16 name("batterystats");
    sp<IBinder> binder = sm->checkService(name);
    return interface_cast<IBatteryStats>(binder);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider data_provider(data, size);

    sp<IBatteryStats> mBatteryStatService;

    // There is some state here, but it's mostly focused around thread-safety, so
    // we won't worry about order.
    int32_t priority = data_provider.ConsumeIntegral<int32_t>();
    bool is_for_app = data_provider.ConsumeBool();
    bool async = data_provider.ConsumeBool();
    requestPriority(getpid(), gettid(), priority, is_for_app, async);

    bool enable = data_provider.ConsumeBool();

    // We are just using batterystats to avoid the need
    // to register a new service.
    requestCpusetBoost(enable, getBatteryService());
    return 0;
}