/*
 * Copyright 2020, The Android Open Source Project
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

#ifndef CODEC2_HIDL_PLUGIN_FILTER_PLUGIN_IMPL_H

#define CODEC2_HIDL_PLUGIN_FILTER_PLUGIN_IMPL_H

#include <map>
#include <memory>

#include <C2Component.h>

#include <utils/Errors.h>

namespace android {

class FilterWrapper {
public:
    class Plugin {
    public:
        Plugin() = default;
        virtual ~Plugin() = default;
        virtual status_t status() const = 0;
        virtual std::shared_ptr<C2ComponentStore> getStore() = 0;
        C2_DO_NOT_COPY(Plugin);
    };

    struct Component {
        const std::shared_ptr<C2Component> comp;
        const std::shared_ptr<C2ComponentInterface> intf;
        const C2Component::Traits traits;
        const std::vector<uint32_t> filterParams;
    };

    FilterWrapper(
            std::unique_ptr<Plugin> &&plugin,
            const std::initializer_list<uint32_t> &filterParams);
    ~FilterWrapper();

    std::shared_ptr<C2ComponentInterface> maybeWrapInterface(
            const std::shared_ptr<C2ComponentInterface> intf);

    std::shared_ptr<C2Component> maybeWrapComponent(
            const std::shared_ptr<C2Component> comp);

private:
    status_t mInit;
    std::unique_ptr<Plugin> mPlugin;
    std::shared_ptr<C2ComponentStore> mStore;
    std::list<FilterWrapper::Component> mComponents;

    std::vector<FilterWrapper::Component> createFilters();

    C2_DO_NOT_COPY(FilterWrapper);
};

}  // namespace android

#endif  // CODEC2_HIDL_PLUGIN_FILTER_PLUGIN_IMPL_H
