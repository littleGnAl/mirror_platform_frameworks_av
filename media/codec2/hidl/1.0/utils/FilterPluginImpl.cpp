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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2-FilterWrapper"
#include <android-base/logging.h>

#include <dlfcn.h>

#include <C2Config.h>
#include <C2Debug.h>
#include <C2ParamInternal.h>

#include <codec2/hidl/1.0/ComponentStore.h>
#include <codec2/hidl/1.0/FilterPlugin.h>

#include "FilterPluginImpl.h"

namespace android {
namespace hardware {
namespace media {
namespace c2 {
namespace V1_0 {
namespace utils {

using namespace ::android;

namespace {

class WrappedDecoderInterface : public C2ComponentInterface {
public:
    WrappedDecoderInterface(
            std::shared_ptr<C2ComponentInterface> intf,
            std::vector<FilterWrapper::Component> &&filters)
        : mIntf(intf), mFilters(std::move(filters)) {
        for (size_t i = 0; i < mFilters.size(); ++i) {
            const std::shared_ptr<C2ComponentInterface> &filter = mFilters[i].intf;
            std::vector<std::shared_ptr<C2ParamDescriptor>> params;
            if (C2_OK != filter->querySupportedParams_nb(&params)) {
                LOG(WARNING) << "WrappedDecoderInterface: " << filter->getName()
                        << "failed querySupportedParams_nb.";
                continue;
            }
            for (uint32_t type : mFilters[i].filterParams) {
                mTypeToIndex[type] = i;
            }
        }
    }

    ~WrappedDecoderInterface() override = default;

    C2String getName() const override { return mIntf->getName(); }

    c2_node_id_t getId() const override { return mIntf->getId(); }

    c2_status_t query_vb(
            const std::vector<C2Param *> &stackParams,
            const std::vector<C2Param::Index> &heapParamIndices,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2Param>>* const heapParams) const override {
        std::list<C2Param *> stackParamsList;
        std::copy_n(stackParams.begin(), stackParams.size(), stackParamsList.begin());
        heapParams->clear();
        std::fill_n(heapParams->begin(), heapParamIndices.size(), nullptr);
        c2_status_t result = C2_OK;
        for (size_t i = 0; i < mFilters.size(); ++i) {
            std::vector<C2Param *> stackParamsForFilter;
            for (auto it = stackParamsList.begin(); it != stackParamsList.end(); ) {
                C2Param *param = *it;
                uint32_t type = param->type().type();
                auto it2 = mTypeToIndex.find(type);
                if (it2 == mTypeToIndex.end() || it2->second != i) {
                    ++it;
                    continue;
                }
                stackParamsForFilter.push_back(param);
                it = stackParamsList.erase(it);
            }
            std::vector<C2Param::Index> heapParamIndicesForFilter;
            for (size_t j = 0; j < heapParamIndices.size(); ++j) {
                uint32_t type = heapParamIndices[j].type();
                auto it = mTypeToIndex.find(type);
                if (it == mTypeToIndex.end() || it->second != i) {
                    continue;
                }
                heapParamIndicesForFilter.push_back(heapParamIndices[j]);
            }
            std::vector<std::unique_ptr<C2Param>> heapParamsForFilter;
            const std::shared_ptr<C2ComponentInterface> &filter = mFilters[i].intf;
            c2_status_t err = filter->query_vb(
                    stackParamsForFilter, heapParamIndicesForFilter, mayBlock,
                    &heapParamsForFilter);
            if (err != C2_OK) {
                LOG(WARNING) << "WrappedDecoderInterface: " << filter->getName()
                        << " returned error for query_vb; err=" << err;
                result = err;
                continue;
            }
            for (size_t j = 0, k = 0;
                 j < heapParamIndices.size() && k < heapParamsForFilter.size();
                 ++j) {
                uint32_t type = heapParamIndices[j].type();
                auto it = mTypeToIndex.find(type);
                if (it == mTypeToIndex.end() || it->second != i) {
                    continue;
                }
                (*heapParams)[j] = std::move(heapParamsForFilter[k++]);
            }
        }

        std::vector<C2Param *> stackParamsForIntf;
        std::copy_n(stackParamsList.begin(), stackParamsList.size(), stackParamsForIntf.begin());

        std::vector<C2Param::Index> heapParamIndicesForIntf;
        for (size_t j = 0; j < heapParamIndices.size(); ++j) {
            uint32_t type = heapParamIndices[j].type();
            if (mTypeToIndex.find(type) != mTypeToIndex.end()) {
                continue;
            }
            heapParamIndicesForIntf.push_back(heapParamIndices[j]);
        }

        std::vector<std::unique_ptr<C2Param>> heapParamsForIntf;
        c2_status_t err = mIntf->query_vb(
                stackParamsForIntf, heapParamIndicesForIntf, mayBlock, &heapParamsForIntf);
        if (err != C2_OK) {
            LOG(WARNING) << "WrappedDecoderInterface: " << mIntf->getName()
                    << " returned error for query_vb; err=" << err;
            result = err;
        }

        for (size_t j = 0, k = 0;
             j < heapParamIndices.size() && k < heapParamsForIntf.size();
             ++j) {
            uint32_t type = heapParamIndices[j].type();
            if (mTypeToIndex.find(type) != mTypeToIndex.end()) {
                continue;
            }
            (*heapParams)[j] = std::move(heapParamsForIntf[k++]);
        }

        return result;
    }

    c2_status_t config_vb(
            const std::vector<C2Param*> &params,
            c2_blocking_t mayBlock,
            std::vector<std::unique_ptr<C2SettingResult>>* const failures) override {
        c2_status_t result = C2_OK;
        for (size_t i = 0; i < mFilters.size(); ++i) {
            const std::shared_ptr<C2ComponentInterface> &filter = mFilters[i].intf;
            std::vector<std::unique_ptr<C2SettingResult>> filterFailures;
            c2_status_t err = filter->config_vb(params, mayBlock, &filterFailures);
            if (err != C2_OK) {
                LOG(WARNING) << "WrappedDecoderInterface: " << filter->getName()
                        << " returned error for config_vb; err=" << err;
                result = err;
            }
        }
        c2_status_t err = mIntf->config_vb(params, mayBlock, failures);
        if (err != C2_OK) {
            LOG(WARNING) << "WrappedDecoderInterface: " << mIntf->getName()
                    << " returned error for config_vb; err=" << err;
            result = err;
        }

        return result;
    }

    c2_status_t createTunnel_sm(c2_node_id_t) override { return C2_OMITTED; }
    c2_status_t releaseTunnel_sm(c2_node_id_t) override { return C2_OMITTED; }

    c2_status_t querySupportedParams_nb(
            std::vector<std::shared_ptr<C2ParamDescriptor>> * const params) const override {
        c2_status_t result = mIntf->querySupportedParams_nb(params);
        if (result != C2_OK) {
            LOG(WARNING) << "WrappedDecoderInterface: " << mIntf->getName()
                    << " returned error for querySupportedParams_nb; err=" << result;
            return result;
        }
        for (const FilterWrapper::Component &filter : mFilters) {
            std::vector<std::shared_ptr<C2ParamDescriptor>> filterParams;
            c2_status_t err = filter.intf->querySupportedParams_nb(&filterParams);
            if (err != C2_OK) {
                LOG(WARNING) << "WrappedDecoderInterface: " << filter.intf->getName()
                        << " returned error for querySupportedParams_nb; err=" << result;
                result = err;
                continue;
            }
            for (const std::shared_ptr<C2ParamDescriptor> &paramDesc : filterParams) {
                if (std::count(
                        filter.filterParams.begin(),
                        filter.filterParams.end(),
                        paramDesc->index().type()) == 0) {
                    continue;
                }
                params->push_back(paramDesc);
            }
        }
        return result;
    }

    c2_status_t querySupportedValues_vb(
            std::vector<C2FieldSupportedValuesQuery> &fields,
            c2_blocking_t mayBlock) const override {
        c2_status_t result = mIntf->querySupportedValues_vb(fields, mayBlock);
        if (result != C2_OK && result != C2_BAD_INDEX) {
            LOG(WARNING) << "WrappedDecoderInterface: " << mIntf->getName()
                    << " returned error for querySupportedParams_nb; err=" << result;
            return result;
        }
        for (const FilterWrapper::Component &filter : mFilters) {
            std::vector<C2FieldSupportedValuesQuery> filterFields;
            std::vector<size_t> indices;
            for (size_t i = 0; i < fields.size(); ++i) {
                const C2FieldSupportedValuesQuery &field = fields[i];
                uint32_t type = C2Param::Index(_C2ParamInspector::GetIndex(field.field())).type();
                if (std::count(
                        filter.filterParams.begin(), filter.filterParams.end(), type) == 0) {
                    continue;
                }
                filterFields.push_back(field);
                indices.push_back(i);
            }
            c2_status_t err = filter.intf->querySupportedValues_vb(filterFields, mayBlock);
            if (err != C2_OK && err != C2_BAD_INDEX) {
                LOG(WARNING) << "WrappedDecoderInterface: " << filter.intf->getName()
                        << " returned error for querySupportedParams_nb; err=" << result;
                result = err;
                continue;
            }
            for (size_t i = 0; i < filterFields.size(); ++i) {
                fields[indices[i]] = filterFields[i];
            }
        }
        return result;
    }

private:
    std::shared_ptr<C2ComponentInterface> mIntf;
    std::vector<FilterWrapper::Component> mFilters;
    std::map<uint32_t, size_t> mTypeToIndex;
};

class WrappedDecoder : public C2Component, std::enable_shared_from_this<WrappedDecoder> {
public:
    WrappedDecoder(
            std::shared_ptr<C2Component> comp,
            std::vector<FilterWrapper::Component> &&filters)
        : mComp(comp), mFilters(std::move(filters)) {
        for (size_t i = 0; i < mFilters.size(); ++i) {
            const std::shared_ptr<C2ComponentInterface> &filter = mFilters[i].comp->intf();
            std::vector<std::shared_ptr<C2ParamDescriptor>> params;
            if (C2_OK != filter->querySupportedParams_nb(&params)) {
                LOG(WARNING) << "WrappedDecoder: " << filter->getName()
                        << "failed querySupportedParams_nb.";
                continue;
            }
            for (uint32_t type : mFilters[i].filterParams) {
                mTypeToIndex[type] = i;
            }
        }
        std::vector<FilterWrapper::Component> filtersDup(mFilters);
        mIntf = std::make_shared<WrappedDecoderInterface>(
                comp->intf(), std::move(filtersDup));
    }

    std::shared_ptr<C2ComponentInterface> intf() override { return mIntf; }

    c2_status_t setListener_vb(
            const std::shared_ptr<Listener> &listener, c2_blocking_t mayBlock) override {
        (void)mayBlock;
        if (listener) {
            mComp->setListener_vb(
                    std::make_shared<PassingListener>(
                            shared_from_this(),
                            listener,
                            mFilters.front().comp),
                    mayBlock);
            for (size_t i = 0; i < mFilters.size() - 1; ++i) {
                mFilters[i].comp->setListener_vb(
                        std::make_shared<PassingListener>(
                                shared_from_this(),
                                listener,
                                mFilters[i + 1].comp),
                        mayBlock);
            }
            mFilters.back().comp->setListener_vb(
                    std::make_shared<LastListener>(shared_from_this(), listener), mayBlock);
        } else {
            mComp->setListener_vb(nullptr, mayBlock);
        }
        mListener = listener;
        return C2_OK;
    }

    c2_status_t queue_nb(std::list<std::unique_ptr<C2Work>>* const items) override {
        return mComp->queue_nb(items);
    }

    c2_status_t announce_nb(const std::vector<C2WorkOutline> &) override {
        return C2_OMITTED;
    }

    c2_status_t flush_sm(
            flush_mode_t mode, std::list<std::unique_ptr<C2Work>>* const flushedWork) override {
        c2_status_t result = mComp->flush_sm(mode, flushedWork);
        std::list<std::unique_ptr<C2Work>> filterFlushedWork;
        for (FilterWrapper::Component filter : mFilters) {
            c2_status_t err = filter.comp->flush_sm(mode, &filterFlushedWork);
            if (err != C2_OK) {
                result = err;
            }
            flushedWork->splice(flushedWork->end(), filterFlushedWork);
        }
        return result;
    }

    c2_status_t drain_nb(drain_mode_t mode) override {
        switch (mode) {
        case DRAIN_COMPONENT_WITH_EOS: {
            std::unique_ptr<C2Work> eosWork{new C2Work};
            eosWork->input.flags = C2FrameData::FLAG_END_OF_STREAM;
            eosWork->worklets.push_back(std::make_unique<C2Worklet>());
            std::list<std::unique_ptr<C2Work>> items;
            items.push_back(std::move(eosWork));
            mComp->queue_nb(&items);
            return C2_OK;
        }
        case DRAIN_COMPONENT_NO_EOS:
        case DRAIN_CHAIN:
        default:
            return C2_BAD_VALUE;
        }
    }

    c2_status_t start() override {
        c2_status_t err = mComp->start();
        if (err != C2_OK) {
            return err;
        }
        for (FilterWrapper::Component filter : mFilters) {
            c2_status_t err = filter.comp->start();
            if (err != C2_OK) {
                // Previous components are already started successfully;
                // we ended up in an incoherent state.
                return C2_CORRUPTED;
            }
        }
        return C2_OK;
    }

    c2_status_t stop() override {
        c2_status_t err = mComp->stop();
        if (err != C2_OK) {
            return err;
        }
        for (FilterWrapper::Component filter : mFilters) {
            c2_status_t err = filter.comp->stop();
            if (err != C2_OK) {
                // Previous components are already stopped successfully;
                // we ended up in an incoherent state.
                return C2_CORRUPTED;
            }
        }
        return C2_OK;
    }

    c2_status_t reset() override {
        c2_status_t err = mComp->reset();
        if (err != C2_OK) {
            return err;
        }
        for (FilterWrapper::Component filter : mFilters) {
            c2_status_t err = filter.comp->reset();
            if (err != C2_OK) {
                // Previous components are already reset successfully;
                // we ended up in an incoherent state.
                return C2_CORRUPTED;
            }
        }
        return C2_OK;
    }

    c2_status_t release() override {
        c2_status_t result = mComp->release();
        if (result != C2_OK) {
            result = C2_CORRUPTED;
        }
        for (FilterWrapper::Component filter : mFilters) {
            c2_status_t err = filter.comp->release();
            if (err != C2_OK) {
                result = C2_CORRUPTED;
            }
        }
        return result;
    }

private:
    class PassingListener : public Listener {
    public:
        PassingListener(
                const std::shared_ptr<C2Component> &wrappedComponent,
                const std::shared_ptr<Listener> &wrappedComponentListener,
                const std::shared_ptr<C2Component> &nextComponent)
            : mWrappedComponent(wrappedComponent),
              mWrappedComponentListener(wrappedComponentListener),
              mNextComponent(nextComponent) {
        }

        void onWorkDone_nb(
                std::weak_ptr<C2Component>,
                std::list<std::unique_ptr<C2Work>> workItems) override {
            std::shared_ptr<C2Component> nextComponent = mNextComponent.lock();
            std::list<std::unique_ptr<C2Work>> failedWorkItems;
            if (!nextComponent) {
                failedWorkItems.splice(failedWorkItems.begin(), workItems);
            } else {
                for (auto it = workItems.begin(); it != workItems.end(); ) {
                    const std::unique_ptr<C2Work> &work = *it;
                    if (work->result != C2_OK || work->workletsProcessed != 1
                            || work->worklets.size() != 1) {
                        failedWorkItems.push_back(std::move(*it));
                        it = workItems.erase(it);
                        continue;
                    }
                    C2FrameData &output = work->worklets.front()->output;
                    work->input = std::move(output);
                    output.flags = C2FrameData::flags_t(0);
                    output.buffers.clear();
                    output.configUpdate.clear();
                    output.infoBuffers.clear();
                    ++it;
                }
            }
            if (!failedWorkItems.empty()) {
                for (const std::unique_ptr<C2Work> &work : failedWorkItems) {
                    work->result = C2_CORRUPTED;
                }
                if (std::shared_ptr<Listener> wrappedComponentListener =
                        mWrappedComponentListener.lock()) {
                    wrappedComponentListener->onWorkDone_nb(
                            mWrappedComponent, std::move(failedWorkItems));
                }
            }
            if (!workItems.empty() && nextComponent) {
                nextComponent->queue_nb(&workItems);
            }
        }

        void onTripped_nb(
                std::weak_ptr<C2Component>,
                std::vector<std::shared_ptr<C2SettingResult>>) override {
            // Trip not supported
        }

        void onError_nb(std::weak_ptr<C2Component>, uint32_t errorCode) {
            if (std::shared_ptr<Listener> wrappedComponentListener =
                    mWrappedComponentListener.lock()) {
                wrappedComponentListener->onError_nb(mWrappedComponent, errorCode);
            }
        }

    private:
        std::weak_ptr<C2Component> mWrappedComponent;
        std::weak_ptr<Listener> mWrappedComponentListener;
        std::weak_ptr<C2Component> mNextComponent;
    };

    class LastListener : public Listener {
    public:
        LastListener(
                const std::shared_ptr<C2Component> &wrappedComponent,
                const std::shared_ptr<Listener> &wrappedComponentListener)
            : mWrappedComponent(wrappedComponent),
              mWrappedComponentListener(wrappedComponentListener) {
        }

        void onWorkDone_nb(
                std::weak_ptr<C2Component>,
                std::list<std::unique_ptr<C2Work>> workItems) override {
            if (std::shared_ptr<Listener> wrappedComponentListener =
                    mWrappedComponentListener.lock()) {
                wrappedComponentListener->onWorkDone_nb(
                        mWrappedComponent, std::move(workItems));
            }
        }

        void onTripped_nb(
                std::weak_ptr<C2Component>,
                std::vector<std::shared_ptr<C2SettingResult>>) override {
            // Trip not supported
        }

        void onError_nb(std::weak_ptr<C2Component>, uint32_t errorCode) {
            if (std::shared_ptr<Listener> wrappedComponentListener =
                    mWrappedComponentListener.lock()) {
                wrappedComponentListener->onError_nb(mWrappedComponent, errorCode);
            }
        }

    private:
        std::weak_ptr<C2Component> mWrappedComponent;
        std::weak_ptr<Listener> mWrappedComponentListener;
    };

    std::shared_ptr<C2Component> mComp;
    std::shared_ptr<C2ComponentInterface> mIntf;
    std::vector<FilterWrapper::Component> mFilters;
    std::map<uint32_t, size_t> mTypeToIndex;
    std::shared_ptr<Listener> mListener;
};

}  // anonymous namespace

FilterWrapper::FilterWrapper(
        std::unique_ptr<Plugin> &&plugin,
        const std::initializer_list<uint32_t> &filterParams)
    : mInit(NO_INIT),
      mPlugin(std::move(plugin)) {
    if (filterParams.size() == 0) {
        mPlugin.reset();
        return;
    }
    if (mPlugin->status() != OK) {
        mPlugin.reset();
        return;
    }
    mStore = mPlugin->getStore();
    if (!mStore) {
        mPlugin.reset();
        return;
    }
    std::vector<std::shared_ptr<const C2Component::Traits>> traits =
        mStore->listComponents();
    std::map<uint32_t, std::set<std::shared_ptr<const C2Component::Traits>>> typeToTraits;
    for (size_t i = 0; i < traits.size(); ++i) {
        const std::shared_ptr<const C2Component::Traits> &trait = traits[i];
        if (trait->domain == C2Component::DOMAIN_OTHER
                || trait->domain == C2Component::DOMAIN_AUDIO
                || trait->kind != C2Component::KIND_OTHER) {
            continue;
        }
        std::shared_ptr<C2ComponentInterface> intf;
        if (C2_OK != mStore->createInterface(trait->name, &intf)) {
            continue;
        }
        std::vector<std::shared_ptr<C2ParamDescriptor>> params;
        if (C2_OK != intf->querySupportedParams_nb(&params)) {
            continue;
        }
        for (const std::shared_ptr<C2ParamDescriptor> &paramDesc : params) {
            uint32_t type = paramDesc->index().type();
            typeToTraits[type].insert(trait);
        }
    }
    // Find the shortest chain of components that cover the filter params in the given sequence.
    // O(N * M^2) where N = filterParams.size() and M = traits.size().
    struct TraitsLengthIndex {
        std::shared_ptr<const C2Component::Traits> traits;
        size_t length;
        size_t index;
    };
    std::vector<std::vector<TraitsLengthIndex>> table;
    // Initialize the table
    table.push_back({});
    uint32_t type = *filterParams.begin();
    for (const std::shared_ptr<const C2Component::Traits> &trait : typeToTraits[type]) {
        table[0].push_back({trait, 1 /* length */, 0 /* index (N/A) */});
    }
    // Populate the table
    for (size_t i = 1; i < filterParams.size(); ++i) {
        uint32_t type = *(filterParams.begin() + i);
        table.push_back({});
        for (const std::shared_ptr<const C2Component::Traits> &trait : typeToTraits[type]) {
            size_t minLength = filterParams.size();
            size_t minIndex = 0;
            for (size_t j = 0; j < table[i - 1].size(); ++j) {
                const TraitsLengthIndex &current = table[i - 1][j];
                size_t length = current.length + (current.traits == trait ? 0 : 1);
                if (minLength > length) {
                    minLength = length;
                    minIndex = j;
                }
            }
            table[i].push_back({trait, minLength, minIndex});
        }
    }
    if (!table[filterParams.size() - 1].empty()) {
        // Walk the table backward to reconstruct the traits list
        size_t minLength = table[filterParams.size() - 1][0].length;
        size_t index = 0;
        std::shared_ptr<const C2Component::Traits> currentTraits;
        std::list<uint32_t> currentFilterParams;
        for (size_t i = 1; i < table[filterParams.size() - 1].size(); ++i) {
            if (minLength > table[filterParams.size() - 1][i].length) {
                minLength = table[filterParams.size() - 1][i].length;
                index = i;
            }
        }
        currentTraits = table[filterParams.size() - 1][index].traits;
        currentFilterParams.push_front(*(filterParams.begin() + (filterParams.size() - 1)));
        for (size_t i = filterParams.size() - 1; i > 0; --i) {
            index = table[i][index].index;
            if (currentTraits != table[i - 1][index].traits) {
                mComponents.push_front({
                        nullptr, nullptr, *currentTraits,
                        std::vector(currentFilterParams.begin(), currentFilterParams.end())});
                currentTraits = table[i - 1][index].traits;
                currentFilterParams.clear();
            }
            currentFilterParams.push_front(*(filterParams.begin() + (i - 1)));
        }
    }
    if (mComponents.empty()) {
        LOG(WARNING) << "FilterWrapper: no filter component found";
        mPlugin.reset();
        return;
    }
    mInit = OK;
}

FilterWrapper::~FilterWrapper() {
}

std::vector<FilterWrapper::Component> FilterWrapper::createFilters() {
    std::vector<FilterWrapper::Component> filters;
    for (const FilterWrapper::Component &filter : mComponents) {
        std::shared_ptr<C2Component> comp;
        std::shared_ptr<C2ComponentInterface> intf;
        if (C2_OK != mStore->createComponent(filter.traits.name, &comp)) {
            return {};
        }
        if (C2_OK != mStore->createInterface(filter.traits.name, &intf)) {
            return {};
        }
        filters.push_back({comp, intf, filter.traits, filter.filterParams});
    }
    return filters;
}

std::shared_ptr<C2ComponentInterface> FilterWrapper::maybeWrapInterface(
        const std::shared_ptr<C2ComponentInterface> intf) {
    if (mInit != OK) {
        return intf;
    }
    return std::make_shared<WrappedDecoderInterface>(intf, createFilters());
}

std::shared_ptr<C2Component> FilterWrapper::maybeWrapComponent(
        const std::shared_ptr<C2Component> comp) {
    if (mInit != OK) {
        return comp;
    }
    return std::make_shared<WrappedDecoder>(comp, createFilters());
}

}  // namespace utils
}  // namespace V1_0
}  // namespace c2
}  // namespace media
}  // namespace hardware
}  // namespace android
