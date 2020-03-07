/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <any>
#include <map>
#include <sstream>
#include <string>

#include <media/MediaMetricsItem.h>

namespace android::mediametrics {

/**
 * The TransactionLog is used to record mediametrics::Items to present
 * different views on the time information (selected by audio, and sorted by key).
 *
 * The TransactionLog will always present data in timestamp order. (Perhaps we
 * just make this submit order).
 *
 * These Views have a cost in shared pointer storage, so they aren't quite free.
 *
 * The TransactionLog is NOT thread safe.
 */
class TransactionLog final { // made final as we have copy constructor instead of dup() override.
public:
    // In long term run, the garbage collector aims to keep the
    // Transaction Log between the Low Water Mark and the High Water Mark.

    // low water mark
    static inline constexpr size_t kLogItemsLowWater = 5000;
    // high water mark
    static inline constexpr size_t kLogItemsHighWater = 10000;

    // Estimated max data usage is 1KB * kLogItemsHighWater.

    TransactionLog() = default;

    TransactionLog(size_t lowWaterMark, size_t highWaterMark)
        : mLowWaterMark(lowWaterMark)
        , mHighWaterMark(highWaterMark) {
        LOG_ALWAYS_FATAL_IF(highWaterMark <= lowWaterMark,
              "%s: required that highWaterMark:%zu > lowWaterMark:%zu",
                  __func__, highWaterMark, lowWaterMark);
    }

    // The TransactionLog copy constructor/assignment is effectively an
    // instantaneous, isochronous snapshot of the other TransactionLog.
    //
    // The contents of the Transaction Log are shared pointers to immutable instances -
    // std::shared_ptr<const mediametrics::Item>, so we use a shallow copy,
    // which is more efficient in space and execution time than a deep copy,
    // and gives the same results.

    TransactionLog(const TransactionLog &other) {
        *this = other;
    }

    TransactionLog& operator=(const TransactionLog &other) {
        std::lock_guard lock(mLock);
        mLog.clear();
        mItemMap.clear();

        std::lock_guard lock2(other.mLock);
        mLog = other.mLog;
        mItemMap = other.mItemMap;

        return *this;
    }

    /**
     * Put an item in the TransactionLog.
     */
    status_t put(const std::shared_ptr<const mediametrics::Item>& item) {
        const std::string& key = item->getKey();
        const int64_t time = item->getTimestamp();

        std::vector<std::any> garbage;  // objects destroyed after lock.
        std::lock_guard lock(mLock);

        (void)gc_l(garbage);
        mLog.emplace(time, item);
        mItemMap[key].emplace(time, item);
        return NO_ERROR;  // no errors for now.
    }

    /**
     * Returns all records within [startTime, endTime]
     */
    std::vector<std::shared_ptr<const mediametrics::Item>> get(
            int64_t startTime = 0, int64_t endTime = INT64_MAX) const {
        std::lock_guard lock(mLock);
        return getItemsInRange_l(mLog, startTime, endTime);
    }

    /**
     * Returns all records for a key within [startTime, endTime]
     */
    std::vector<std::shared_ptr<const mediametrics::Item>> get(
            const std::string& key,
            int64_t startTime = 0, int64_t endTime = INT64_MAX) const {
        std::lock_guard lock(mLock);
        auto mapIt = mItemMap.find(key);
        if (mapIt == mItemMap.end()) return {};
        return getItemsInRange_l(mapIt->second, startTime, endTime);
    }

    /**
     * Returns a pair consisting of the Transaction Log as a string
     * and the number of lines in the string.
     *
     * The number of lines in the returned pair is used as an optimization
     * for subsequent line limiting.
     *
     * \param lines the maximum number of lines in the string returned.
     */
    std::pair<std::string, int32_t> dump(int32_t lines) const {
        std::stringstream ss;
        int32_t ll = lines;
        std::lock_guard lock(mLock);

        // All audio items in time order.
        if (ll > 0) {
            ss << "Consolidated:\n";
            --ll;
        }
        for (const auto &log : mLog) {
            if (ll <= 0) break;
            ss << "  " << log.second->toString() << "\n";
            --ll;
        }

        // Grouped by item key (category)
        if (ll > 0) {
            ss << "Categorized:\n";
            --ll;
        }
        for (const auto &itemMap : mItemMap) {
            if (ll <= 0) break;
            ss << " " << itemMap.first << "\n";
            --ll;
            for (const auto &item : itemMap.second) {
                if (ll <= 0) break;
                ss << "  " << item.second->toString() << "\n";
                --ll;
            }
        }
        return { ss.str(), lines - ll };
    }

    /**
     *  Returns number of Items in the TransactionLog.
     */
    size_t size() const {
        std::lock_guard lock(mLock);
        return mLog.size();
    }

    /**
     * Clears all Items from the TransactionLog.
     */
    // TODO: Garbage Collector, sweep and expire old values
    void clear() {
        std::lock_guard lock(mLock);
        mLog.clear();
        mItemMap.clear();
    }

private:
    using MapTimeItem =
            std::multimap<int64_t /* time */, std::shared_ptr<const mediametrics::Item>>;

    // GUARDED_BY mLock
    /**
     * Garbage collects if the TimeMachine size exceeds the high water mark.
     *
     * \param garbage a type-erased vector of elements to be destroyed
     *        outside of lock.  Move large items to be destroyed here.
     *
     * \return true if garbage collection was done.
     */
    bool gc_l(std::vector<std::any>& garbage) {
        if (mLog.size() < mHighWaterMark) return false;

        ALOGD("%s: garbage collection", __func__);

        auto eraseEnd = mLog.begin();
        size_t toRemove = mLog.size() - mLowWaterMark;
        // remove at least those elements.

        // use a stale vector with precise type to avoid type erasure overhead in garbage
        std::vector<std::shared_ptr<const mediametrics::Item>> stale;

        for (size_t i = 0; i < toRemove; ++i) {
            stale.emplace_back(std::move(eraseEnd->second));
            ++eraseEnd; // amortized O(1)
        }
        // ensure that eraseEnd is an lower bound on timeToErase.
        const int64_t timeToErase = eraseEnd->first;
        while (eraseEnd != mLog.end()) {
            auto it = eraseEnd;
            --it;  // amortized O(1)
            if (it->first != timeToErase) {
                break;  // eraseEnd represents a unique time jump.
            }
            stale.emplace_back(std::move(eraseEnd->second));
            ++eraseEnd;
        }

        mLog.erase(mLog.begin(), eraseEnd);  // O(ptr_diff)

        size_t itemMapCount = 0;
        for (auto it = mItemMap.begin(); it != mItemMap.end();) {
            auto &keyHist = it->second;
            auto it2 = keyHist.lower_bound(timeToErase);
            if (it2 == keyHist.end()) {
                garbage.emplace_back(std::move(keyHist)); // directly move keyhist to garbage
                it = mItemMap.erase(it);
            } else {
                for (auto it3 = keyHist.begin(); it3 != it2; ++it3) {
                    stale.emplace_back(std::move(it3->second));
                }
                keyHist.erase(keyHist.begin(), it2);
                itemMapCount += keyHist.size();
                 ++it;
            }
        }

        garbage.emplace_back(std::move(stale));

        ALOGD("%s(%zu, %zu): log size:%zu item map size:%zu, item map items:%zu",
                __func__, mLowWaterMark, mHighWaterMark,
                mLog.size(), mItemMap.size(), itemMapCount);
        return true;
    }

    static std::vector<std::shared_ptr<const mediametrics::Item>> getItemsInRange_l(
            const MapTimeItem& map,
            int64_t startTime = 0, int64_t endTime = INT64_MAX) {
        auto it = map.lower_bound(startTime);
        if (it == map.end()) return {};

        auto it2 = map.upper_bound(endTime);

        std::vector<std::shared_ptr<const mediametrics::Item>> ret;
        while (it != it2) {
            ret.push_back(it->second);
            ++it;
        }
        return ret;
    }

    const size_t mLowWaterMark = kLogItemsLowWater;
    const size_t mHighWaterMark = kLogItemsHighWater;

    mutable std::mutex mLock;

    // GUARDED_BY mLock
    MapTimeItem mLog;

    // GUARDED_BY mLock
    std::map<std::string /* item_key */, MapTimeItem> mItemMap;
};

} // namespace android::mediametrics
