/*
 * Copyright (C) 2009 The Android Open Source Project
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

#ifndef MEDIA_CODEC_INFO_UTILS_H_

#define MEDIA_CODEC_INFO_UTILS_H_

#include <algorithm>
#include <vector>

namespace android {

/**
 * Immutable class for describing the range of two numeric values.
 *
 * To make it immutable, all data are private and all functions are const.
 *
 * From frameworks/base/core/java/android/util/Range.java
 */
template<typename T>
struct Range {
    Range() : lower_(), upper_() {}

    Range(T l, T u) : lower_(l), upper_(u) {}

    constexpr bool empty() const { return lower_ >= upper_; }

    T lower() const { return lower_; }

    T upper() const { return upper_; }

    // Check if a value is in the range.
    bool contains(T value) const {
        return lower_ <= value && upper_ > value;
    }

    // Clamp a value in the range
    T clamp(T value) const{
        if (value < lower_) {
            return lower_;
        } else if (value > upper_) {
            return upper_;
        } else {
            return value;
        }
    }

    // Return the intersected range
    Range<T> intersect(Range<T> range) const {
        if (range.lower() < lower_ && range.upper() > upper_) {
            // range includes this
            return *this;
        } else if (range.lower() > lower_ && range.upper() < upper_) {
            // this includes range
            return range;
        } else {
            // if ranges are disjoint returns an empty Range(lower > upper)
            Range<T> result
                    = Range<T>(std::max(lower_, range.lower_), std::min(upper_, range.upper_));
            if (result.empty()) {
                ALOGE("Failed to intersect 2 ranges as they are disjoint");
            }
            return result;
        }
    }

    /**
     * Returns the intersection of this range and the inclusive range
     * specified by {@code [lower, upper]}.
     * <p>
     * See {@link #intersect(Range)} for more details.</p>
     *
     * @param lower a non-{@code null} {@code T} reference
     * @param upper a non-{@code null} {@code T} reference
     * @return the intersection of this range and the other range
     *
     * @throws NullPointerException if {@code lower} or {@code upper} was {@code null}
     * @throws IllegalArgumentException if the ranges are disjoint.
     */
    Range<T> intersect(T lower, T upper) {
        return Range(std::max(lower_, lower), std::min(upper_, upper));
    }

private:
    T lower_;
    T upper_;
};

/**
 * Sorts distinct (non-intersecting) range array in ascending order.
 * From frameworks/base/media/java/android/media/Utils.java
 */
template<typename T>
static inline void sortDistinctRanges(std::vector<Range<T>> &ranges) {
    std::sort(ranges.begin(), ranges.end(),
            [](Range<T> r1, Range<T> r2) {
        if (r1.upper() < r2.lower()) {
            return -1;
        } else if (r1.lower() > r2.upper()) {
            return 1;
        } else {
            ALOGE("sample rate ranges must be distinct.");
            return 0;
        }
    });
}

/**
 * Returns the intersection of two sets of non-intersecting ranges
 * From frameworks/base/media/java/android/media/Utils.java
 * @param one a sorted set of non-intersecting ranges in ascending order
 * @param another another sorted set of non-intersecting ranges in ascending order
 * @return the intersection of the two sets, sorted in ascending order
 */
template<typename T>
static inline std::vector<Range<T>> intersectSortedDistinctRanges(
        const std::vector<Range<T>> &one, const std::vector<Range<T>> &another) {
    std::vector<Range<T>> result(one.size() + another.size());
    int ix = 0;
    for (Range<T> range : another) {
        while (ix < one.size() && one[ix].upper() < range.lower()) {
            ++ix;
        }
        while (ix < one.size() && one[ix].upper() < range.upper()) {
            result.push_back(range.intersect(one[ix]));
            ++ix;
        }
        if (ix == one.size()) {
            break;
        }
        if (one[ix].lower() <= range.upper()) {
            result.push_back(range.intersect(one[ix]));
        }
    }
    return result;
}

// parse string into int range
static inline std::optional<Range<int>> ParseIntRange(const std::string &str) {
    if (str.empty()) {
        ALOGW("could not parse integer range: %s", str.c_str());
        return std::nullopt;
    }
    int lower, upper;
    size_t ix = str.find_first_of('-');
    if (ix >= 0) {
        lower = strtol(str.substr(0, ix).c_str(), NULL, 10);
        upper = strtol(str.substr(ix + 1).c_str(), NULL, 10);
        if ((lower == 0 && str.substr(0, ix) != "0")
                || (upper == 0 && str.substr(ix + 1) != "0")) {
            ALOGW("could not parse integer range: %s", str.c_str());
            return std::nullopt;
        }
    } else {
        int value = strtol(str.c_str(), NULL, 10);
        if (value == 0 && str != "0") {
            ALOGW("could not parse integer range: %s", str.c_str());
            return std::nullopt;
        }
        lower = upper = value;
    }
    return std::make_optional<Range<int>>(lower, upper);
}

}

#endif  // MEDIA_CODEC_INFO_UTILS_H_