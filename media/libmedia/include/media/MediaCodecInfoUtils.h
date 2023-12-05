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
#include <cmath>
#include <vector>

#include <media/stagefright/foundation/AUtils.h>

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

    bool contains(Range<T> range) const {
        return (range.lower_ >= lower_) && (range.upper_ <= upper_);
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
        if (lower_ > range.lower() && range.upper() > upper_) {
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

    /**
     * Returns the smallest range that includes this range and
     * another range.
     *
     * E.g. if a < b < c < d, the
     * extension of [a, c] and [b, d] ranges is [a, d].
     * As the endpoints are object references, there is no guarantee
     * which specific endpoint reference is used from the input ranges:
     *
     * E.g. if a == a' < b < c, the
     * extension of [a, b] and [a', c] ranges could be either
     * [a, c] or ['a, c], where ['a, c] could be either the exact
     * input range, or a newly created range with the same endpoints.
     *
     * @param range a non-null Range<T> reference
     * @return the extension of this range and the other range.
     */
    Range<T> extend(Range<T> range) {

        if (lower_ >= range.lower_ && upper_ <= range.upper_) {
            // other includes this
            return range;
        } else if (lower_ <= range.lower_ && upper_ >= range.upper_) {
            // this inludes other
            return *this;
        } else {
            return Range<T>(std::min(lower_, range.lower_), std::max(upper_, range.upper_));
        }
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

/**
 * Immutable class for describing width and height dimensions in pixels.
 */
struct VideoSize {
    /**
     * Create a new immutable VideoSize instance.
     *
     * @param width The width of the size, in pixels
     * @param height The height of the size, in pixels
     */
    VideoSize(int width, int height) : mWidth(width), mHeight(height) {}

    // default constructor
    VideoSize() : mWidth(0), mHeight(0) {}

    /**
     * Get the width of the size (in pixels).
     * @return width
     */
    int getWidth() const { return mWidth; }

    /**
     * Get the height of the size (in pixels).
     * @return height
     */
    int getHeight() const { return mHeight; }

    /**
     * Check if this size is equal to another size.
     *
     * Two sizes are equal if and only if both their widths and heights are
     * equal.
     *
     * A size object is never equal to any other type of object.
     *
     * @return true if the objects were equal, false otherwise
     */
    bool equals(VideoSize other) const {
        return mWidth == other.mWidth && mHeight == other.mHeight;
    }

    std::string toString() const {
        return std::to_string(mWidth) + "x" + std::to_string(mHeight);
    }

    /**
     * Parses the specified string as a size value.
     *
     * The ASCII characters {@code \}{@code u002a} ('*') and
     * {@code \}{@code u0078} ('x') are recognized as separators between
     * the width and height.
     *
     * For any {@code VideoSize s}: {@code VideoSize::ParseSize(s.toString()).equals(s)}.
     * However, the method also handles sizes expressed in the
     * following forms:
     *
     * "<i>width</i>{@code x}<i>height</i>" or
     * "<i>width</i>{@code *}<i>height</i>" {@code => new VideoSize(width, height)},
     * where <i>width</i> and <i>height</i> are string integers potentially
     * containing a sign, such as "-10", "+7" or "5".
     *
     * <pre>{@code
     * VideoSize::ParseSize("3*+6").equals(new VideoSize(3, 6)) == true
     * VideoSize::ParseSize("-3x-6").equals(new VideoSize(-3, -6)) == true
     * VideoSize::ParseSize("4 by 3") => throws NumberFormatException
     * }</pre>
     *
     * @param string the string representation of a size value.
     * @return the size value represented by {@code string}.
     */
    static std::optional<VideoSize> ParseSize(std::string str) {
        if (str.empty()) {
            return std::nullopt;
        }

        int sep_ix = str.find_first_of('*');
        if (sep_ix < 0) {
            sep_ix = str.find_first_of('x');
        }
        if (sep_ix < 0) {
            return std::nullopt;
        }

        // strtol() returns 0 if unable to parse a number
        int w = strtol(str.substr(0, sep_ix).c_str(), NULL, 10);
        int h = strtol(str.substr(sep_ix + 1).c_str(), NULL, 10);
        if ((w == 0 && (str.substr(0, sep_ix) != "0"))
                || (h == 0 && (str.substr(sep_ix + 1) != "0"))) {
            ALOGW("could not parse size %s", str.c_str());
            return std::nullopt;
        }

        return std::make_optional(VideoSize(w, h));
    }

    int hashCode() const {
        // assuming most sizes are <2^16, doing a rotate will give us perfect hashing
        return mHeight ^ ((mWidth << (sizeof(int) / 2)) | (mWidth >> (sizeof(int) / 2)));
    }

    bool empty() const {
        return mWidth <= 0 || mHeight <= 0;
    }

private:
    int mWidth;
    int mHeight;
};

struct VideoSizeCompare {
    bool operator() (const VideoSize& lhs, const VideoSize& rhs) const {
        if (lhs.getWidth() == rhs.getWidth()) {
            return lhs.getHeight() < rhs.getHeight();
        } else {
            return lhs.getWidth() < rhs.getWidth();
        }
    }
};

struct Rational {
    /**
     * Calculates the greatest common divisor using Euclid's algorithm.
     *
     * <p><em>Visible for testing only.</em></p>
     *
     * @param numerator the numerator in a fraction
     * @param denominator the denominator in a fraction
     *
     * @return An int value representing the GCD. Always positive.
     */
    static int GCD(int numerator, int denominator) {
        /*
         * Non-recursive implementation of Euclid's algorithm:
         *
         *  GCD(a, 0) := a
         *  GCD(a, b) := GCD(b, a mod b)
         *
         */
        int a = numerator;
        int b = denominator;

        while (b != 0) {
            int oldB = b;

            b = a % b;
            a = oldB;
        }

        return std::abs(a);
    }

    /**
     * <p>Create a {@code Rational} with a given numerator and denominator.</p>
     *
     * <p>The signs of the numerator and the denominator may be flipped such that the denominator
     * is always positive. Both the numerator and denominator will be converted to their reduced
     * forms (see {@link #equals} for more details).</p>
     *
     * <p>For example,
     * <ul>
     * <li>a rational of {@code 2/4} will be reduced to {@code 1/2}.
     * <li>a rational of {@code 1/-1} will be flipped to {@code -1/1}
     * <li>a rational of {@code 5/0} will be reduced to {@code 1/0}
     * <li>a rational of {@code 0/5} will be reduced to {@code 0/1}
     * </ul>
     * </p>
     *
     * @param numerator the numerator of the rational
     * @param denominator the denominator of the rational
     *
     * @see #equals
     */
    Rational(int numerator, int denominator) {
        if (denominator < 0) {
            numerator = -numerator;
            denominator = -denominator;
        }

        // Convert to reduced form
        if (denominator == 0 && numerator > 0) {
            mNumerator = 1; // +Inf
            mDenominator = 0;
        } else if (denominator == 0 && numerator < 0) {
            mNumerator = -1; // -Inf
            mDenominator = 0;
        } else if (denominator == 0 && numerator == 0) {
            mNumerator = 0; // NaN
            mDenominator = 0;
        } else if (numerator == 0) {
            mNumerator = 0;
            mDenominator = 1;
        } else {
            int gcd = GCD(numerator, denominator);

            mNumerator = numerator / gcd;
            mDenominator = denominator / gcd;
        }
    }

    // default constructor;
    Rational() {
        Rational(0, 0);
    }

    /**
     * Gets the numerator of the rational.
     *
     * <p>The numerator will always return {@code 1} if this rational represents
     * infinity (that is, the denominator is {@code 0}).</p>
     */
    int getNumerator() {
        return mNumerator;
    }

    /**
     * Gets the denominator of the rational
     *
     * <p>The denominator may return {@code 0}, in which case the rational may represent
     * positive infinity (if the numerator was positive), negative infinity (if the numerator
     * was negative), or {@code NaN} (if the numerator was {@code 0}).</p>
     *
     * <p>The denominator will always return {@code 1} if the numerator is {@code 0}.
     */
    int getDenominator() {
        return mDenominator;
    }

    /**
     * Indicates whether this rational is a <em>Not-a-Number (NaN)</em> value.
     *
     * <p>A {@code NaN} value occurs when both the numerator and the denominator are {@code 0}.</p>
     *
     * @return {@code true} if this rational is a <em>Not-a-Number (NaN)</em> value;
     *         {@code false} if this is a (potentially infinite) number value
     */
    bool isNaN() const {
        return mDenominator == 0 && mNumerator == 0;
    }

    /**
     * Indicates whether this rational represents an infinite value.
     *
     * <p>An infinite value occurs when the denominator is {@code 0} (but the numerator is not).</p>
     *
     * @return {@code true} if this rational is a (positive or negative) infinite value;
     *         {@code false} if this is a finite number value (or {@code NaN})
     */
    bool isInfinite() {
        return mNumerator != 0 && mDenominator == 0;
    }

    /**
     * Indicates whether this rational represents a finite value.
     *
     * <p>A finite value occurs when the denominator is not {@code 0}; in other words
     * the rational is neither infinity or {@code NaN}.</p>
     *
     * @return {@code true} if this rational is a (positive or negative) infinite value;
     *         {@code false} if this is a finite number value (or {@code NaN})
     */
    bool isFinite() {
        return mDenominator != 0;
    }

    /**
     * Indicates whether this rational represents a zero value.
     *
     * <p>A zero value is a {@link #isFinite finite} rational with a numerator of {@code 0}.</p>
     *
     * @return {@code true} if this rational is finite zero value;
     *         {@code false} otherwise
     */
    bool isZero() {
        return isFinite() && mNumerator == 0;
    }

    /**
     * Return a string representation of this rational, e.g. {@code "1/2"}.
     *
     * <p>The following rules of conversion apply:
     * <ul>
     * <li>{@code NaN} values will return {@code "NaN"}
     * <li>Positive infinity values will return {@code "Infinity"}
     * <li>Negative infinity values will return {@code "-Infinity"}
     * <li>All other values will return {@code "numerator/denominator"} where {@code numerator}
     * and {@code denominator} are substituted with the appropriate numerator and denominator
     * values.
     * </ul></p>
     */
    std::string toString() {
        if (isNaN()) {
            return "NaN";
        } else if (isPosInf()) {
            return "Infinity";
        } else if (isNegInf()) {
            return "-Infinity";
        } else {
            return std::to_string(mNumerator) + "/" + std::to_string(mDenominator);
        }
    }

    int hashCode() {
        // Bias the hash code for the first (2^16) values for both numerator and denominator
        // ToDo: In Java, it uses a unsigned right shift >>> which C++ does not have.
        //       int numeratorFlipped = mNumerator << 16 | mNumerator >>> 16;
        int numeratorFlipped = mNumerator << 16 | mNumerator >> 16;

        return mDenominator ^ numeratorFlipped;
    }

    /**
     * Returns the value of the specified number as a {@code double}.
     *
     * <p>The {@code double} is calculated by converting both the numerator and denominator
     * to a {@code double}; then returning the result of dividing the numerator by the
     * denominator.</p>
     *
     * @return the divided value of the numerator and denominator as a {@code double}.
     */
    double doubleValue() {
        double num = mNumerator;
        double den = mDenominator;

        return num / den;
    }

    /**
     * Returns the value of the specified number as a {@code float}.
     *
     * <p>The {@code float} is calculated by converting both the numerator and denominator
     * to a {@code float}; then returning the result of dividing the numerator by the
     * denominator.</p>
     *
     * @return the divided value of the numerator and denominator as a {@code float}.
     */
    float floatValue() {
        float num = mNumerator;
        float den = mDenominator;

        return num / den;
    }

    /**
     * Returns the value of the specified number as a {@code int}.
     *
     * <p>{@link #isInfinite Finite} rationals are converted to an {@code int} value
     * by dividing the numerator by the denominator; conversion for non-finite values happens
     * identically to casting a floating point value to an {@code int}, in particular:
     *
     * @return the divided value of the numerator and denominator as a {@code int}.
     */
    int intValue() {
        // Mimic float to int conversion rules from JLS 5.1.3

        if (isPosInf()) {
            return INT_MAX;
        } else if (isNegInf()) {
            return INT_MIN;
        } else if (isNaN()) {
            return 0;
        } else { // finite
            return mNumerator / mDenominator;
        }
    }

    /**
     * Returns the value of the specified number as a {@code long}.
     *
     * <p>{@link #isInfinite Finite} rationals are converted to an {@code long} value
     * by dividing the numerator by the denominator; conversion for non-finite values happens
     * identically to casting a floating point value to a {@code long}, in particular:
     *
     * @return the divided value of the numerator and denominator as a {@code long}.
     */
    long longValue() {
        // Mimic float to long conversion rules from JLS 5.1.3

        if (isPosInf()) {
            return LONG_MAX;
        } else if (isNegInf()) {
            return LONG_MIN;
        } else if (isNaN()) {
            return 0;
        } else { // finite
            return mNumerator / mDenominator;
        }
    }

    /**
     * Returns the value of the specified number as a {@code short}.
     *
     * <p>{@link #isInfinite Finite} rationals are converted to a {@code short} value
     * identically to {@link #intValue}; the {@code int} result is then truncated to a
     * {@code short} before returning the value.</p>
     *
     * @return the divided value of the numerator and denominator as a {@code short}.
     */
    short shortValue() {
        return (short) intValue();
    }

    /**
     * Compare this rational to the specified rational to determine their natural order.
     *
     * <p>{@link #NaN} is considered to be equal to itself and greater than all other
     * {@code Rational} values. Otherwise, if the objects are not {@link #equals equal}, then
     * the following rules apply:</p>
     *
     * <ul>
     * <li>Positive infinity is greater than any other finite number (or negative infinity)
     * <li>Negative infinity is less than any other finite number (or positive infinity)
     * <li>The finite number represented by this rational is checked numerically
     * against the other finite number by converting both rationals to a common denominator multiple
     * and comparing their numerators.
     * </ul>
     *
     * @param another the rational to be compared
     *
     * @return a negative integer, zero, or a positive integer as this object is less than,
     *         equal to, or greater than the specified rational.
     */
    // bool operator> (const Rational& another) {
    int compareTo(Rational another) const {
        if (equals(another)) {
            return 0;
        } else if (isNaN()) { // NaN is greater than the other non-NaN value
            return 1;
        } else if (another.isNaN()) { // the other NaN is greater than this non-NaN value
            return -1;
        } else if (isPosInf() || another.isNegInf()) {
            return 1; // positive infinity is greater than any non-NaN/non-posInf value
        } else if (isNegInf() || another.isPosInf()) {
            return -1; // negative infinity is less than any non-NaN/non-negInf value
        }

        // else both this and another are finite numbers

        // make the denominators the same, then compare numerators
        long thisNumerator = ((long)mNumerator) * another.mDenominator; // long to avoid overflow
        long otherNumerator = ((long)another.mNumerator) * mDenominator; // long to avoid overflow

        // avoid underflow from subtraction by doing comparisons
        if (thisNumerator < otherNumerator) {
            return -1;
        } else if (thisNumerator > otherNumerator) {
            return 1;
        } else {
            // This should be covered by #equals, but have this code path just in case
            return 0;
        }
    }

    bool operator > (const Rational& another) const {
        return compareTo(another) > 0;
    }

    bool operator >= (const Rational& another) const {
        return compareTo(another) >= 0;
    }

    bool operator < (const Rational& another) const {
        return compareTo(another) < 0;
    }

    bool operator <= (const Rational& another) const {
        return compareTo(another) <= 0;
    }

    bool operator == (const Rational& another) const {
        return equals(another);
    }

private:
    int mNumerator;
    int mDenominator;

    bool isPosInf() const {
        return mDenominator == 0 && mNumerator > 0;
    }

    bool isNegInf() const {
        return mDenominator == 0 && mNumerator < 0;
    }

    bool equals(Rational other) const {
        return (mNumerator == other.mNumerator && mDenominator == other.mDenominator);
    }
};

static const Rational NaN = Rational(0, 0);
static const Rational POSITIVE_INFINITY = Rational(1, 0);
static const Rational NEGATIVE_INFINITY = Rational(-1, 0);
static const Rational ZERO = Rational(0, 1);

/**
 * Parses the specified string as a rational value.
 * <p>The ASCII characters {@code \}{@code u003a} (':') and
 * {@code \}{@code u002f} ('/') are recognized as separators between
 * the numerator and denominator.</p>
 * <p>
 * For any {@code Rational r}: {@code Rational::parseRational(r.toString()).equals(r)}.
 * However, the method also handles rational numbers expressed in the
 * following forms:</p>
 * <p>
 * "<i>num</i>{@code /}<i>den</i>" or
 * "<i>num</i>{@code :}<i>den</i>" {@code => new Rational(num, den);},
 * where <i>num</i> and <i>den</i> are string integers potentially
 * containing a sign, such as "-10", "+7" or "5".</p>
 *
 * Rational::ParseRational("3:+6").equals(new Rational(1, 2)) == true
 * Rational::ParseRational("-3/-6").equals(new Rational(1, 2)) == true
 * Rational::ParseRational("4.56") => return std::nullopt
 *
 * @param str the string representation of a rational value.
 * @return the rational value wrapped by std::optional represented by str.
 */
static inline std::optional<Rational> ParseRational(std::string str) {
    if (str.compare("NaN") == 0) {
        return std::make_optional(NaN);
    } else if (str.compare("Infinity") == 0) {
        return std::make_optional(POSITIVE_INFINITY);
    } else if (str.compare("-Infinity") == 0) {
        return std::make_optional(NEGATIVE_INFINITY);
    }

    int sep_ix = str.find_first_of(':');
    if (sep_ix < 0) {
        sep_ix = str.find_first_of('/');
    }
    if (sep_ix < 0) {
        return std::nullopt;
    }

    int numerator = strtol(str.substr(0, sep_ix).c_str(), NULL, 10);
    int denominator = strtol(str.substr(sep_ix + 1).c_str(), NULL, 10);
    if ((numerator == 0 && str.substr(0, sep_ix) != "0")
            || (denominator == 0 && str.substr(sep_ix + 1) != "0")) {
        ALOGW("could not parse string: %s to Rational", str.c_str());
        return std::nullopt;
    }
    return std::make_optional(Rational(numerator, denominator));
}

/**
 * Returns the equivalent factored range newrange, where for every
 * e : newrange.contains(e) implies that range.contains(e * factor),
 * and !newrange.contains(e) implies that !range.contains(e * factor).
 */
static inline Range<int> FactorRange(Range<int> range, int factor) {
    if (factor == 1) {
        return range;
    }
    return Range(divUp(range.lower(), factor), range.upper() / factor);
}

/**
 * Returns the equivalent factored range newrange, where for every
 * e : newrange.contains(e) implies that range.contains(e * factor),
 * and !newrange.contains(e) implies that !range.contains(e * factor).
 */
static inline Range<long> FactorRange(Range<long> range, long factor) {
    if (factor == 1) {
        return range;
    }
    return Range(divUp(range.lower(), factor), range.upper() / factor);
}

static inline Rational ScaleRatio(Rational ratio, int num, int den) {
    int common = Rational::GCD(num, den);
    num /= common;
    den /= common;
    return Rational(
            (int)(ratio.getNumerator() * (double)num),     // saturate to int
            (int)(ratio.getDenominator() * (double)den));  // saturate to int
}

static inline Range<Rational> ScaleRange(Range<Rational> range, int num, int den) {
    if (num == den) {
        return range;
    }
    return Range(
            ScaleRatio(range.lower(), num, den),
            ScaleRatio(range.upper(), num, den));
}

static inline Range<int> IntRangeFor(double v) {
    return Range((int)v, (int)ceil(v));
}

static inline Range<long> LongRangeFor(double v) {
    return Range((long)v, (long)ceil(v));
}

static inline Range<int> AlignRange(Range<int> range, int align) {
    return range.intersect(
            divUp(range.lower(), align) * align,
            (range.upper() / align) * align);
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

static inline std::optional<Range<long>> ParseLongRange(const std::string str) {
    if (str.empty()) {
        ALOGW("could not parse long range: %s", str.c_str());
        return std::nullopt;
    }
    long lower, upper;
    int ix = str.find_first_of('-');
    if (ix >= 0) {
        lower = strtol(str.substr(0, ix).c_str(), NULL, 10);
        upper = strtol(str.substr(ix + 1).c_str(), NULL, 10);
        // differentiate between unable to parse a number and the parsed number is 0
        if ((lower == 0 && str.substr(0, ix) != "0") || (upper == 0 && str.substr(ix + 1) != "0")) {
            ALOGW("could not parse long range: %s", str.c_str());
            return std::nullopt;
        }
    } else {
        long value = strtol(str.c_str(), NULL, 10);
        if (value == 0 && str != "0") {
            ALOGW("could not parse long range: %s", str.c_str());
            return std::nullopt;
        }
        lower = upper = value;
    }
    return std::make_optional<Range<long>>(lower, upper);
}

static inline std::optional<Range<Rational>> ParseRationalRange(const std::string str) {
    int ix = str.find_first_of('-');
    if (ix >= 0) {
        std::optional<Rational> lower = ParseRational(str.substr(0, ix));
        std::optional<Rational> upper = ParseRational(str.substr(ix + 1));
        if (!lower || !upper) {
            return std::nullopt;
        }
        return std::make_optional<Range<Rational>>(lower.value(), upper.value());
    } else {
        std::optional<Rational> value = ParseRational(str);
        if (!value) {
            return std::nullopt;
        }
        return std::make_optional<Range<Rational>>(value.value(), value.value());
    }
}

static inline std::optional<std::pair<VideoSize, VideoSize>> ParseSizeRange(const std::string str) {
    int ix = str.find_first_of('-');
    if (ix >= 0) {
        std::optional<VideoSize> lowerOpt = VideoSize::ParseSize(str.substr(0, ix));
        std::optional<VideoSize> upperOpt = VideoSize::ParseSize(str.substr(ix + 1));
        if (!lowerOpt || !upperOpt) {
            return std::nullopt;
        }
        return std::make_optional(
                std::pair<VideoSize, VideoSize>(lowerOpt.value(), upperOpt.value()));
    } else {
        std::optional<VideoSize> opt = VideoSize::ParseSize(str);
        if (!opt) {
            return std::nullopt;
        }
        return std::make_optional(std::pair<VideoSize, VideoSize>(opt.value(), opt.value()));
    }
}

static inline long divUpLong(long num, long den) {
    return (num + den - 1) / den;
}

}

#endif  // MEDIA_CODEC_INFO_UTILS_H_