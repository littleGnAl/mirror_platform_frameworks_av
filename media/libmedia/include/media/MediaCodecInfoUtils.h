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

    /**
     * Returns the smallest range that includes this range and
     * another {@code range}.
     *
     * E.g. if a {@code <} b {@code <} c {@code <} d, the
     * extension of [a, c] and [b, d] ranges is [a, d].
     * As the endpoints are object references, there is no guarantee
     * which specific endpoint reference is used from the input ranges:
     *
     * E.g. if a {@code ==} a' {@code <} b {@code <} c, the
     * extension of [a, b] and [a', c] ranges could be either
     * [a, c] or ['a, c], where ['a, c] could be either the exact
     * input range, or a newly created range with the same endpoints.
     *
     * @param range a non-{@code null} {@code Range<T>} reference
     * @return the extension of this range and the other range.
     *
     * @throws NullPointerException if {@code range} was {@code null}
     */
    public Range<T> extend(Range<T> range) {
        checkNotNull(range, "range must not be null");

        int cmpLower = range.mLower.compareTo(mLower);
        int cmpUpper = range.mUpper.compareTo(mUpper);

        if (cmpLower <= 0 && cmpUpper >= 0) {
            // other includes this
            return range;
        } else if (cmpLower >= 0 && cmpUpper <= 0) {
            // this inludes other
            return this;
        } else {
            return Range.create(
                    cmpLower >= 0 ? mLower : range.mLower,
                    cmpUpper <= 0 ? mUpper : range.mUpper);
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

/** Returns the equivalent factored range {@code newrange}, where for every
 * {@code e}: {@code newrange.contains(e)} implies that {@code range.contains(e * factor)},
 * and {@code !newrange.contains(e)} implies that {@code !range.contains(e * factor)}.
 */
static Range<Integer>factorRange(Range<Integer> range, int factor) {
    if (factor == 1) {
        return range;
    }
    return Range.create(divUp(range.getLower(), factor), range.getUpper() / factor);
}

/** Returns the equivalent factored range {@code newrange}, where for every
 * {@code e}: {@code newrange.contains(e)} implies that {@code range.contains(e * factor)},
 * and {@code !newrange.contains(e)} implies that {@code !range.contains(e * factor)}.
 */
static Range<Long>factorRange(Range<Long> range, long factor) {
    if (factor == 1) {
        return range;
    }
    return Range.create(divUp(range.getLower(), factor), range.getUpper() / factor);
}

static Range<Rational> scaleRange(Range<Rational> range, int num, int den) {
    if (num == den) {
        return range;
    }
    return Range.create(
            scaleRatio(range.getLower(), num, den),
            scaleRatio(range.getUpper(), num, den));
}

static Range<Integer> alignRange(Range<Integer> range, int align) {
    return range.intersect(
            divUp(range.getLower(), align) * align,
            (range.getUpper() / align) * align);
}

/**
 * Immutable class for describing width and height dimensions in pixels.
 */
public final class Size {
    /**
     * Create a new immutable Size instance.
     *
     * @param width The width of the size, in pixels
     * @param height The height of the size, in pixels
     */
    public Size(int width, int height) {
        mWidth = width;
        mHeight = height;
    }

    /**
     * Get the width of the size (in pixels).
     * @return width
     */
    public int getWidth() {
        return mWidth;
    }

    /**
     * Get the height of the size (in pixels).
     * @return height
     */
    public int getHeight() {
        return mHeight;
    }

    /**
     * Check if this size is equal to another size.
     * <p>
     * Two sizes are equal if and only if both their widths and heights are
     * equal.
     * </p>
     * <p>
     * A size object is never equal to any other type of object.
     * </p>
     *
     * @return {@code true} if the objects were equal, {@code false} otherwise
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == null) {
            return false;
        }
        if (this == obj) {
            return true;
        }
        if (obj instanceof Size) {
            Size other = (Size) obj;
            return mWidth == other.mWidth && mHeight == other.mHeight;
        }
        return false;
    }

    /**
     * Return the size represented as a string with the format {@code "WxH"}
     *
     * @return string representation of the size
     */
    @Override
    public String toString() {
        return mWidth + "x" + mHeight;
    }

    private static NumberFormatException invalidSize(String s) {
        throw new NumberFormatException("Invalid Size: \"" + s + "\"");
    }

    /**
     * Parses the specified string as a size value.
     * <p>
     * The ASCII characters {@code \}{@code u002a} ('*') and
     * {@code \}{@code u0078} ('x') are recognized as separators between
     * the width and height.</p>
     * <p>
     * For any {@code Size s}: {@code Size.parseSize(s.toString()).equals(s)}.
     * However, the method also handles sizes expressed in the
     * following forms:</p>
     * <p>
     * "<i>width</i>{@code x}<i>height</i>" or
     * "<i>width</i>{@code *}<i>height</i>" {@code => new Size(width, height)},
     * where <i>width</i> and <i>height</i> are string integers potentially
     * containing a sign, such as "-10", "+7" or "5".</p>
     *
     * <pre>{@code
     * Size.parseSize("3*+6").equals(new Size(3, 6)) == true
     * Size.parseSize("-3x-6").equals(new Size(-3, -6)) == true
     * Size.parseSize("4 by 3") => throws NumberFormatException
     * }</pre>
     *
     * @param string the string representation of a size value.
     * @return the size value represented by {@code string}.
     *
     * @throws NumberFormatException if {@code string} cannot be parsed
     * as a size value.
     * @throws NullPointerException if {@code string} was {@code null}
     */
    public static Size parseSize(String string)
            throws NumberFormatException {
        checkNotNull(string, "string must not be null");

        int sep_ix = string.indexOf('*');
        if (sep_ix < 0) {
            sep_ix = string.indexOf('x');
        }
        if (sep_ix < 0) {
            throw invalidSize(string);
        }
        try {
            return new Size(Integer.parseInt(string.substring(0, sep_ix)),
                    Integer.parseInt(string.substring(sep_ix + 1)));
        } catch (NumberFormatException e) {
            throw invalidSize(string);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        // assuming most sizes are <2^16, doing a rotate will give us perfect hashing
        return mHeight ^ ((mWidth << (Integer.SIZE / 2)) | (mWidth >>> (Integer.SIZE / 2)));
    }

    private final int mWidth;
    private final int mHeight;
}

/**
 * <p>An immutable data type representation a rational number.</p>
 *
 * <p>Contains a pair of {@code int}s representing the numerator and denominator of a
 * Rational number. </p>
 */
public final class Rational extends Number implements Comparable<Rational> {
    /**
     * Constant for the <em>Not-a-Number (NaN)</em> value of the {@code Rational} type.
     *
     * <p>A {@code NaN} value is considered to be equal to itself (that is {@code NaN.equals(NaN)}
     * will return {@code true}; it is always greater than any non-{@code NaN} value (that is
     * {@code NaN.compareTo(notNaN)} will return a number greater than {@code 0}).</p>
     *
     * <p>Equivalent to constructing a new rational with both the numerator and denominator
     * equal to {@code 0}.</p>
     */
    public static final Rational NaN = new Rational(0, 0);

    /**
     * Constant for the positive infinity value of the {@code Rational} type.
     *
     * <p>Equivalent to constructing a new rational with a positive numerator and a denominator
     * equal to {@code 0}.</p>
     */
    public static final Rational POSITIVE_INFINITY = new Rational(1, 0);

    /**
     * Constant for the negative infinity value of the {@code Rational} type.
     *
     * <p>Equivalent to constructing a new rational with a negative numerator and a denominator
     * equal to {@code 0}.</p>
     */
    public static final Rational NEGATIVE_INFINITY = new Rational(-1, 0);

    /**
     * Constant for the zero value of the {@code Rational} type.
     *
     * <p>Equivalent to constructing a new rational with a numerator equal to {@code 0} and
     * any non-zero denominator.</p>
     */
    public static final Rational ZERO = new Rational(0, 1);

    /**
     * Unique version number per class to be compliant with {@link java.io.Serializable}.
     *
     * <p>Increment each time the fields change in any way.</p>
     */
    private static final long serialVersionUID = 1L;

    /*
     * Do not change the order of these fields or add new instance fields to maintain the
     * Serializable compatibility across API revisions.
     */
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
    private final int mNumerator;
    @UnsupportedAppUsage(maxTargetSdk = Build.VERSION_CODES.R, trackingBug = 170729553)
    private final int mDenominator;

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
    public Rational(int numerator, int denominator) {

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
            int gcd = gcd(numerator, denominator);

            mNumerator = numerator / gcd;
            mDenominator = denominator / gcd;
        }
    }

    /**
     * Gets the numerator of the rational.
     *
     * <p>The numerator will always return {@code 1} if this rational represents
     * infinity (that is, the denominator is {@code 0}).</p>
     */
    public int getNumerator() {
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
    public int getDenominator() {
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
    public boolean isNaN() {
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
    public boolean isInfinite() {
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
    public boolean isFinite() {
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
    public boolean isZero() {
        return isFinite() && mNumerator == 0;
    }

    private boolean isPosInf() {
        return mDenominator == 0 && mNumerator > 0;
    }

    private boolean isNegInf() {
        return mDenominator == 0 && mNumerator < 0;
    }

    /**
     * <p>Compare this Rational to another object and see if they are equal.</p>
     *
     * <p>A Rational object can only be equal to another Rational object (comparing against any
     * other type will return {@code false}).</p>
     *
     * <p>A Rational object is considered equal to another Rational object if and only if one of
     * the following holds:</p>
     * <ul><li>Both are {@code NaN}</li>
     *     <li>Both are infinities of the same sign</li>
     *     <li>Both have the same numerator and denominator in their reduced form</li>
     * </ul>
     *
     * <p>A reduced form of a Rational is calculated by dividing both the numerator and the
     * denominator by their greatest common divisor.</p>
     *
     * <pre>{@code
     * (new Rational(1, 2)).equals(new Rational(1, 2)) == true   // trivially true
     * (new Rational(2, 3)).equals(new Rational(1, 2)) == false  // trivially false
     * (new Rational(1, 2)).equals(new Rational(2, 4)) == true   // true after reduction
     * (new Rational(0, 0)).equals(new Rational(0, 0)) == true   // NaN.equals(NaN)
     * (new Rational(1, 0)).equals(new Rational(5, 0)) == true   // both are +infinity
     * (new Rational(1, 0)).equals(new Rational(-1, 0)) == false // +infinity != -infinity
     * }</pre>
     *
     * @param obj a reference to another object
     *
     * @return A boolean that determines whether or not the two Rational objects are equal.
     */
    @Override
    public boolean equals(@Nullable Object obj) {
        return obj instanceof Rational && equals((Rational) obj);
    }

    private boolean equals(Rational other) {
        return (mNumerator == other.mNumerator && mDenominator == other.mDenominator);
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
    @Override
    public String toString() {
        if (isNaN()) {
            return "NaN";
        } else if (isPosInf()) {
            return "Infinity";
        } else if (isNegInf()) {
            return "-Infinity";
        } else {
            return mNumerator + "/" + mDenominator;
        }
    }

    /**
     * <p>Convert to a floating point representation.</p>
     *
     * @return The floating point representation of this rational number.
     * @hide
     */
    public float toFloat() {
        // TODO: remove this duplicate function (used in CTS and the shim)
        return floatValue();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        // Bias the hash code for the first (2^16) values for both numerator and denominator
        int numeratorFlipped = mNumerator << 16 | mNumerator >>> 16;

        return mDenominator ^ numeratorFlipped;
    }

    /**
     * Calculates the greatest common divisor using Euclid's algorithm.
     *
     * <p><em>Visible for testing only.</em></p>
     *
     * @param numerator the numerator in a fraction
     * @param denominator the denominator in a fraction
     *
     * @return An int value representing the gcd. Always positive.
     * @hide
     */
    public static int gcd(int numerator, int denominator) {
        /*
         * Non-recursive implementation of Euclid's algorithm:
         *
         *  gcd(a, 0) := a
         *  gcd(a, b) := gcd(b, a mod b)
         *
         */
        int a = numerator;
        int b = denominator;

        while (b != 0) {
            int oldB = b;

            b = a % b;
            a = oldB;
        }

        return Math.abs(a);
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
    @Override
    public double doubleValue() {
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
    @Override
    public float floatValue() {
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
     * <p>
     * <ul>
     * <li>Positive infinity saturates to the largest maximum integer
     * {@link Integer#MAX_VALUE}</li>
     * <li>Negative infinity saturates to the smallest maximum integer
     * {@link Integer#MIN_VALUE}</li>
     * <li><em>Not-A-Number (NaN)</em> returns {@code 0}.</li>
     * </ul>
     * </p>
     *
     * @return the divided value of the numerator and denominator as a {@code int}.
     */
    @Override
    public int intValue() {
        // Mimic float to int conversion rules from JLS 5.1.3

        if (isPosInf()) {
            return Integer.MAX_VALUE;
        } else if (isNegInf()) {
            return Integer.MIN_VALUE;
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
     * <p>
     * <ul>
     * <li>Positive infinity saturates to the largest maximum long
     * {@link Long#MAX_VALUE}</li>
     * <li>Negative infinity saturates to the smallest maximum long
     * {@link Long#MIN_VALUE}</li>
     * <li><em>Not-A-Number (NaN)</em> returns {@code 0}.</li>
     * </ul>
     * </p>
     *
     * @return the divided value of the numerator and denominator as a {@code long}.
     */
    @Override
    public long longValue() {
        // Mimic float to long conversion rules from JLS 5.1.3

        if (isPosInf()) {
            return Long.MAX_VALUE;
        } else if (isNegInf()) {
            return Long.MIN_VALUE;
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
    @Override
    public short shortValue() {
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
     *
     * @throws NullPointerException if {@code another} was {@code null}
     */
    @Override
    public int compareTo(Rational another) {
        checkNotNull(another, "another must not be null");

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

    /*
     * Serializable implementation.
     *
     * The following methods are omitted:
     * >> writeObject - the default is sufficient (field by field serialization)
     * >> readObjectNoData - the default is sufficient (0s for both fields is a NaN)
     */

    /**
     * writeObject with default serialized form - guards against
     * deserializing non-reduced forms of the rational.
     *
     * @throws InvalidObjectException if the invariants were violated
     */
    private void readObject(java.io.ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        in.defaultReadObject();

        /*
         * Guard against trying to deserialize illegal values (in this case, ones
         * that don't have a standard reduced form).
         *
         * - Non-finite values must be one of [0, 1], [0, 0], [0, 1], [0, -1]
         * - Finite values must always have their greatest common divisor as 1
         */

        if (mNumerator == 0) { // either zero or NaN
            if (mDenominator == 1 || mDenominator == 0) {
                return;
            }
            throw new InvalidObjectException(
                    "Rational must be deserialized from a reduced form for zero values");
        } else if (mDenominator == 0) { // either positive or negative infinity
            if (mNumerator == 1 || mNumerator == -1) {
                return;
            }
            throw new InvalidObjectException(
                    "Rational must be deserialized from a reduced form for infinity values");
        } else { // finite value
            if (gcd(mNumerator, mDenominator) > 1) {
                throw new InvalidObjectException(
                        "Rational must be deserialized from a reduced form for finite values");
            }
        }
    }

    private static NumberFormatException invalidRational(String s) {
        throw new NumberFormatException("Invalid Rational: \"" + s + "\"");
    }

    /**
     * Parses the specified string as a rational value.
     * <p>The ASCII characters {@code \}{@code u003a} (':') and
     * {@code \}{@code u002f} ('/') are recognized as separators between
     * the numerator and denumerator.</p>
     * <p>
     * For any {@code Rational r}: {@code Rational.parseRational(r.toString()).equals(r)}.
     * However, the method also handles rational numbers expressed in the
     * following forms:</p>
     * <p>
     * "<i>num</i>{@code /}<i>den</i>" or
     * "<i>num</i>{@code :}<i>den</i>" {@code => new Rational(num, den);},
     * where <i>num</i> and <i>den</i> are string integers potentially
     * containing a sign, such as "-10", "+7" or "5".</p>
     *
     * <pre>{@code
     * Rational.parseRational("3:+6").equals(new Rational(1, 2)) == true
     * Rational.parseRational("-3/-6").equals(new Rational(1, 2)) == true
     * Rational.parseRational("4.56") => throws NumberFormatException
     * }</pre>
     *
     * @param string the string representation of a rational value.
     * @return the rational value represented by {@code string}.
     *
     * @throws NumberFormatException if {@code string} cannot be parsed
     * as a rational value.
     * @throws NullPointerException if {@code string} was {@code null}
     */
    public static Rational parseRational(String string)
            throws NumberFormatException {
        checkNotNull(string, "string must not be null");

        if (string.equals("NaN")) {
            return NaN;
        } else if (string.equals("Infinity")) {
            return POSITIVE_INFINITY;
        } else if (string.equals("-Infinity")) {
            return NEGATIVE_INFINITY;
        }

        int sep_ix = string.indexOf(':');
        if (sep_ix < 0) {
            sep_ix = string.indexOf('/');
        }
        if (sep_ix < 0) {
            throw invalidRational(string);
        }
        try {
            return new Rational(Integer.parseInt(string.substring(0, sep_ix)),
                    Integer.parseInt(string.substring(sep_ix + 1)));
        } catch (NumberFormatException e) {
            throw invalidRational(string);
        }
    }
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

static Range<Long> parseLongRange(Object o, Range<Long> fallback) {
    if (o == null) {
        return fallback;
    }
    try {
        String s = (String)o;
        int ix = s.indexOf('-');
        if (ix >= 0) {
            return Range.create(
                    Long.parseLong(s.substring(0, ix), 10),
                    Long.parseLong(s.substring(ix + 1), 10));
        }
        long value = Long.parseLong(s);
        return Range.create(value, value);
    } catch (ClassCastException e) {
    } catch (NumberFormatException e) {
    } catch (IllegalArgumentException e) {
    }
    Log.w(TAG, "could not parse long range '" + o + "'");
    return fallback;
}

static Range<Rational> parseRationalRange(Object o, Range<Rational> fallback) {
    if (o == null) {
        return fallback;
    }
    try {
        String s = (String)o;
        int ix = s.indexOf('-');
        if (ix >= 0) {
            return Range.create(
                    Rational.parseRational(s.substring(0, ix)),
                    Rational.parseRational(s.substring(ix + 1)));
        }
        Rational value = Rational.parseRational(s);
        return Range.create(value, value);
    } catch (ClassCastException e) {
    } catch (NumberFormatException e) {
    } catch (IllegalArgumentException e) {
    }
    Log.w(TAG, "could not parse rational range '" + o + "'");
    return fallback;
}

static Pair<Size, Size> parseSizeRange(Object o) {
    if (o == null) {
        return null;
    }
    try {
        String s = (String)o;
        int ix = s.indexOf('-');
        if (ix >= 0) {
            return Pair.create(
                    Size.parseSize(s.substring(0, ix)),
                    Size.parseSize(s.substring(ix + 1)));
        }
        Size value = Size.parseSize(s);
        return Pair.create(value, value);
    } catch (ClassCastException e) {
    } catch (NumberFormatException e) {
    } catch (IllegalArgumentException e) {
    }
    Log.w(TAG, "could not parse size range '" + o + "'");
    return null;
}

}

#endif  // MEDIA_CODEC_INFO_UTILS_H_