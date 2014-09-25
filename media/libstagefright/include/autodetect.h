/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef AUTODETECT_H
#define AUTODETECT_H

#include <inttypes.h>
#include <stdio.h>

namespace android {

// flags used for native encoding detection
enum Encoding {
    kEncodingNone               = 0,
   // Two-byte encodings
    kEncodingShiftJIS           = (1 << 0),
    kEncodingGBK                = (1 << 1),
    kEncodingBig5               = (1 << 2),
    kEncodingEUCKR              = (1 << 3),
    // One-byte encodings
    kEncodingCP874              = (1 << 4), // Thai
    kEncodingCP1251             = (1 << 5), // Cyrillic
    kOneByteEncodings           = kEncodingCP874 | kEncodingCP1251,

    kEncodingAll                = kEncodingShiftJIS | kEncodingGBK | kEncodingBig5 |
                                  kEncodingEUCKR | kEncodingCP874 | kEncodingCP1251,
};

class String8;

class AutoDetect {
public:
    AutoDetect(int stringsEstimate = 128, const char* locale = NULL);
    ~AutoDetect();

    void setLocale(const char* locale);
    Encoding getLocaleEncoding() const;
    bool convertToUTF8(const char* src, int strLen, String8 *s, Encoding encoding) const;

    /* Verify that the given string contains only characters that match the given encoding */
    bool verifyEncoding(const char* str, int numBytes, Encoding encoding) const;

    /* Return a bitmap of all known encodings that match the given string */
    Encoding possibleEncodings(const char* s, int numBytes) const;

    /* Deduce encoding for the given string and suggest a match */
    Encoding suggestEncoding(const char* s, int numBytes) const;

    /* Deduce encoding from all added strings and suggest a match */
    void addString(const char* str, int numBytes);
    Encoding suggestEncoding() const;

private:
    Encoding mLocaleEncoding;
    char* mAddedStrings;
    int mAddedStringSize;
    int mAddedStringLen;

};

}  // namespace android

#endif // AUTODETECT_H



