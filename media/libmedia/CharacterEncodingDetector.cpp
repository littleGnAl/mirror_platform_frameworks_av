/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <media/CharacterEncodingDetector.h>
#include "MediaCharsetDetector.h"

namespace android {

CharacterEncodingDetector::CharacterEncodingDetector() {
    mDetector = new MediaCharsetDetector();
}

CharacterEncodingDetector::~CharacterEncodingDetector() {
    delete mDetector;
}

void CharacterEncodingDetector::addTag(const char *name, const char *value) {
    mDetector->addTag(name, value);
}
size_t CharacterEncodingDetector::size() {
    return mDetector->size();
}

void CharacterEncodingDetector::detectAndConvert() {
    mDetector->detectAndConvert();
}

status_t CharacterEncodingDetector::getTag(int index, const char **name, const char**value) {
    return mDetector->getTag(index, name, value);
}

}  // namespace android
