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

#include <cutils/properties.h>
#include "utility/ValidateXml.h"

TEST(CheckConfig, mediaProfilesValidation) {
    RecordProperty("description",
                   "Verify that the media profiles file "
                   "is valid according to the schema");

    char value[PROPERTY_VALUE_MAX];
    char location[PROPERTY_VALUE_MAX] = "/vendor/etc";
    char fileName[PROPERTY_VALUE_MAX] = "media_profiles_V1_0.xml";

    if (property_get("media.settings.xml", value, NULL) > 0) {
        char *delimiter;
        delimiter=strrchr(value,'/');

        if (delimiter != NULL) {
            value[delimiter-value] = '\0';
            strcpy(location, value);
            strcpy(fileName, delimiter+1);
        }
    }

    EXPECT_ONE_VALID_XML_MULTIPLE_LOCATIONS(fileName, {location},
                                            "/data/local/tmp/media_profiles.xsd");
}
