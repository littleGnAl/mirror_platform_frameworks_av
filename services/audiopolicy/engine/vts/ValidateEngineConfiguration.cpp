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

#include <unistd.h>
#include <string>
#include "utility/ValidateXml.h"

TEST(ValidateConfiguration, audioPolicyEngineConfiguration) {
    RecordProperty("description",
                   "Verify that the audio policy engine configuration file "
                   "is valid according to the schema");

    std::string schema = {XSD_DIR};
    schema += "/audio_policy_engine_configuration.xsd";
    std::vector<const char*> locations = {"/odm/etc", "/vendor/etc", "/system/etc"};
    EXPECT_ONE_VALID_XML_MULTIPLE_LOCATIONS("audio_policy_engine_configuration.xml", locations,
                                            schema.c_str());
}
