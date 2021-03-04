/******************************************************************************
 *
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */
#include <C2Config.h>
#include <C2PlatformSupport.h>
#include <gtest/gtest.h>
#include <log/log.h>

using namespace android;
class C2SoftCodecTest : public ::testing::Test {};

TEST_F(C2SoftCodecTest, PicInfoSizeTest) {
  std::shared_ptr<C2ComponentStore> componentStore = GetCodec2PlatformComponentStore();
  ASSERT_NE(componentStore, nullptr) << "Error in GetTestComponentStore";

  std::shared_ptr<C2Component> component;
  c2_status_t status = componentStore->createComponent(C2COMPONENTNAME, &component);
  ASSERT_EQ(status, C2_OK) << "Error in createComponent";
  ASSERT_NE(component, nullptr) << "component is null";

  std::shared_ptr<C2ComponentInterface> interface;
  status = componentStore->createInterface(C2COMPONENTNAME, &interface);
  ASSERT_EQ(status, C2_OK) << "Error in createInterface";
  ASSERT_NE(interface, nullptr) << "interface is null";

  std::unique_ptr<C2StreamPictureSizeInfo::output> param =
      std::make_unique<C2StreamPictureSizeInfo::output>();
  std::vector<C2FieldSupportedValuesQuery> validValueInfos = {
      C2FieldSupportedValuesQuery::Current(
          C2ParamField(param.get(), &C2StreamPictureSizeInfo::width)),
      C2FieldSupportedValuesQuery::Current(
          C2ParamField(param.get(), &C2StreamPictureSizeInfo::height))};
  status = interface->querySupportedValues_vb(validValueInfos, C2_MAY_BLOCK);
  ASSERT_EQ(status, C2_OK) << "Error in querySupportedValues_vb";
  ASSERT_EQ(validValueInfos.size(), 2) << "querySupportedValues_vb didn't return 2 values";

  ASSERT_EQ(validValueInfos[0].values.range.max.ref<uint32_t>(), 1920)
      << "Incorrect maximum value for width";
  ASSERT_EQ(validValueInfos[1].values.range.max.ref<uint32_t>(), 1920)
      << "Incorrect maximum value for height";
  ASSERT_EQ(validValueInfos[0].values.range.min.ref<uint32_t>(), 2)
      << "Incorrect minimum value for width";
  ASSERT_EQ(validValueInfos[1].values.range.min.ref<uint32_t>(), 2)
      << "Incorrect minimum value for height";
  ASSERT_EQ(validValueInfos[0].values.range.step.ref<uint32_t>(), 2)
      << "Incorrect alignment value for width";
  ASSERT_EQ(validValueInfos[1].values.range.step.ref<uint32_t>(), 2)
      << "Incorrect alignment value for height";

  return;
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  int status = RUN_ALL_TESTS();
  ALOGV("Test result = %d\n", status);
  return status;
}
