#include <codec2/aidl/GraphicsTracker.h>

#include <iostream>

using ::aidl::android::hardware::media::c2::implementation::GraphicsTracker;
int main() {
  auto tracker = GraphicsTracker::CreateGraphicsTracker(10);

  if (tracker) {
      std::cout << "GraphicsTracker created" << std::endl;
  } else {
      std::cout << "GraphicsTracker creation failed" << std::endl;
  }

}
