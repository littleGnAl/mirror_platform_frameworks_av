# Build the unit tests.
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

ifneq ($(TARGET_SIMULATOR),true)

LOCAL_MODULE := SurfaceMediaSource_test

LOCAL_MODULE_TAGS := tests

LOCAL_SRC_FILES := \
    SurfaceMediaSource_test.cpp \
	DummyRecorder.cpp \

LOCAL_SHARED_LIBRARIES := \
	libbinder \
	libcrypto \
	libcutils \
	libEGL \
	libGLESv2 \
	libgui \
	liblog \
	libmedia \
	libstagefright \
	libstagefright_foundation \
	libstagefright_omx \
	libstlport \
	libsync \
	libui \
	libutils \

LOCAL_STATIC_LIBRARIES := \
	libgtest \
	libgtest_main \

LOCAL_C_INCLUDES := \
    bionic \
    bionic/libstdc++/include \
    external/gtest/include \
    external/stlport/stlport \
	frameworks/av/media/libstagefright \
	frameworks/av/media/libstagefright/include \
	$(TOP)/frameworks/native/include/media/openmax \

LOCAL_32_BIT_ONLY := true

include $(BUILD_EXECUTABLE)

endif

# Include subdirectory makefiles
# ============================================================

# If we're building with ONE_SHOT_MAKEFILE (mm, mmm), then what the framework
# team really wants is to build the stuff defined by this makefile.
ifeq (,$(ONE_SHOT_MAKEFILE))
include $(call first-makefiles-under,$(LOCAL_PATH))
endif
