# Build the unit tests.
LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_MODULE := DrmSessionManager_test

LOCAL_MODULE_TAGS := tests

LOCAL_SRC_FILES := \
	DrmSessionManager_test.cpp \

LOCAL_SHARED_LIBRARIES := \
	liblog \
	libmediaplayerservice \
	libmediadrm \
	libutils \
	android.hardware.drm@1.0 \

LOCAL_C_INCLUDES := \
	frameworks/av/include \
	frameworks/av/media/libmediaplayerservice \

LOCAL_CFLAGS += -Werror -Wall

ifneq ($(BOARD_USE_64BITMEDIA),true)
LOCAL_32_BIT_ONLY := true
endif

include $(BUILD_NATIVE_TEST)

