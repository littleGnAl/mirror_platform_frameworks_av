LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES =       \
	OMXHarness.cpp  \

LOCAL_SHARED_LIBRARIES := \
	libbinder \
	libcrypto \
	liblog \
	libmedia \
	libstagefright \
	libstagefright_foundation \
	libutils \

LOCAL_C_INCLUDES := \
	$(TOP)/frameworks/av/media/libstagefright \
	$(TOP)/frameworks/native/include/media/openmax

LOCAL_MODULE := omx_tests

LOCAL_MODULE_TAGS := tests

LOCAL_32_BIT_ONLY := true

include $(BUILD_EXECUTABLE)
