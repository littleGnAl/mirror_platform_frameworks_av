LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	ID3.cpp

LOCAL_MODULE := libstagefright_id3

include $(BUILD_STATIC_LIBRARY)

################################################################################

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	testid3.cpp

LOCAL_SHARED_LIBRARIES := \
	libbinder \
	libcrypto \
	liblog \
	libstagefright \
	libstagefright_foundation \
	libutils \

LOCAL_STATIC_LIBRARIES := \
        libstagefright_id3

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE := testid3

include $(BUILD_EXECUTABLE)
