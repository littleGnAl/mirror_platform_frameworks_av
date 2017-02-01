LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES :=     \
        CentralTendencyStatistics.cpp \
        ThreadCpuUsage.cpp

LOCAL_MODULE := libcpustats

LOCAL_CFLAGS := -Werror -Wall

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include

include $(BUILD_STATIC_LIBRARY)
