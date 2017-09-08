#include <stdio.h>

#ifndef HDCP_LOG_H
#define HDCP_LOG_H
#define TYPE_DEBUG "D/"
#define TYPE_INFO "I/"
#define TYPE_ERR "E/"

#ifndef ANDROID
#define LOG_RAW(...)  printf(__VA_ARGS__)
#define LOGE(...) HDCP_LOG(TYPE_ERR, ##__VA_ARGS__)
//#define HDCP_LOG(type, fm, ...) printf("\n%s%s:%d  "fm,type, __FILE__, __LINE__, ##__VA_ARGS__)
#define HDCP_LOG(type, ...) ({\
        LOG_RAW("\n%s%s : %d  ",type, __FILE__,__LINE__);\
        LOG_RAW(__VA_ARGS__);\
                }) 

#else
#define LOG_TAG "TRUSTY_TEST"
#include <utils/Log.h>
#define LOG_RAW(...)	 ALOGD(__VA_ARGS__)    //FIXME in android, it only can print 1024 byte once

#define LOGE(...) ALOGE(__VA_ARGS__)
#endif

#ifndef HDCP_RELEASE    
#ifndef ANDROID
#define LOGD(...) HDCP_LOG(TYPE_DEBUG, ##__VA_ARGS__)
#define LOGI( ...)  HDCP_LOG(TYPE_INFO, ##__VA_ARGS__)
#else
#define LOG_TAG "SPRD_HDCP"
#include <utils/Log.h>
#define LOGD(...) ALOGD(__VA_ARGS__)
#define LOGI(...) ALOGI(__VA_ARGS__)
#endif

#define LOG_BUF(addr, len) do{\
    int i,offset, loc_len = (int)(len); \
    char buf[1024]; \
    char *dest = buf, *source=(char *)(addr); \
    if(loc_len >= 1024/5) \
        if((dest = (char *)malloc(loc_len*5)) == NULL)  break; \
    dest[0] = '['; \
    offset = 1; \
    for(i =0; i<loc_len; i++){\
        snprintf(dest+offset, (size_t)loc_len,"0x%02x ", source[i]); \
        offset += 5; \
    } \
    dest[offset] = ']'; \
    dest[offset+1] = '\0'; \
    printf("%s\n", dest); \
    LOG_RAW("%s\n",dest); \
    if(loc_len >= 1024/5) free(dest);\
}while(0)

#else
    #define LOGD(...) 
    #define LOGI(...) 
    #define LOG_BUF(addr, len)
#endif

#endif
