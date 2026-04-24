/* Copyright (c) 2026-2026, vfast.
 * Author: [yanruibing]
 */
#ifndef __ERROR_H__
#define __ERROR_H__

typedef enum {
    VF_OK              = 0,   /* 成功 */
    VF_ERR_GENERIC     = -1,  /* 通用错误 */
    VF_ERR_AUTH_DENIED = -2,  /* 认证拒绝 (密码错或账号禁用) */
    VF_ERR_AUTH_TIMEOUT= -3,  /* 认证超时 (RADIUS服务器未响应) */
    VF_ERR_NOT_FOUND   = -4,  /* 用户不存在 */
    VF_ERR_SYSTEM      = -5,  /* 系统错误 (内存不足、文件IO失败) */
    VF_ERR_INVALID_PARAM = -6, /* 参数非法 */
    VF_ERR_CONFIG      = -7   /* 配置错误 */
} vf_error_t;

#endif