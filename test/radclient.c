#include <stdio.h>
#include <string.h>
#include <radcli/radcli.h>

#define RC_CONFIG_FILE "/home/yrb/src/cleveldb/radcli.conf"

int main() {
    int result;
    VALUE_PAIR *send = NULL, *received = NULL;
    uint32_t service = 1; // Login-User
    rc_handle *rh;

    rc_openlog("rad-client");

    // 1. 加载配置
    if ((rh = rc_read_config(RC_CONFIG_FILE)) == NULL) {
        fprintf(stderr, "Error loading config\n");
        return 1;
    }

    // 2. 准备属性
    rc_avpair_add(rh, &send, PW_USER_NAME, "yrb", -1, 0);
    rc_avpair_add(rh, &send, PW_USER_PASSWORD, "123", -1, 0);
    rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0);

    // 【关键】手动添加 Message-Authenticator 占位符
    // 强制使用 ID 80 和 长度 16，确保哈希计算完整
    // char dummy[16] = {0};
    // rc_avpair_add(rh, &send, 80, dummy, 16, 0);

    // struct addrinfo *info = NULL;
    // char found_secret[MAX_SECRET_LENGTH] = {0};

    // if (rc_find_server_addr(rh, "192.168.211.130", &info, found_secret, AUTH) == 0) {
    //     printf("[SUCCESS] 库成功找到了服务器 IP 对应的密钥!\n");
    //     printf("[DEBUG] 库内部读取到的密钥是: [%s]\n", found_secret);
        
    //     if (strcmp(found_secret, "vpnsecret123") != 0) {
    //         printf("[ERROR] 密钥不匹配！你代码里想用 vpnsecret123，但库读到的是 [%s]\n", found_secret);
    //     }
        
    //     if (info) freeaddrinfo(info); // 清理 addrinfo
    // } else {
    //     printf("[FATAL] 库根本没在 servers 文件里找到 192.168.211.130 的配置!\n");
    // }

    // 2. 利用 rc_conf_str 检查配置路径是否正确
    printf("[DEBUG] 当前使用的 servers 文件路径: %s\n", rc_conf_str(rh, "servers"));
    printf("[DEBUG] 当前使用的 dictionary 路径: %s\n", rc_conf_str(rh, "dictionary"));

    // 3. 执行认证
    // 注意：这里的 0 是 NAS-Port
    result = rc_auth(rh, 0, send, &received, NULL);

    if (result == OK_RC) {
        printf("Authentication OK\n");
    } else {
        // 如果这里还报错误，请检查服务器端的 clients.conf 密钥是否也带了空格
        fprintf(stderr, "Authentication Failed: %d\n", result);
    }

    if (send) rc_avpair_free(send);
    if (received) rc_avpair_free(received);
    rc_destroy(rh);
    return 0;
}