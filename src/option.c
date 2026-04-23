/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include "log.h"
#include "zmalloc.h"
#include "option.h"

#define CONFIG_READ_LEN             1024
/* --- Common Defaults --- */
#define VPN_OPT_TUN_NAME            "tun0"
#define VPN_OPT_MTU                 1400
#define VPN_OPT_RING_DEPTH          4096
#define VPN_OPT_POOL_SIZE           2048
#define VPN_OPT_UDP_BACKLOG         20     /* Default 20MB for UDP receive buffer to prevent drops during bursts */
#define VPN_OPT_DEFAULT_PID_FILE    "/var/run/vfast.pid"
#define VPN_OPT_DEFAULT_FILE        "./config.conf"
#define VPN_OPT_DEFAULT_LOG_FILE    "./vfast.log"
#define VPN_OPT_DEFAULT_KEY_FILE    "./vfast.key"
/* --- Client Defaults --- */
#define VPN_OPT_REMOTE_HOST         "127.0.0.1"
#define VPN_OPT_REMOTE_PORT         9999
/* --- Server Defaults --- */
#define VPN_OPT_TUN_IP              "10.0.0.1"
#define VPN_OPT_POOL_NET            "10.0.0.0"
#define VPN_OPT_POOL_CAP            65536
#define VPN_OPT_LOCAL_PORT          9999

static int yesnotoi(char *s) {
    if (!strcasecmp(s,"yes")) return 1;
    else if (!strcasecmp(s,"no")) return 0;
    else return -1;
}

/**
 * @brief Checks if a string is a valid IPv4 address in dotted-decimal format.
 * @param ip The string to check.
 * @return true if valid, false otherwise.
 */
static inline bool is_valid_ipv4(const char *ip) {
    if (ip == NULL || *ip == '\0') return false;
    
    struct in_addr addr;
    /* inet_pton returns 1 on success, 0 on invalid format, -1 on error */
    return inet_pton(AF_INET, ip, &addr) == 1;
}

/**
 * @brief Initializes the vpn_option_t structure using predefined macros.
 */
void vf_option_init(vpn_option_t *opt) {
    if (!opt) return;

    /* Common */
    strncpy(opt->tun_name, VPN_OPT_TUN_NAME, IFNAMSIZ - 1);
    opt->tun_name[IFNAMSIZ - 1] = '\0';
    
    opt->mtu           = VPN_OPT_MTU;
    opt->io_ring_depth = VPN_OPT_RING_DEPTH;
    opt->io_pool_size  = VPN_OPT_POOL_SIZE;
    opt->udp_backlog   = VPN_OPT_UDP_BACKLOG;
    opt->disable_ipv6  = true;
    opt->daemonize     = false;
    opt->cfile         = zstrdup(VPN_OPT_DEFAULT_FILE);
    opt->pidfile       = zstrdup(VPN_OPT_DEFAULT_PID_FILE);
    opt->logfile       = zstrdup(VPN_OPT_DEFAULT_LOG_FILE);
    opt->keyfile       = zstrdup(VPN_OPT_DEFAULT_KEY_FILE);
    /* Client */
    strncpy(opt->remote_host, VPN_OPT_REMOTE_HOST, sizeof(opt->remote_host) - 1);
    opt->remote_port   = VPN_OPT_REMOTE_PORT;
    
    /* Server */
    strncpy(opt->tun_ip, VPN_OPT_TUN_IP, sizeof(opt->tun_ip) - 1);
    strncpy(opt->pool_network, VPN_OPT_POOL_NET, sizeof(opt->pool_network) - 1);
    
    opt->pool_size     = VPN_OPT_POOL_CAP;
    opt->local_port    = VPN_OPT_LOCAL_PORT;
}

void vf_option_conf(vpn_option_t *opt, const char *cfile) {
    FILE *fp;
    FILE *logfp;
    char *err = NULL;
    char tmp[CONFIG_READ_LEN+128] = {0};
    char buf[CONFIG_READ_LEN+1] = {0};

    fp = fopen(cfile, "r");
    if (fp == NULL) {
        fprintf(stderr, "Error opening config file: %s\n", cfile);
        exit(1);
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        char *p = buf;
        /* Remove whitespace characters at the beginning of the line */
        while (isspace(*p)) p++;

        /* Skip lines starting with # or empty lines */
        if (*p == '#' || *p == '\0') continue;

        /* Remove newlines at the end of lines */
        p[strcspn(p, "\r\n")] = '\0';

        char *first = p;
        char *second = NULL;

        /* Split the line into key and value */
        while (*p && !isspace(*p)) p++;
        if (*p) {
            *p = '\0';
            second = p + 1;
        }

        while (second && isspace(*second)) second++;

        if (!first || !second || *second == '\0') {
            continue; // Skip invalid or missing value lines
        }

        /* --- Mapping configuration to vpn_option_t fields --- */
        if (!strcasecmp(first, "tunname")) {
            strncpy(opt->tun_name, second, IFNAMSIZ - 1);
            opt->tun_name[IFNAMSIZ - 1] = '\0';
        } else if (!strcasecmp(first, "tunip")) {
            if (!is_valid_ipv4(second)) {
                err = "Invalid tunip format"; goto loaderr;
            }
            strncpy(opt->tun_ip, second, sizeof(opt->tun_ip) - 1);
            opt->tun_ip[sizeof(opt->tun_ip) - 1] = '\0';
        } else if (!strcasecmp(first, "mtu")) {
            opt->mtu = atoi(second);
            if (opt->mtu < 576 || opt->mtu > 9000) {
                err = "Invalid MTU value (range 576-9000)"; goto loaderr;
            }
        } else if (!strcasecmp(first, "disable-ipv6")) {
            int val = yesnotoi(second);
            if (val == -1) { err = "disable-ipv6 must be 'yes' or 'no'"; goto loaderr; }
            opt->disable_ipv6 = (bool)val;
        } else if (!strcasecmp(first, "port") || !strcasecmp(first, "local_port")) {
            opt->local_port = atoi(second);
            if (opt->local_port < 1 || opt->local_port > 65535) {
                err = "Invalid local port"; goto loaderr;
            }
        } else if (!strcasecmp(first, "remote-host")) {
            if (!is_valid_ipv4(second)) {
                snprintf(tmp, sizeof(tmp), "Invalid IPv4 address for '%s': %s", first, second);
                err = tmp;
                goto loaderr;
            }
            strncpy(opt->remote_host, second, sizeof(opt->remote_host) - 1);
            opt->remote_host[sizeof(opt->remote_host) - 1] = '\0';
        } else if (!strcasecmp(first, "remote-port")) {
            opt->remote_port = atoi(second);
            if (opt->remote_port < 1 || opt->remote_port > 65535) {
                err = "Invalid remote port"; goto loaderr;
            }
        } else if (!strcasecmp(first, "udp-backlog")) {
            opt->udp_backlog = atoi(second);
            if (opt->udp_backlog < 1) {
                err = "Invalid udp-backlog value"; goto loaderr;
            }
        } else if (!strcasecmp(first, "io-ring-depth")) {
            opt->io_ring_depth = atoi(second);
            // Industrial check: must be power of two
            if (opt->io_ring_depth < 1 || (opt->io_ring_depth & (opt->io_ring_depth - 1)) != 0) {
                err = "io-ring-depth must be a power of two"; goto loaderr;
            }
        } else if (!strcasecmp(first, "io-pool-size")) {
            opt->io_pool_size = atoi(second);
            if (opt->io_pool_size < 1024 || opt->io_pool_size > 4096) {
                err = "Invalid io-pool-size"; goto loaderr;
            }
        } else if (!strcasecmp(first, "pool-network")) {
            strncpy(opt->pool_network, second, sizeof(opt->pool_network) - 1);
        } else if (!strcasecmp(first, "pool-size")) {
            opt->pool_size = atoi(second);
            if (opt->pool_size < 1) {
                err = "Invalid pool-size"; goto loaderr;
            }
        } else if (!strcasecmp(first, "daemonize")) {
            int val = yesnotoi(second);
            if (val == -1) { err = "daemonize must be 'yes' or 'no'"; goto loaderr; }
            // Assuming you add 'bool daemonize' to opt, or handle it externally
            opt->daemonize = (bool)val; 
        } else if (!strcasecmp(first, "log-max-size")) {
            // Reusing your logic for logfilesize
            int val = atoi(second);
            if (val < 5 || val > 4000) { 
                err = "log-max-size must be between 5 MB and 4000 MB"; 
                goto loaderr;
            }
            opt->log_max_size = val;
        } else if (!strcasecmp(first, "logfile")) {
            memset(tmp, 0, sizeof(tmp));
            zfree(opt->logfile);
            opt->logfile = zstrdup(second);
            if (opt->logfile[0] != '\0') {
                /* Test if we are able to open the file. The server will not
                 * be able to abort just for this problem later... */
                logfp = fopen(opt->logfile,"a");
                if (logfp == NULL) {
                    snprintf(tmp, sizeof(tmp), "Can't open the log file: %s", strerror(errno));
                    err = tmp;
                    goto loaderr;
                }
                fclose(logfp);
            }
        } else if (!strcasecmp(first, "keyfile")) {
            memset(tmp, 0, sizeof(tmp));
            zfree(opt->keyfile);
            opt->keyfile = zstrdup(second);
            if (opt->keyfile[0] != '\0') {
                /* Test if we are able to open the file. The server will not
                 * be able to abort just for this problem later... */
                logfp = fopen(opt->keyfile,"a");
                if (logfp == NULL) {
                    snprintf(tmp, sizeof(tmp), "Can't open the key file: %s", strerror(errno));
                    err = tmp;
                    goto loaderr;
                }
                fclose(logfp);
            }
        } else if (!strcasecmp(first, "pidfile")) {
            zfree(opt->pidfile);
            opt->pidfile = zstrdup(second);
        } else if (!strcasecmp(first, "daemonize")) {
            int val = yesnotoi(second);
            if (val == -1) {
                err = "argument must be 'yes' or 'no'"; 
                goto loaderr;
            }
            opt->daemonize = (val == 1);
        } 
    }

    fclose(fp);
    return;

loaderr:
    if (fp) fclose(fp);
    log_error("Config Error: %s\n", err);
    exit(1);
}

void vf_option_clean(vpn_option_t *opt) {
    if (!opt) return;

    if (opt->logfile) zfree(opt->logfile);
    if (opt->pidfile) zfree(opt->pidfile);
    if (opt->cfile) zfree(opt->cfile);
    if (opt->keyfile) zfree(opt->keyfile);

    log_info("Options resource cleanup...");
}