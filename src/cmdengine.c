/*
 * Copyright (c) 2026-2026, CLI
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdatomic.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>

#include "utils.h"
#include "log.h"
#include "cmd.h"
#include "cmdengine.h"
#include "session.h"

typedef struct cmd_engine_s {
    atomic_int interval;       /* Atomic integer for scan interval */
    atomic_bool islogptk;      /* Atomic boolean for packet logging */
    atomic_bool isdebug;       /* Atomic boolean for debug mode */

    struct {
        atomic_uint_least64_t rx_pkts;   /* Successfully reassembled datagrams */
        atomic_uint_least64_t tx_pkts;   /* Reassembly attempts that timed out */
        atomic_uint_least64_t drops;     /* Reassembly errors (e.g., missing fragments) */
    } reass_stats;

    struct {
        atomic_int_fast16_t total;    /* Total number of pre-allocated task buffers */
        atomic_int_fast16_t count;    /* Number of pre-allocated task buffers */
        atomic_int_fast16_t r_tun;    /* Read number for tun tasks */
        atomic_int_fast16_t r_udp;    /* Read number for UDP tasks */
        atomic_int_fast16_t w_tun;    /* Write number for tun tasks */
        atomic_int_fast16_t w_udp;    /* Write number for UDP tasks */
    } task_pool;
} cmd_engine_t;

static cmd_engine_t cmdengine = {
    .interval = ATOMIC_VAR_INIT(1000),  /* Default 1000ms */
    .islogptk = ATOMIC_VAR_INIT(false), /* Default disabled */
    .isdebug = ATOMIC_VAR_INIT(true),  /* Default enabled */
    .reass_stats = {
        .rx_pkts = ATOMIC_VAR_INIT(0),
        .tx_pkts = ATOMIC_VAR_INIT(0),
        .drops = ATOMIC_VAR_INIT(0)
    },
    .task_pool = {
        .count = ATOMIC_VAR_INIT(0),
        .r_tun = ATOMIC_VAR_INIT(0),
        .r_udp = ATOMIC_VAR_INIT(0),
        .w_tun = ATOMIC_VAR_INIT(0),
        .w_udp = ATOMIC_VAR_INIT(0)
    }
};

static struct timespec g_start_ts;

static int cmd_set_islogptk(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_set_isdebug(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_get_reass_stats(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_get_config(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_get_sessions(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_get_session_bysid(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_get_task_pool(void *ctx, int argc, char **argv, cmd_resp_t *resp);

static int cmd_handle_set(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_handle_get(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_handle_status(void *ctx, int argc, char **argv, cmd_resp_t *resp);

static const cmd_entry_t cmd_table[] = {
    /* --- Root Level Commands (group is NULL) --- */
    {NULL,  "STATUS", "show server status",               "",            1, cmd_handle_status},
    {NULL,  "SET",    "set parameters",                   "<key> <val>", 1, cmd_handle_set},
    {NULL,  "GET",    "get parameters",                   "<key>",       1, cmd_handle_get},
    {NULL,  "HELP",   "command help",                     "[command]",   1, cmd_handle_help},
    {NULL,  "EXIT",   "exit the CLI",                     "",            1, NULL},
    /* --- SET Group Sub-commands --- */
    {"SET", "interval", "Scan interval (ms)",              "<val>",      3, NULL},
    {"SET", "logpkt",   "print raw XDP packet info",       "<1|0>",      3, cmd_set_islogptk},
    {"SET", "debug",    "enable/disable debug mode",       "<1|0>",      3, cmd_set_isdebug},
    /* --- GET Group Sub-commands --- */
    {"GET", "pktstats", "get packet statistics",           "",           2, cmd_get_reass_stats},
    {"GET", "config",   "get configuration",               "",           2, cmd_get_config},
    {"GET", "session",  "get session number",              "",           2, cmd_get_sessions},
    {"GET", "show",     "show session information",        "<sid>",      3, cmd_get_session_bysid},
    {"GET", "tasks",    "show task pool status",           "",           2, cmd_get_task_pool},

    {NULL, NULL, NULL, NULL, 0, NULL}
};

static void get_uptime_str(char *buf, size_t len) {
    struct timespec now_ts;
    clock_gettime(CLOCK_MONOTONIC, &now_ts);

    long diff = now_ts.tv_sec - g_start_ts.tv_sec;
    if (diff < 0) diff = 0;

    int days  = (int)(diff / 86400);
    int hours = (int)((diff % 86400) / 3600);
    int mins  = (int)((diff % 3600) / 60);
    int secs  = (int)(diff % 60);

    snprintf(buf, len, "%dd %dh %dm %ds", days, hours, mins, secs);
}

static int get_thread_count() {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return -1;

    char line[256];
    int threads = -1;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "Threads:", 8) == 0) {
            char *p = line + 8;
            while (*p && (*p < '0' || *p > '9')) p++;
            if (*p) threads = atoi(p);
            break;
        }
    }
    fclose(fp);
    return threads;
}

static int get_fd_count() {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return -1;

    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {
            count++;
        }
    }
    closedir(dir);
    
    /**
     * Note: The count includes the directory stream itself, so we subtract 1 
     * to get the actual number of open file descriptors.
     * This is a common practice when counting entries in /proc/self/fd, 
     * as the directory stream is an open file descriptor 
     * that we don't want to include in the count of active FDs
     */
    return (count > 0) ? (count - 1) : 0;
}

typedef struct {
    unsigned long utime;
    unsigned long stime;
    unsigned long long total_system_time;
} cpu_occupy_t;

/**
 * @brief Helper to get cumulative CPU ticks for the process and the system.
 */
static int get_cpu_ticks_sample(unsigned long *utime, unsigned long *stime, unsigned long long *system_total) {
    // 1. Get process ticks from /proc/self/stat
    FILE *fp = fopen("/proc/self/stat", "r");
    if (!fp) return -1;
    char buf[1024];
    if (!fgets(buf, sizeof(buf), fp)) { fclose(fp); return -1; }
    fclose(fp);

    /* Robust parsing: Find the last ')' to skip the comm (process name) field 
     * because process names can contain spaces or brackets. */
    char *q = strrchr(buf, ')');
    if (!q || sscanf(q + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", utime, stime) != 2) {
        return -1;
    }

    // 2. Get global system ticks from /proc/stat (Sum of all CPU states)
    fp = fopen("/proc/stat", "r");
    if (!fp) return -1;
    if (!fgets(buf, sizeof(buf), fp)) { fclose(fp); return -1; }
    fclose(fp);

    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
    if (sscanf(buf, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", 
               &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) < 4) {
        return -1;
    }
    *system_total = user + nice + system + idle + iowait + irq + softirq + steal;

    return 0;
}

/**
 * @brief Industrial-grade CPU usage calculation (Instantaneous Ratio).
 * Samples twice with a short delay to calculate the real-time load.
 * @return CPU usage percentage (e.g., 12.5 for 12.5%), or 0.0 on error.
 */
static double get_cpu_usage_ratio(void) {
    cpu_occupy_t s1, s2;

    /* Sample 1 */
    if (get_cpu_ticks_sample(&s1.utime, &s1.stime, &s1.total_system_time) < 0) {
        return 0.0;
    }

    /* Industrial standard interval (100ms - 200ms) */
    usleep(100000); 

    /* Sample 2 */
    if (get_cpu_ticks_sample(&s2.utime, &s2.stime, &s2.total_system_time) < 0) {
        return 0.0;
    }

    /* Calculate Deltas */
    unsigned long process_delta = (s2.utime + s2.stime) - (s1.utime + s1.stime);
    unsigned long long system_delta = s2.total_system_time - s1.total_system_time;

    if (system_delta == 0) return 0.0;

    /* Calculation: (Process Ticks / Total System Ticks) * 100 
     * This represents the percentage of total CPU resources used. */
    double usage = ((double)process_delta / (double)system_delta) * 100.0;

    /* Optional: Scale by number of cores if you want "Per-Core" equivalent, 
     * but usually Total System usage is what CLI status needs. */
    return usage;
}

static long get_memory_vm_rss_kb(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) {
        return -1;
    }

    char buf[256];
    long rss_kb = -1;

    while (fgets(buf, sizeof(buf), fp)) {
        char *match = strstr(buf, "VmRSS:");
        if (match) {
            char *ptr = match + 6;
            while (*ptr && (*ptr < '0' || *ptr > '9')) {
                ptr++;
            }

            if (*ptr >= '0' && *ptr <= '9') {
                rss_kb = atol(ptr);
            }
            break; 
        }
    }

    fclose(fp);
    return rss_kb;
}

/**
 * @brief Professional Handler for 'SET logpkt' using C11 Atomic Operations.
 * This implementation achieves lock-free updates, ensuring maximum performance 
 * for the data plane while maintaining strict thread safety and visibility.
 */
static int cmd_set_islogptk(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    /* 1. Context Recovery: Ensure the engine context is valid */
    cmd_engine_t *engine = (cmd_engine_t *)ctx;
    if (!engine) {
        cmd_resp_red(resp, "ERR: System internal error: context is NULL.");
        return -1;
    }

    /* 2. Argument Integrity Check: 
     * Ensures argv[2] exists before access to prevent segmentation faults.
     */
    if (argc < 3 || argv[2] == NULL) {
        cmd_resp_red(resp, "ERR: Missing parameter. Usage: SET logpkt <1|0|on|off>");
        return 0;
    }

    const char *val_str = argv[2];
    bool enable;

    /* 3. Strict Value Validation:
     * Mapping CLI string inputs to logical boolean values.
     */
    if (strcmp(val_str, "1") == 0 || 
        strcasecmp(val_str, "on") == 0 || 
        strcasecmp(val_str, "true") == 0) {
        enable = true;
    } else if (strcmp(val_str, "0") == 0 || 
               strcasecmp(val_str, "off") == 0 || 
               strcasecmp(val_str, "false") == 0) {
        enable = false;
    } else {
        cmd_resp_red(resp, "ERR: Invalid value '%s'. Expected: 1, 0, on, off, true, or false.", val_str);
        return 0; 
    }

    /* 4. Atomic State Comparison:
     * atomic_load ensures we read the most current value across CPU caches.
     * If the state is already the same, we avoid redundant store and logging.
     */
    if (atomic_load(&engine->islogptk) == enable) {
        cmd_resp_green(resp, "OK: Raw packet logging is already %s.", enable ? "ENABLED" : "DISABLED");
        return 0;
    }

    /* 5. Atomic Thread-Safe Update:
     * atomic_store provides a lock-free way to update the variable.
     * memory_order_seq_cst (default) ensures the strongest consistency.
     */
    atomic_store(&engine->islogptk, enable);

    /* 6. Response and Audit Trail:
     * Feedback is given to the CLI user and a persistent log is generated for the admin.
     */
    cmd_resp_green(resp, "OK: Raw packet logging changed to %s.", enable ? "ENABLED" : "DISABLED");
    log_info("[MGMT] Configuration updated: islogptk set to %d by administrator.", (int)enable);

    return 0;
}

static int cmd_set_isdebug(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    /* Similar structure to cmd_set_islogptk, but for the isdebug flag */
    cmd_engine_t *engine = (cmd_engine_t *)ctx;
    if (!engine) {
        cmd_resp_red(resp, "ERR: System internal error: context is NULL.");
        return -1;
    }

    if (argc < 3 || argv[2] == NULL) {
        cmd_resp_red(resp, "ERR: Missing parameter. Usage: SET debug <1|0|on|off>");
        return 0;
    }

    const char *val_str = argv[2];
    bool enable;

    if (strcmp(val_str, "1") == 0 || 
        strcasecmp(val_str, "on") == 0 || 
        strcasecmp(val_str, "true") == 0) {
        enable = true;
    } else if (strcmp(val_str, "0") == 0 || 
               strcasecmp(val_str, "off") == 0 || 
               strcasecmp(val_str, "false") == 0) {
        enable = false;
    } else {
        cmd_resp_red(resp, "ERR: Invalid value '%s'. Expected: 1, 0, on, off, true, or false.", val_str);
        return 0; 
    }

    if (atomic_load(&engine->isdebug) == enable) {
        cmd_resp_green(resp, "OK: Debug mode is already %s.", enable ? "ENABLED" : "DISABLED");
        return 0;
    }

    atomic_store(&engine->isdebug, enable);
    if (enable) 
        log_set_level(LOG_TRACE);
    else 
        log_set_level(LOG_INFO);

    cmd_resp_green(resp, "OK: Debug mode changed to %s.", enable ? "ENABLED" : "DISABLED");
    log_info("[MGMT] Configuration updated: isdebug set to %d by administrator.", (int)enable);

    return 0;
}

/**
 * @brief Sub-dispatcher for the "SET" group.
 */
static int cmd_handle_set(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    /* 1. Check if sub-command (key) is provided.
     * If just "SET" is typed, show all keys in the SET group.
     */
    if (argc < 2) {
        cmd_group_help("SET", resp);
        return 0;
    }

    const char *sub_cmd = argv[1];

    /* 2. Search ONLY within the "SET" group */
    for (int i = 0; cmd_table[i].name != NULL; i++) {
        /* Only consider entries belonging to the "SET" group */
        if (cmd_table[i].group != NULL && strcasecmp(cmd_table[i].group, "SET") == 0) {
            
            if (strcasecmp(sub_cmd, cmd_table[i].name) == 0) {
                /* Guard against uninitialized handlers in the static table */
                if (cmd_table[i].handler == NULL) {
                    cmd_resp_red(resp, "ERR: SET %s logic is not implemented.", sub_cmd);
                    return 0;
                }

                /* Validate arguments for this specific sub-command */
                if (argc < cmd_table[i].min_argc) {
                    cmd_resp_red(resp, "ERR: Usage: SET %s %s", 
                                   cmd_table[i].name, cmd_table[i].usage);
                    return 0;
                }
                /* Execute the targeted handler */
                return cmd_table[i].handler(ctx, argc, argv, resp);
            }
        }
    }

    /* 3. Fallback: Key not found in this group */
    cmd_resp_red(resp, "ERR: Unknown SET key '%s'. Use 'HELP SET' to see options.", sub_cmd);
    return -1;
}

/**
 * @brief Sub-dispatcher for the "GET" command group.
 * This function handles the second-level routing for all configuration retrieval requests.
 * It ensures that the user has provided a valid key and that the internal state 
 * can be accessed safely via the registered handler.
 * @param ctx      Opaque pointer to the application engine context (cmd_engine_t).
 * @param argc     Number of arguments in the command line (e.g., "GET logpkt" -> argc=2).
 * @param argv     Array of strings containing the command and arguments.
 * @param resp     Pointer to the response buffer context for outputting results.
 * @return int     0 on successful dispatch or handled user error, -1 on internal system failure.
 */
static int cmd_handle_get(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    /* 1. Preliminary Validation: Defensive checks for mandatory pointers */
    if (!ctx || !resp) {
        /* This should theoretically never happen if the framework is sound */
        return -1; 
    }

    /* 2. Argument Presence Check:
     * If the user sends "GET" without any keys, provide an interactive discovery
     * list of all available keys within this specific group.
     */
    if (argc < 2) {
        cmd_group_help("GET", resp);
        return 0;
    }

    /* Extract the sub-command (key) after the "GET" verb */
    const char *target_key = argv[1];

    /* 3. Static Table Lookup:
     * Linearly scan the command table for entries matching the "GET" group.
     * Note: strcasecmp is used to allow "get logpkt" or "GET LOGPKT".
     */
    for (int i = 0; cmd_table[i].name != NULL; i++) {
        /* Filter entries that belong to the "GET" group */
        if (cmd_table[i].group != NULL && strcasecmp(cmd_table[i].group, "GET") == 0) {
            
            /* Match the specific sub-command name */
            if (strcasecmp(target_key, cmd_table[i].name) == 0) {
                
                /* Guard against uninitialized handlers in the static table */
                if (cmd_table[i].handler == NULL) {
                    cmd_resp_red(resp, "ERR: GET %s logic is not implemented.", target_key);
                    return 0;
                }

                /* Validation: Ensure the caller provided enough arguments for the leaf handler */
                if (argc < cmd_table[i].min_argc) {
                    cmd_resp_red(resp, "ERR: Usage: GET %s %s", 
                                   cmd_table[i].name, 
                                   cmd_table[i].usage ? cmd_table[i].usage : "");
                    return 0;
                }

                /* Execute the leaf handler. Leaf handlers for GET must use atomic_load 
                 * internally for thread-safe access to the engine context. */
                return cmd_table[i].handler(ctx, argc, argv, resp);
            }
        }
    }

    /* 4. Fallback: No matching key found in the GET group */
    cmd_resp_red(resp, "ERR: Unknown GET key '%s'. Use 'HELP GET' to list valid keys.", target_key);
    
    return -1;
}

/**
 * @brief Professional Handler to retrieve IP reassembly statistics.
 * * This implementation ensures context validity, utilizes atomic loads for 
 * thread-safety without blocking the XDP data path, and provides formatted 
 * tabular output for better CLI readability.
 */
static int cmd_get_reass_stats(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    (void)argv;

    /* 1. Context and Parameter Validation */
    cmd_engine_t *engine = (cmd_engine_t *)ctx;
    
    if (!engine || !resp) {
        /* Technical error: Should be caught during integration */
        return -1; 
    }

    /* Argument Check: 
     * Since this is a leaf node (e.g., "GET reass"), we expect argc to be exactly 2.
     * If there are extra arguments, we flag it as an invalid usage.
     */
    if (argc != 2) {
        cmd_resp_red(resp, "ERR: Unexpected arguments. Usage: GET reass");
        return 0;
    }

    /* 2. Snapshot Atomic Data
     * We load values into local variables to ensure a consistent point-in-time 
     * view of the statistics for this specific report.
     */
    uint64_t rx_pkts = atomic_load(&engine->reass_stats.rx_pkts);
    uint64_t tx_pkts   = atomic_load(&engine->reass_stats.tx_pkts);
    uint64_t drops     = atomic_load(&engine->reass_stats.drops);

    /* 3. Professional Formatted Output 
     * Using headers and aligned columns makes the CLI output parseable by 
     * humans and simple scripts.
     */
    cmd_resp_printf(resp, "\n  %s%-20s%s : %s%lu%s\n", C_GREEN, "Reass-RX", C_RESET, C_YELLOW, rx_pkts, C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%lu%s\n", C_GREEN, "Reass-TX", C_RESET, C_YELLOW, tx_pkts, C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%lu%s\n", C_GREEN, "Reass-Drops", C_RESET, C_YELLOW, drops, C_RESET);

    return 0;
}

static int cmd_get_config(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    (void)argv;

    cmd_engine_t *engine = (cmd_engine_t *)ctx;
    if (!engine || !resp) {
        return -1;
    }

    if (argc != 2) {
        cmd_resp_red(resp, "ERR: Unexpected arguments. Usage: GET config");
        return -1;
    }

    int interval = atomic_load(&engine->interval);
    bool islogptk = atomic_load(&engine->islogptk);

    cmd_resp_printf(resp, "\n  %s%-20s%s : %s%d%s %sms%s\n", 
                    C_GREEN, "interval", C_RESET, 
                    C_YELLOW, interval, C_RESET, 
                    C_GRAY, C_RESET);

    cmd_resp_printf(resp, "  %s%-20s%s : %s%s%s\n", 
                    C_GREEN, "logpkt", C_RESET, 
                    C_YELLOW, islogptk ? "yes" : "no",
                    C_RESET);

    cmd_resp_printf(resp, "  %s%-20s%s : %s%s%s\n", 
                    C_GREEN, "debug", C_RESET, 
                    C_YELLOW, cmd_isdebug_enabled() ? "yes" : "no",
                    C_RESET);

    return 0;
}

static int cmd_get_sessions(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    (void)argv;

    cmd_engine_t *engine = (cmd_engine_t *)ctx;
    if (!engine || !resp) {
        return -1;
    }

    if (argc != 2) {
        cmd_resp_red(resp, "ERR: Unexpected arguments. Usage: GET session");
        return -1;
    }

    uint32_t n = vf_ss_get_total_count();

    cmd_resp_printf(resp, "\n  %s%-20s%s : %s%u%s %ssessions%s\n", 
                    C_GREEN, "session number", C_RESET, 
                    C_YELLOW, n, C_RESET, 
                    C_GRAY, C_RESET);
    return 0;
}

static int cmd_get_session_bysid(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    cmd_engine_t *engine = (cmd_engine_t *)ctx;
    if (!engine || !resp) {
        return -1;
    }

    if (argc < 3 || argv[2] == NULL) {
        cmd_resp_red(resp, "ERR: Unexpected arguments. Usage: GET show <sid>");
        return 0;
    }

    const char *val_str = argv[2];
    char *endptr;
    uint32_t sid = (uint32_t)strtoul(val_str, &endptr, 16);

    if (val_str == endptr || (*endptr != '\0' && !isspace(*endptr))) {
        cmd_resp_red(resp, "ERR: Invalid SID format '%s'. Use hex (e.g., 0x32076a9d)\n", val_str);
        return -1;
    }

    /* 3. Lookup session context */
    vf_session_t *s = NULL;
    if (!vf_ss_lookup_by_sid(sid, &s) || s == NULL) {
        cmd_resp_printf(resp, C_RED "SID [" C_RESET C_YELLOW "0x%08x" C_RESET "] " C_RED "not found" C_RESET, sid);
        return 0;
    }

    /* 4. Format Output (Green Keys, Yellow Values) */
    char ip_buf[INET_ADDRSTRLEN];
    ip_ntop(s->remote_addr.sin_addr.s_addr, ip_buf, sizeof(ip_buf));
    uint16_t port = ntohs(s->remote_addr.sin_port);

    cmd_resp_printf(resp, "\n");

    // Session ID
    cmd_resp_printf(resp, "  %s%-20s%s : %s0x%08x%s\n", 
                    C_GREEN, "Sid", C_RESET, 
                    C_YELLOW, s->session_id, C_RESET);

    // Virtual IP
    char vip_str[INET_ADDRSTRLEN];
    ip_ntop(s->virtual_ip, vip_str, sizeof(vip_str));
    cmd_resp_printf(resp, "  %s%-20s%s : %s%s%s\n", 
                    C_GREEN, "Vip", C_RESET, 
                    C_YELLOW, vip_str, C_RESET);

    // Remote Address (IP:Port)
    char endpoint[64];
    snprintf(endpoint, sizeof(endpoint), "%s:%d", ip_buf, port);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%s%s\n", 
                    C_GREEN, "Remote", C_RESET, 
                    C_YELLOW, endpoint, C_RESET);

    // Last Active (Relative time)
    uint64_t idle_sec = (uint64_t)(time(NULL) - s->last_seen);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%llu%s%ss%s\n", 
                    C_GREEN, "Active", C_RESET, 
                    C_YELLOW, (unsigned long long)idle_sec, C_RESET,
                    C_GRAY, C_RESET);

    return 0;
}

static int cmd_handle_status(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    (void)ctx;
    (void)argv;

    if (argc != 1) {
        cmd_resp_red(resp, "ERR: Unexpected arguments. Usage: STATUS");
        return 0;
    }

    char uptime_str[64];
    get_uptime_str(uptime_str, sizeof(uptime_str));

    int thread_count = get_thread_count();
    int fd_count = get_fd_count();
    double cpu_usage = get_cpu_usage_ratio();
    long mem_rss_kb = get_memory_vm_rss_kb();

    cmd_resp_printf(resp, "\n  %s%-20s%s : %s%d%s\n", C_GREEN, "PID", C_RESET, C_YELLOW, getpid(), C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%s%s\n", C_GREEN, "Uptime", C_RESET, C_YELLOW, uptime_str, C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%d%s\n", C_GREEN, "Threads", C_RESET, C_YELLOW, thread_count, C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%d%s\n", C_GREEN, "Open FDs", C_RESET, C_YELLOW, fd_count, C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%.2f CPU-seconds%s\n", C_GREEN, "CPU Usage", C_RESET, C_YELLOW, cpu_usage, C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%ld KB%s\n", C_GREEN, "Memory RSS", C_RESET, C_YELLOW, mem_rss_kb, C_RESET);

    return 0;
}

static int cmd_get_task_pool(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    (void)argv;

    cmd_engine_t *engine = (cmd_engine_t *)ctx;
    if (!engine || !resp) {
        return -1;
    }

    if (argc != 2) {
        cmd_resp_red(resp, "ERR: Unexpected arguments. Usage: GET tasks");
        return -1;
    }

    int total = atomic_load(&engine->task_pool.total);
    int count = atomic_load(&engine->task_pool.count);
    int r_tun = atomic_load(&engine->task_pool.r_tun);
    int r_udp = atomic_load(&engine->task_pool.r_udp);
    int w_tun = atomic_load(&engine->task_pool.w_tun);
    int w_udp = atomic_load(&engine->task_pool.w_udp);

    cmd_resp_printf(resp, "\n  %s%-20s%s : %s%d%s\n", C_GREEN, "Total Tasks", C_RESET, C_YELLOW, total, C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%d%s\n", C_GREEN, "Active Tasks", C_RESET, C_YELLOW, count, C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%d%s\n", C_GREEN, "Read TUN", C_RESET, C_YELLOW, r_tun, C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%d%s\n", C_GREEN, "Read UDP", C_RESET, C_YELLOW, r_udp, C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%d%s\n", C_GREEN, "Write TUN", C_RESET, C_YELLOW, w_tun, C_RESET);
    cmd_resp_printf(resp, "  %s%-20s%s : %s%d%s\n", C_GREEN, "Write UDP", C_RESET, C_YELLOW, w_udp, C_RESET);

    return 0;
}

/**
 * @brief Initializes the command table and launches the management server thread.
 * @return pthread_t The thread ID of the management server on success, 
 * or 0 if the table registration or thread creation fails.
 */
pthread_t cmd_start_core(void) {
    clock_gettime(CLOCK_MONOTONIC, &g_start_ts);
    /* 1. Register the business command table */
    cmd_register_table(cmd_table);

    /* 2. Start the management server thread */
    pthread_t tid = cmd_server_start(&cmdengine);

    /* 3. Validation and Error Logging */
    if (tid == 0) {
        log_error("[CORE] Fatal: Failed to start management server thread.");
        return 0; 
    }

    log_info("[CORE] Management plane initialized successfully. Thread ID: %lu", (unsigned long)tid);
    
    return tid;
}

bool cmd_islogpkt_enabled(void) {
    return atomic_load(&cmdengine.islogptk);
}

bool cmd_isdebug_enabled(void) {
    return atomic_load(&cmdengine.isdebug);
}

/**
 * @brief Updates IP reassembly metrics using atomic increments.
 * Optimized name: cmd_reass_stats_add
 */
void cmd_reass_stats_add(int rx_pkts, int tx_pkts, int drops) {
    /* Direct atomic additions - Lock-free and XDP friendly */
    if (rx_pkts) atomic_fetch_add(&cmdengine.reass_stats.rx_pkts, 1);
    if (tx_pkts) atomic_fetch_add(&cmdengine.reass_stats.tx_pkts, 1);
    if (drops) atomic_fetch_add(&cmdengine.reass_stats.drops, 1);
}

void cmd_task_pool_set(int total, int count, int r_tun, int r_udp, int w_tun, int w_udp) {
    atomic_store(&cmdengine.task_pool.total, total);
    atomic_store(&cmdengine.task_pool.count, count);
    atomic_store(&cmdengine.task_pool.r_tun, r_tun);
    atomic_store(&cmdengine.task_pool.r_udp, r_udp);
    atomic_store(&cmdengine.task_pool.w_tun, w_tun);
    atomic_store(&cmdengine.task_pool.w_udp, w_udp);
}