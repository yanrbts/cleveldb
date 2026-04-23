/**
 * @file cmd.c
 * @brief Industrial-grade Command Line Interface (CLI) Framework.
 * Support for AF_UNIX transport, Redis-style parsing, and safe dispatching.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <stdbool.h>
#include <errno.h>
#include <stdatomic.h>
#include "log.h"
#include "cmd.h"

static atomic_bool g_server_running = ATOMIC_VAR_INIT(true);
static const cmd_entry_t *g_table = NULL;

/**
 * @brief Internal structure for thread argument passing.
 */
typedef struct {
    void *user_ctx;
} cmd_server_args_t;

/**
 * @brief Global suppression of SIGPIPE to prevent process termination 
 * when a remote client closes the socket unexpectedly.
 */
static void silence_sigpipe(void) {
    static bool silenced = false;
    if (!silenced) {
        signal(SIGPIPE, SIG_IGN);
        silenced = true;
    }
}

/**
 * @brief Parses input string into argc/argv. Supports double quotes for spaces.
 * Example: SET key "value with spaces" -> [SET, key, value with spaces]
 */
static int parse_args(char *input, int *argc, char **argv) {
    char *p = input;
    bool in_quotes = false;
    *argc = 0;

    while (*p && *argc < MAX_ARG_COUNT) {
        /* Skip leading whitespace */
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;

        if (*p == '"') {
            in_quotes = true;
            p++; /* Move past the opening quote */
            argv[(*argc)++] = p;
            while (*p && (in_quotes || !isspace((unsigned char)*p))) {
                if (*p == '"') {
                    in_quotes = false;
                    *p = '\0'; /* Terminate quoted string */
                }
                p++;
            }
        } else {
            argv[(*argc)++] = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            if (*p) {
                *p = '\0'; /* Terminate argument */
                p++;
            }
        }
    }
    return in_quotes ? -1 : 0; /* Return error if quote was never closed */
}

/**
 * @brief Initializes an AF_UNIX server socket.
 */
int cmd_transport_listen(const char *path) {
    silence_sigpipe();

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    unlink(path); /* Ensure the socket path is clean */

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/**
 * @brief Connects to an existing AF_UNIX server socket.
 */
int cmd_transport_connect(const char *path) {
    silence_sigpipe();

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/**
 * @brief Sends a protocol-compliant packet.
 * * Note: Sending Header and Payload separately allows the receiver to parse 
 * 'length' first, then allocate exact memory for the payload. 
 * This mitigates stream-based fragmentation (Sticky/Half packets).
 */
int cmd_transport_send(int fd, uint16_t type, const char *data, uint32_t len) {
    afuinx_header_t hdr = {
        .magic   = AFUINX_MAGIC,
        .version = AFUINX_VERSION,
        .type    = type,
        .length  = len
    };

    /* 1. Send fixed-size header to establish message boundary */
    if (send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL) != sizeof(hdr)) {
        return -1;
    }

    /* 2. Send variable-length payload based on hdr.length */
    if (len > 0 && data) {
        if (send(fd, data, len, MSG_NOSIGNAL) != (ssize_t)len) {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief Receives a protocol-compliant packet with timeout and size safety.
 */
int cmd_transport_recv(int fd, afuinx_header_t *hdr, char **payload) {
    /* Set receive timeout to prevent infinite blocking */
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Receive Header */
    if (recv(fd, hdr, sizeof(*hdr), MSG_WAITALL) != sizeof(*hdr)) return -1;
    if (hdr->magic != AFUINX_MAGIC) return -1;

    /* Receive Payload */
    if (hdr->length > 0) {
        /* Security check: restrict allocation to prevent OOM attacks */
        if (hdr->length > MAX_RESP_BUF) return -1;

        *payload = calloc(1, hdr->length + 1);
        if (!*payload) return -1;

        if (recv(fd, *payload, hdr->length, MSG_WAITALL) != (ssize_t)hdr->length) {
            free(*payload);
            *payload = NULL;
            return -1;
        }
    } else {
        *payload = NULL;
    }
    return 0;
}

/**
 * @brief Dispatches command based on a provided command table.
 * @param table Command registry provided by the business layer.
 * @param ctx   Arbitrary context data passed to the handler.
 */
int cmd_dispatch(void *ctx, char *input, char *output, size_t max_len) {
    if (!g_table || !input || !output || max_len == 0) return -1;

    int argc = 0;
    char *argv[MAX_ARG_COUNT];
    cmd_resp_t resp = { .buf = output, .size = max_len, .offset = 0 };

    if (parse_args(input, &argc, argv) != 0) {
        cmd_resp_red(&resp, "ERR: Unbalanced quotes in command line");
        return -1;
    }

    if (argc == 0) return -1;

    /* Search the table for a matching command name */
    for (int i = 0; g_table[i].name != NULL; i++) {
        if (strcasecmp(argv[0], g_table[i].name) == 0) {
            /* Ensure the handler is NOT NULL before proceeding */
            if (g_table[i].handler == NULL) {
                cmd_resp_red(&resp, "ERR: Command '%s' has no executor. "
                                      "Try 'HELP %s' for details.", 
                                      g_table[i].name, g_table[i].name);
                return 0; /* Handled gracefully, not a system error */
            }

            /* Minimum Argument Validation */
            if (argc < g_table[i].min_argc) {
                cmd_resp_red(&resp, "ERR: Usage: %s %s", 
                                g_table[i].name, g_table[i].usage);
                return 0;
            }
            /* Invoke Business Logic */
            return g_table[i].handler(ctx, argc, argv, &resp);
        }
    }

    cmd_resp_red(&resp, "ERR: Unknown command '%.32s'", argv[0]);
    return -1;
}

void cmd_register_table(const cmd_entry_t *table) {
    g_table = table;
}

/**
 * @brief Formatted print to the response buffer with overflow protection.
 */
void cmd_resp_printf(cmd_resp_t *r, const char *fmt, ...) {
    if (!r || !r->buf || r->offset >= r->size) return;

    va_list ap;
    va_start(ap, fmt);
    int available = (int)(r->size - r->offset);
    int written = vsnprintf(r->buf + r->offset, available, fmt, ap);
    va_end(ap);

    if (written > 0) {
        r->offset += (written < available) ? written : (available - 1);
    }
}

/**
 * @brief Standard buffered printf wrapper with absolute boundary protection.
 * Dedicated for internal use to ensure consistency.
 */
static void cmd_resp_printf_internal(cmd_resp_t *r, const char *fmt, va_list ap) {
    /* 1. Strict guard: ensure buffer exists and has at least 1 byte for '\0' */
    if (!r || !r->buf || r->size == 0 || r->offset >= (r->size - 1)) {
        return;
    }

    size_t available = r->size - r->offset;
    char *target = r->buf + r->offset;

    /* 2. Using va_copy to protect the original va_list state (Architectural Safety) */
    va_list aq;
    va_copy(aq, ap);
    int n = vsnprintf(target, available, fmt, aq);
    va_end(aq);

    /* 3. Handle return value safely */
    if (n > 0) {
        size_t written = (size_t)n;
        /* If truncated, written must not exceed (available - 1) */
        if (written >= available) {
            written = available - 1;
        }
        r->offset += written;
        /* Double check to ensure NULL termination at the new end */
        r->buf[r->offset] = '\0';
    }
}

/**
 * @brief Thread-safe (per-resp) primitive for raw string appending.
 */
static void cmd_resp_print_raw(cmd_resp_t *r, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    cmd_resp_printf_internal(r, fmt, ap);
    va_end(ap);
}

/**
 * @brief Specialized color wrapper: RED
 * Uses multi-stage atomic-like writes to prevent stack-based buffer overflows.
 */
void cmd_resp_red(cmd_resp_t *r, const char *fmt, ...) {
    if (!r || !fmt) return;

    /* Stage 1: Escape sequence prefix */
    cmd_resp_print_raw(r, "%s", C_RED);

    /* Stage 2: Formatted message */
    va_list ap;
    va_start(ap, fmt);
    cmd_resp_printf_internal(r, fmt, ap);
    va_end(ap);

    /* Stage 3: Reset sequence suffix */
    cmd_resp_print_raw(r, "%s", C_RESET);
}

/**
 * @brief Specialized color wrapper: GREEN
 */
void cmd_resp_green(cmd_resp_t *r, const char *fmt, ...) {
    if (!r || !fmt) return;

    cmd_resp_print_raw(r, "%s", C_GREEN);

    va_list ap;
    va_start(ap, fmt);
    cmd_resp_printf_internal(r, fmt, ap);
    va_end(ap);

    cmd_resp_print_raw(r, "%s", C_RESET);
}

void cmd_resp_cyan(cmd_resp_t *r, const char *fmt, ...) {
    if (!r || !fmt) return;

    cmd_resp_print_raw(r, "%s", C_CYAN);

    va_list ap;
    va_start(ap, fmt);
    cmd_resp_printf_internal(r, fmt, ap);
    va_end(ap);

    cmd_resp_print_raw(r, "%s", C_RESET);
}

/**
 * @brief Generates a strictly aligned, tabular help message for command groups.
 * * Features:
 * - Dynamic Usage construction with parent-child command prefixing.
 * - Three-column vertical alignment (Command, Description/Sub, Usage).
 * - Context-aware formatting for both global and group-specific help.
 * @param group  The command group to filter (e.g., "SET"). If NULL, shows the global menu.
 * @param resp   Pointer to the response buffer context.
 * @return int   0 on success, -1 if the group/command was not found.
 */
int cmd_group_help(const char *group, cmd_resp_t *resp) {
    if (!g_table || !resp) return -1;

    /* Fixed column widths to ensure perfect vertical alignment across all rows */
    const int COL1_WIDTH = 15;  /* Command / Primary Column */
    const int COL2_WIDTH = 30;  /* Description / Sub-command Column */
    
    bool found_any = false;

    /* --- Header Section --- */
    if (group) {
        /* Header ensures the alignment baseline is clear for group-specific help */
        cmd_resp_printf(resp, "\n"C_GRAY "%-*s %-*s %s [ Group: %s ]" C_RESET "\n\n", 
                        COL1_WIDTH, "SUB-COMMAND", COL2_WIDTH, "DESCRIPTION", "USAGE", group);
    } else {
        cmd_resp_printf(resp, C_GRAY "\n%-*s %-*s %s" C_RESET "\n\n", 
                        COL1_WIDTH, "COMMAND", COL2_WIDTH, "DESCRIPTION / SUB", "USAGE");
    }

    for (int i = 0; g_table[i].name != NULL; i++) {
        bool match = false;
        
        /* Filter logic: Match root commands (group=NULL) or specific group members */
        if (group == NULL) {
            if (g_table[i].group == NULL) match = true;
        } else {
            if (g_table[i].group != NULL && strcasecmp(g_table[i].group, group) == 0) match = true;
        }

        if (match) {
            found_any = true;
            
            /* --- Construct Unified Usage String (Prepends group if applicable) --- */
            char usage_str[128];
            if (g_table[i].group) {
                snprintf(usage_str, sizeof(usage_str), "(Usage: %s %s %s)", 
                         g_table[i].group, g_table[i].name, g_table[i].usage ? g_table[i].usage : "");
            } else {
                snprintf(usage_str, sizeof(usage_str), "(Usage: %s %s)", 
                         g_table[i].name, g_table[i].usage ? g_table[i].usage : "");
            }

            /* --- STEP 1: Print Primary Matched Row --- */
            /* Using %-*s ensures the third column (Usage) starts at the exact same vertical position */
            cmd_resp_green(resp, "%-*s %-*s %s\n",
                            COL1_WIDTH, g_table[i].name,
                            COL2_WIDTH, g_table[i].help ? g_table[i].help : "",
                            usage_str);

            /* --- STEP 2: Cascading Sub-commands (Only triggered for global HELP) --- */
            if (group == NULL) {
                for (int j = 0; g_table[j].name != NULL; j++) {
                    if (g_table[j].group != NULL && strcasecmp(g_table[j].group, g_table[i].name) == 0) {
                        
                        /* Format sub-command with a visual marker for hierarchy */
                        char sub_name_fmt[64];
                        snprintf(sub_name_fmt, sizeof(sub_name_fmt), "  > %s", g_table[j].name);

                        char sub_usage[128];
                        snprintf(sub_usage, sizeof(sub_usage), "(Usage: %s %s %s)", 
                                 g_table[j].group, g_table[j].name, g_table[j].usage ? g_table[j].usage : "");

                        /* * Alignment Strategy for Sub-commands:
                         * - Col 1: Empty.
                         * - Col 2: Sub-command name.
                         * - Col 3: Sub-command usage.
                         */
                        cmd_resp_cyan(resp, "%-*s %-*s %s\n",
                                        COL1_WIDTH, "",            
                                        COL2_WIDTH, sub_name_fmt,   
                                        sub_usage);
                    }
                }
            }
        }
    }

    if (!found_any) {
        if (group) {
            cmd_resp_red(resp, "ERR: Unknown group or command '%s'.\n", group);
        }
        return -1;
    }

    return 0;
}

int cmd_handle_help(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    (void)ctx;

    if (argc > 1) {
        /* Scenario: "HELP SET" -> Show all commands in the SET group */
        cmd_group_help(argv[1], resp);
    } else {
        /* Scenario: "HELP" -> Show only root commands */
        cmd_group_help(NULL, resp);
    }
    return 0;
}

/**
 * @brief Internal routine to handle the server lifecycle.
 */
static void *cmd_server_worker(void *arg) {
    cmd_server_args_t *args = (cmd_server_args_t *)arg;
    void *user_ctx = args->user_ctx;
    
    /* Clean up argument container immediately after extraction */
    free(args);

    /* Initialize the transport layer (Listen) */
    int lfd = cmd_transport_listen(SOCKET_PATH);
    if (lfd < 0) {
        log_error("[MGMT] Fatal: Failed to initialize listener on %s: %s", 
                SOCKET_PATH, strerror(errno));
        return NULL;
    }

    log_info("[MGMT] Server thread started. Port: %s", SOCKET_PATH);

    while (atomic_load(&g_server_running)) {

        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            /* Case 1: Interrupted by a signal (e.g., SIGUSR1 for wake-up). 
             * Just restart the system call to keep the loop alive. */
            if (errno == EINTR) {
                continue;
            }

            /* Case 2: Process/System-wide file descriptor limit reached.
             * Instead of crashing, wait 1s for other tasks to release handles. */
            if (errno == EMFILE || errno == ENFILE) {
                log_error("[MGMT] Accept failed: Out of file descriptors. Retrying...");
                sleep(1); 
                continue;
            }

            /* Case 3: Fatal error (e.g., EBADF - lfd is invalid/closed).
             * Unrecoverable state; terminate the thread to prevent log flooding. */
            log_error("[MGMT] Accept fatal error: %s. Thread exiting...", strerror(errno));
            break;
        }

        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

        /* Set a receive timeout to prevent hung CLI connections from blocking the thread */
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        afuinx_header_t hdr;
        char *payload = NULL;

        /* Protocol exchange: Receive command */
        if (cmd_transport_recv(cfd, &hdr, &payload) == 0) {
            char resp_buf[MAX_RESP_BUF] = {0};
            
            /* Dispatch to the registered business logic */
            if (g_table) {
                cmd_dispatch(user_ctx, payload, resp_buf, sizeof(resp_buf));
            } else {
                snprintf(resp_buf, sizeof(resp_buf), "ERR: Command table not registered.");
            }

            /* Protocol exchange: Send response */
            cmd_transport_send(cfd, 1, resp_buf, (uint32_t)strlen(resp_buf));
            
            if (payload) free(payload);
        }

        close(cfd);
    }

    close(lfd);
    return NULL;
}

pthread_t cmd_server_start(void *user_ctx) {
    pthread_t tid;
    cmd_server_args_t *args = malloc(sizeof(cmd_server_args_t));
    
    if (!args) {
        log_error("[MGMT] Failed to allocate thread arguments");
        return 0;
    }

    args->user_ctx = user_ctx;
    atomic_store(&g_server_running, true);
    /* Create the thread */
    int rc = pthread_create(&tid, NULL, cmd_server_worker, args);
    if (rc != 0) {
        log_error("[MGMT] Thread creation failed: %s\n", strerror(rc));
        free(args);
        return 0;
    }
    
    return tid;
}

/**
 * @brief Gracefully terminates the CLI server thread.
 * @param ptid Pointer to the thread ID to be joined and reset.
 */
void cmd_server_stop(pthread_t *ptid) {
    /* Step 1: Defensive check. Do nothing if the pointer is NULL or thread is already stopped. */
    if (!ptid || *ptid == 0) {
        return;
    }

    /* Step 2: Signal the worker thread to exit its main loop via an atomic flag. */
    atomic_store(&g_server_running, false);

    /* Step 3: Send a cancellation request to the thread. 
     * This forces the thread to wake up from blocking calls like accept(). */
    pthread_cancel(*ptid);

    /* Step 4: Block until the thread terminates to reclaim its resources (stack, TCB). 
     * This prevents "zombie threads" from leaking system memory. */
    pthread_join(*ptid, NULL);
    *ptid = 0;

    log_info("[MGMT] CLI Server stopped gracefully and resources reclaimed.");
}