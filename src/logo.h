/*
 * Copyright (c) 2026-2026, cleveldb.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __LOGO_H__
#define __LOGO_H__

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

#define L_CYAN    "\033[36m"
#define L_GREEN   "\033[32m"
#define L_BLUE    "\033[34m"
#define L_YELLOW  "\033[33m"
#define L_MAGENTA "\033[35m"
#define L_WHITE   "\033[37m"
#define L_RESET   "\033[0m"

static const char *g_server_banners[] = {
    /* Logo 1: (Standard) */
    L_CYAN
    "  ────╔═╗\n"
    "  ────║╔╝\n"
    "  ╔╗╔╦╝╚╦══╦══╦═╦╗╔╦══╦═╗\n"
    "  ║╚╝╠╗╔╣══╣║═╣╔╣╚╝║║═╣╔╝\n"
    "  ╚╗╔╝║║╠══║║═╣║╚╗╔╣║═╣║\n"
    "  ─╚╝─╚╝╚══╩══╩╝─╚╝╚══╩╝\n"
    L_RESET,

    /* Logo 2: (Bold Block) */
    L_YELLOW
    "  ╋╋╋╋┏━┓\n"
    "  ╋╋╋╋┃┏┛\n"
    "  ┏┓┏┳┛┗┳━━┳━━┳━┳┓┏┳━━┳━┓\n"
    "  ┃┗┛┣┓┏┫━━┫┃━┫┏┫┗┛┃┃━┫┏┛\n"
    "  ┗┓┏┛┃┃┣━━┃┃━┫┃┗┓┏┫┃━┫┃\n"
    "  ╋┗┛╋┗┛┗━━┻━━┻┛╋┗┛┗━━┻┛\n"
    L_RESET,

    /* Logo 3: (Round Slant) */
    L_MAGENTA
    "  ╱╱╱╱╭━┳━╮\n"
    "  ╭━┳━┫━┫━╋━┳┳┳━┳━┳━┳┳╮\n"
    "  ╰╮┃╭┫╭╋━┃┻┫╭┻╮┃╭┫┻┫╭╯\n"
    "  ╱╰━╯╰╯╰━┻━┻╯╱╰━╯╰━┻╯\n"
    L_RESET,

    /* Logo 4: (Bold Slant) */
    L_GREEN
    "  ╋╋╋╋┏━┳━┓\n"
    "  ┏━┳━┫━┫━╋━┳┳┳━┳━┳━┳┳┓\n"
    "  ┗┓┃┏┫┏╋━┃┻┫┏┻┓┃┏┫┻┫┏┛\n"
    "  ╋┗━┛┗┛┗━┻━┻┛╋┗━┛┗━┻┛\n"
    L_RESET,

    /* Logo 5: (Thin Slant) */
    L_WHITE
    "  ────╔═╦═╗\n"
    "  ╔═╦═╣═╣═╬═╦╦╦═╦═╦═╦╦╗\n"
    "  ╚╗║╔╣╔╬═║╩╣╔╩╗║╔╣╩╣╔╝\n"
    "  ─╚═╝╚╝╚═╩═╩╝─╚═╝╚═╩╝\n"
    L_RESET
};

/* --- Client Banners --- */
static const char *g_client_banners[] = {
    /* Logo 1: V-CLIENT (Bold Block with Plus) */
    L_YELLOW
    "  ╋╋╋╋┏━┓╋╋┏┓╋╋╋╋╋╋╋┏┓\n"
    "  ╋╋╋╋┃┏┛╋╋┃┃╋╋╋╋╋╋┏┛┗┓\n"
    "  ┏┓┏┳┛┗┳━━┫┃┏┳━━┳━╋┓┏┛\n"
    "  ┃┗┛┣┓┏┫┏━┫┃┣┫┃━┫┏┓┫┃\n"
    "  ┗┓┏┛┃┃┃┗━┫┗┫┃┃━┫┃┃┃┗┓\n"
    "  ╋┗┛╋┗┛┗━━┻━┻┻━━┻┛┗┻━┛\n"
    L_RESET,

    /* Logo 2: vfclient (Round Slant) */
    L_MAGENTA
    "  ╱╱╱╱╭━╮╱╱╱╭╮╱╱╱╱╭╮\n"
    "  ╭━┳━┫━╋━┳╮┣╋━┳━┳┫╰╮\n"
    "  ╰╮┃╭┫╭┫━┫╰┫┃┻┫┃┃┃╭┫\n"
    "  ╱╰━╯╰╯╰━┻━┻┻━┻┻━┻━╯\n"
    L_RESET,

    /* Logo 3: vfclient (Bold Slant) */
    L_GREEN
    "  ╋╋╋╋┏━┓╋╋╋┏┓╋╋╋╋┏┓\n"
    "  ┏━┳━┫━╋━┳┓┣╋━┳━┳┫┗┓\n"
    "  ┗┓┃┏┫┏┫━┫┗┫┃┻┫┃┃┃┏┫\n"
    "  ╋┗━┛┗┛┗━┻━┻┻━┻┻━┻━┛\n"
    L_RESET,

    /* Logo 4: vfclient (Thin Slant) */
    L_WHITE
    "  ────╔═╗───╔╗────╔╗\n"
    "  ╔═╦═╣═╬═╦╗╠╬═╦═╦╣╚╗\n"
    "  ╚╗║╔╣╔╣═╣╚╣║╩╣║║║╔╣\n"
    "  ─╚═╝╚╝╚═╩═╩╩═╩╩═╩═╝\n"
    L_RESET,
    
    /* Logo 5: V-CLIENT (Standard) */
    L_BLUE
    "  ────╔═╗──╔╗───────╔╗\n"
    "  ────║╔╝──║║──────╔╝╚╗\n"
    "  ╔╗╔╦╝╚╦══╣║╔╦══╦═╬╗╔╝\n"
    "  ║╚╝╠╗╔╣╔═╣║╠╣║═╣╔╗╣║\n"
    "  ╚╗╔╝║║║╚═╣╚╣║║═╣║║║╚╗\n"
    "  ─╚╝─╚╝╚══╩═╩╩══╩╝╚╩═╝\n"
    L_RESET
};

#define SERVER_BANNER_COUNT (sizeof(g_server_banners) / sizeof(g_server_banners[0]))
#define CLIENT_BANNER_COUNT (sizeof(g_client_banners) / sizeof(g_client_banners[0]))

/**
 * @brief  Displays a randomized ASCII logo followed by system metadata.
 * @param  is_server Boolean flag: true for server-side metadata, false for client-side.
 * @param  version   Software version string (e.g., "v2.1.0").
 * @param  author    Developer or team name.
 * @param  address   Network binding IP or Gateway endpoint.
 */
static inline void vf_show_random_banner(bool is_server, const char *version, const char *author, const char *address) {
    /* Initialize random seed using current epoch time */
    srand((unsigned int)time(NULL));

    const char **pool = is_server ? g_server_banners : g_client_banners;
    int pool_size = is_server ? SERVER_BANNER_COUNT : CLIENT_BANNER_COUNT;

    /* Output Randomized Logo */
    if (pool_size > 0) {
        int idx = rand() % pool_size;
        printf("\n%s\n\n", pool[idx]);
    }

    /* Output System Metadata with consistent columnar padding */
    printf("  " L_GREEN "%-15s" L_RESET " : %s%s%s\n", 
           "Application", L_YELLOW, is_server ? "VFAST Server Engine" : "VFAST Client Portal", L_RESET);

    printf("  " L_GREEN "%-15s" L_RESET " : %s%s%s\n", 
           "Version", L_YELLOW, version ? version : "N/A", L_RESET);

    printf("  " L_GREEN "%-15s" L_RESET " : %s%s%s\n", 
           "Author", L_YELLOW, author ? author : "N/A", L_RESET);

    /* Dynamic label based on operational role */
    printf("  " L_GREEN "%-15s" L_RESET " : %s%s%s\n", 
           is_server ? "TUN Addr" : "Server IP", L_YELLOW, address ? address : "0.0.0.0", L_RESET);

    printf("  " L_GREEN "%-15s" L_RESET " : %s%s%s\n", 
           "System Status", L_YELLOW, is_server ? "Initializing Shards..." : "Establishing Tunnel...", L_RESET);

    printf("\n");
}

#endif