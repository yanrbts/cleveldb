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

#define L_CYAN    "\033[36m"
#define L_GREEN   "\033[32m"
#define L_BLUE    "\033[34m"
#define L_RESET   "\033[0m"

static const char *g_banners[] = {
    /* Logo 1: Standard Style */
    L_CYAN
    "────╔═╗\n"
    "────║╔╝\n"
    "╔╗╔╦╝╚╦══╦══╦═╦╗╔╦══╦═╗\n"
    "║╚╝╠╗╔╣══╣║═╣╔╣╚╝║║═╣╔╝\n"
    "╚╗╔╝║║╠══║║═╣║╚╗╔╣║═╣║\n"
    "─╚╝─╚╝╚══╩══╩╝─╚╝╚══╩╝\n"
    L_RESET,

    /* Logo 2: Slant Style */
    L_GREEN
    "    _   __________   _____ ______\n"
    "   | | / / ____/ /  / ___//_  __/\n"
    "   | |/ / /_  / /   \\__ \\  / /   \n"
    "   |  / / __// /______/ / / /    \n"
    "   |_/_/    /_____/____/ /_/     \n"
    L_RESET,

    /* Logo 3: Block Style */
    L_BLUE
    " __   __  _______  _______  _______  _______ \n"
    "|  | |  ||       ||   _   ||       ||       |\n"
    "|  |_|  ||    ___||  |_|  ||  _____||_     _|\n"
    "|       ||   |___ |       || |_____   |   |  \n"
    "|       ||    ___||       ||_____  |  |   |  \n"
    " |     | |   |    |   _   | _____| |  |   |  \n"
    "  |___|  |___|    |__| |__||_______|  |___|  \n"
    L_RESET
};

#define BANNER_COUNT (sizeof(g_banners) / sizeof(g_banners[0]))

static inline void vf_show_random_banner(void) {
    srand((unsigned int)time(NULL));
    int index = rand() % BANNER_COUNT;

    printf("%s\n", g_banners[index]);

    printf("  " L_GREEN "Core Engine" L_RESET " : VFAST Gateway v2.1\n");
    printf("  " L_GREEN "Status     " L_RESET " : Initializing Shards...\n");
}

#endif