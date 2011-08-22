/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _ULCC_MMCLIENT_H_
#define _ULCC_MMCLIENT_H_

#define MAX_PAGES_PER_LOOP		4096
#define MIN_PAGES_PER_LOOP		256

void _ULCC_HIDDEN _new_sem_name(char *name, unsigned int rnd_seed);

int _ULCC_HIDDEN use_memmgr(const int c_colors, const int c_pages_per_color);
int _ULCC_HIDDEN max_pick_loops(const int c_pages, const int c_colors);
int _ULCC_HIDDEN next_pages_per_loop(const int color, const int pages);

int _ULCC_HIDDEN cc_mmclient_init(void);
void _ULCC_HIDDEN cc_mmclient_fini(void);

int _ULCC_HIDDEN mm_free_pages_open(void);
void _ULCC_HIDDEN mm_free_pages_close(void);
int _ULCC_HIDDEN mm_free_pages_lock(void);
int _ULCC_HIDDEN mm_free_pages_unlock(void);

/* request pages in a specific color */
#ifdef _ULCC_CONFIG_KMODULE_PAGEPIPE
int _ULCC_HIDDEN cc_mm_sndreq(const int color, const int pages,
	const unsigned long pipeid, const unsigned long key);
#else
int _ULCC_HIDDEN cc_mm_sndreq(const int color, const int pages);
#endif

#endif
