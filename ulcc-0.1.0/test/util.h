/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _ULCC_UTIL_H_
#define _ULCC_UTIL_H_

/* Data set operations */
cc_dataset_t _ULCC_EXPORT *cc_dataset_new(const int max);
int _ULCC_EXPORT cc_dataset_add(cc_dataset_t *dst, const unsigned long start,
	const unsigned long end);
int _ULCC_EXPORT cc_dataset_add2(cc_dataset_t *dst, const cc_dataset_t *dst2);
void _ULCC_EXPORT cc_dataset_clr(cc_dataset_t *dst);
void _ULCC_EXPORT cc_dataset_free(cc_dataset_t *dst);

/* Thread set operations */
cc_thrdset_t _ULCC_EXPORT *cc_thrdset_new(int max);
int _ULCC_EXPORT cc_thrdset_add(cc_thrdset_t *tst, const cc_tid_t *threads,
	const int n);
void _ULCC_EXPORT cc_thrdset_free(cc_thrdset_t *tst);

/* CPU set operations */
int _ULCC_EXPORT cc_cpuset_proc(cc_cpuset_t *cst, const pid_t pid);
int _ULCC_EXPORT cc_cpuset_add(cc_cpuset_t *cst, const cc_cid_t *cpus,
	const int n);
int _ULCC_EXPORT cc_cpuset_from_thrdset(cc_cpuset_t *cst,
	const cc_thrdset_t *tst);
int _ULCC_EXPORT cc_cpuset_count(const cc_cpuset_t *cst);

/* Misc */
int _ULCC_EXPORT cc_cache_size(void);
int _ULCC_EXPORT cc_cache_colors(void);

#endif
