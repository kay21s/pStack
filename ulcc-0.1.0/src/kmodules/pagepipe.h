/*
 * Copyright (C) 2011 Xiaoning Ding, Kaibo Wang, Xiaodong Zhang
 *
 * This file is part of ULCC (User Level Cache Control) utility. ULCC is free
 * software: you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation.
 * Read the file COPYING for details of GNU GPL.
 */

#ifndef _PAGEPIPE_H
#define _PAGEPIPE_H
#include <linux/ioctl.h>

#define MAJOR_NUM 101
#define DEVICE_FILE_NAME "pagepipe"
#define DEVICE_NAME "pagepipe"
#define IOCTL_SETUP_PIPE _IOWR(MAJOR_NUM, 0, unsigned long)
#define IOCTL_NUM_UNUSEDPAGES _IOR(MAJOR_NUM, 1, unsigned long)

#endif
