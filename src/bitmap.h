#ifndef BITMAP_H
#define BITMAP_H

#include "conn_tcp.h"

#define MAX_STREAM (1 << 20)

idx_type get_free_index(void);
void ret_free_index(idx_type);
void init_bitmap(void);

#endif
