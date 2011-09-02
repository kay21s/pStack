#ifndef BITMAP_H
#define BITMAP_H

#include "conn_attribute.h"
#include "parallel.h"

idx_type get_free_index(TCP_THREAD_LOCAL_P);
void ret_free_index(idx_type, TCP_THREAD_LOCAL_P);
void init_bitmap(TCP_THREAD_LOCAL_P, int);

#endif
