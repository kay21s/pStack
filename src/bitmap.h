#ifndef BITMAP_H
#define BITMAP_H

#include "conn_attribute.h"

idx_type get_free_index(void);
void ret_free_index(idx_type);
void init_bitmap(void);

#endif
