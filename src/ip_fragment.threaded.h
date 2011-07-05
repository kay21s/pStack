/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@icm.edu.pl>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_IP_FRAGMENT_H
#define _NIDS_IP_FRAGMENT_H

#define IPF_NOTF 1
#define IPF_NEW  2
#define IPF_ISF  3

#include "parallel.h"

void ip_frag_init(int,IP_THREAD_LOCAL_P );
void ip_frag_exit(IP_THREAD_LOCAL_P );
int ip_defrag_stub(struct ip *, struct ip **,IP_THREAD_LOCAL_P );

#endif /* _NIDS_IP_FRAGMENT_H */
