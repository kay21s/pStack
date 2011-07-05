/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#include <config.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(PARALLEL)
#include "tcp.threaded.h"
#else
#include "tcp.h"
#endif
#include "util.h"
#include "nids.h"

u_int compute_time(struct timeval *t1, struct timeval *t2)
{
	u_int total_t;

	if (t1->tv_usec > t2->tv_usec) {
		t2->tv_usec += 1000000;
		t2->tv_sec--;
	}

	total_t = (t2->tv_sec-t1->tv_sec)*1000000 + (t2->tv_usec - t1->tv_usec);

	return total_t;
}

void
nids_no_mem(char *func)
{
  fprintf(stderr, "Out of memory in %s.\n", func);
  exit(1);
}

char *
test_malloc(int x)
{
  char *ret = malloc(x);
  
  if (!ret)
    nids_params.no_mem("test_malloc");

  return ret;
}

void
register_callback(struct proc_node **procs, void (*x))
{
  struct proc_node *ipp;

  for (ipp = *procs; ipp; ipp = ipp->next)
    if (x == ipp->item)
      return;
  ipp = mknew(struct proc_node);
  ipp->item = x;
  ipp->next = *procs;
  *procs = ipp;
}

void
unregister_callback(struct proc_node **procs, void (*x))
{
  struct proc_node *ipp;
  struct proc_node *ipp_prev = 0;

  for (ipp = *procs; ipp; ipp = ipp->next) {
    if (x == ipp->item) {
      if (ipp_prev)
	ipp_prev->next = ipp->next;
      else
	*procs = ipp->next;
      free(ipp);
      return;
    }
    ipp_prev = ipp;
  }
}
