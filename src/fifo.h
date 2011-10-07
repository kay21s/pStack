#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <inttypes.h>
#include <string.h>
#include <stdint.h>

#include "fifo_common.h"

#define CONS_BATCH
#define PROD_BATCH
#define AVOID_DEADLOCK


typedef struct{
                char * data;
                uint32_t len;
} FIFO_ELEM;

#define FIFO_ELEM_DATA(p)       ((p)->data)
#define FIFO_ELEM_SIZE(p)       ((p)->len)


#define FREQ 1.0	/* in cycle numbers */
// 2600017445

#define TEST_SIZE 200000000

#define INSERT_FAILED   -1
#define EXTRACT_FAILED  -2
#define SUCCESS         0
/****** Should be 2^N *****/

#define MAX_CORE_NUM 8

#define CONS_WORK_CYCLES 0
#define PROD_WORK_CYCLES 0

#define BATCH_SIZE (128)
#define CONS_BATCH_SIZE BATCH_SIZE
#define PROD_BATCH_SIZE BATCH_SIZE
#define QUEUE_SIZE 1024
/***************************/

#define PROBAB (0)
#define PROBAB_MEMCPY 0
#define MEM_LEN (0)
#define PROBAB_MALLOC 0
#define PROBAB_YIELD 0
#define PROBAB_LOCK 0
#define PROBAB_WORKLOAD 10
#define WORKLOAD (40)
#define AVG_WORKLOAD (0) // for 10, 1024, 2000 

#define ELEMENT_TYPE FIFO_ELEM

#define PADDING 128
#define PAD(suffix, type) char padding ## suffix [PADDING - sizeof(type)]
#define PAD_2(suffix, type_1, type_2) char padding ## suffix [PADDING - sizeof(type_1) - sizeof(type_2)]
#define PAD_3(suffix, type_1, type_2, type_3) char padding ## suffix \
             [PADDING - sizeof(type_1) - sizeof(type_2) - sizeof(type_3)]
#define PAD_4(suffix, type_1, type_2, type_3, type_4) char padding ## suffix \
             [PADDING-sizeof(type_1)-sizeof(type_2)-sizeof(type_3)-sizeof(type_4)]

#if defined(CONS_BATCH)  || defined(PROD_BATCH)

typedef struct {
	ELEMENT_TYPE 	volatile *head;
	ELEMENT_TYPE	volatile *batch_head;
	PAD_2	(1, ELEMENT_TYPE, ELEMENT_TYPE);
	ELEMENT_TYPE	volatile *tail;
	ELEMENT_TYPE	volatile *batch_tail;
	PAD_2	(2, ELEMENT_TYPE, ELEMENT_TYPE);
	uint64_t	start_c;
	uint64_t	stop_c;
	ELEMENT_TYPE	* head_orig; /* read only */
	ELEMENT_TYPE	* tail_orig; /* read only */
	PAD_4(3, uint64_t, uint64_t, ELEMENT_TYPE *, ELEMENT_TYPE*);
	ELEMENT_TYPE	data[QUEUE_SIZE];
}queue_t  __attribute__ ((aligned(128)));

#else

typedef struct {
	ELEMENT_TYPE	volatile *head;
	PAD           (1, ELEMENT_TYPE);
	ELEMENT_TYPE	volatile *tail;
	PAD           (2, ELEMENT_TYPE);
	uint64_t	start_c;
	uint64_t	stop_c;
	ELEMENT_TYPE	* head_orig; /* read only */
	ELEMENT_TYPE	* tail_orig; /* read only */
	PAD_4(3, uint64_t, uint64_t, ELEMENT_TYPE *, ELEMENT_TYPE *);
	ELEMENT_TYPE	data[QUEUE_SIZE];
}queue_t  __attribute__ ((aligned(128)));

#endif

#define FIFO_BUFFER ELEMENT_TYPE

queue_t global_queue[MAX_CORE_NUM];

#define QUEUE(p)	(global_queue[p])
#define QUEUE_PTR(p)	(&global_queue[p])
#define QUEUE_START(p)	(global_queue[p].start_c)
#define QUEUE_STOP(p)	(global_queue[p].stop_c)
#define QUEUE_HEAD(p)	(global_queue[p].head)
#define QUEUE_BATCH_HEAD(p)	(global_queue[p].batch_head)
#define QUEUE_TAIL(p)	(global_queue[p].tail)
#define QUEUE_BATCH_TAIL(p)	(global_queue[p].batch_tail)

#define QUEUE_HEAD_ORIG(p)	(global_queue[p].head_orig)
#define QUEUE_TAIL_ORIG(p)	(global_queue[p].tail_orig)

#define QUEUE_HEAD_VAL(p)	(*global_queue[p].head)
#define QUEUE_TAIL_VAL(p)	(*global_queue[p].tail)
#define QUEUE_DATA(p, i)	(global_queue[p].data[i])
#define QUEUE_DATA_PTR(p, i)	(&(global_queue[p].data[i]))

#define QUEUE_PTR_START(p)	(p->start_c)
#define QUEUE_PTR_STOP(p)	(p->stop_c)
#define QUEUE_PTR_HEAD(p)	(p->head)
#define QUEUE_PTR_TAIL(p)	(p->tail)
#define QUEUE_PTR_HEAD_ORIG(p)	(p->head_orig)
#define QUEUE_PTR_TAIL_ORIG(p)	(p->tail_orig)
#define QUEUE_PTR_HEAD_VAL(p)	(*(p->head))
#define QUEUE_PTR_TAIL_VAL(p)	(*(p->tail))
#define QUEUE_PTR_DATA(p, i)	(p->data[i])
#define QUEUE_PTR_DATA_PTR(p, i)	(&(p->data[i]))

typedef struct {
	uint32_t	cpu_id;
	pthread_barrier_t * barrier;
} INIT_INFO;


#define INIT_ID(p)	(init_info[p].cpu_id)
#define INIT_BAR(p)	(init_info[p].barrier)
#define INIT_PTR(p)	(&init_info[p])

void * consumer(void *);
void   producer(void *, uint32_t);
inline int insert_hpq(queue_t *, ELEMENT_TYPE);
inline int extract_hpq(queue_t *, ELEMENT_TYPE *);
