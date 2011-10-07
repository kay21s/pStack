#include "fifo.h"
#include <sched.h>

#if defined(FIFO_DEBUG)
#include <assert.h>
#endif

/*************************************************/
/********** Queue Functions **********************/
/*************************************************/

inline void wait_ticks(uint64_t ticks)
{
        uint64_t        current_time;
        uint64_t        time = read_tsc();
        time += ticks;
        do {
                current_time = read_tsc();
        } while (current_time < time);
}

/* ADJUST_SLIP is the original mechanism in Fastforward */
#if defined(ADJUST_SLIP)

#define DANGER 16
#define GOOD 64
#define AVG_STAGE 10

inline uint32_t
distance(ELEMENT_TYPE volatile *tail, ELEMENT_TYPE volatile *head)
{
	return (tail > head)?
	       (tail - head) : (tail + QUEUE_SIZE - head);
}

inline void
adjust_slip(queue_t * queue)
{
	/* Does distance() incur extra cache-coherence traffic? */
	uint32_t dist_old, dist = distance(queue->tail, queue->head);

	if ( dist < DANGER ) {
		dist_old = 0;
		do {
			dist_old = dist;
			wait_ticks( AVG_STAGE * ((GOOD+1) - dist) );
			dist = distance(queue->tail, queue->head);
		} while (dist < GOOD && dist_old < dist);
	}
}

#endif /* ADJUST_SLIP */

//void queue_init(uint32_t num)
void fifo_init(uint32_t num)
{
	memset(QUEUE_PTR(num), 0, sizeof(queue_t));
	QUEUE_HEAD(num) = QUEUE_DATA_PTR(num, 0);
	QUEUE_TAIL(num) = QUEUE_DATA_PTR(num, 0);
#if defined(PROD_BATCH) || defined(CONS_BATCH)
	QUEUE_BATCH_HEAD(num) = QUEUE_HEAD(num);
	QUEUE_BATCH_TAIL(num) = QUEUE_TAIL(num);
#endif

	QUEUE_HEAD_ORIG(num) = QUEUE_DATA_PTR(num, 0);
	QUEUE_TAIL_ORIG(num) = QUEUE_DATA_PTR(num, QUEUE_SIZE);
	
}

#if defined(PROD_BATCH) || defined(CONS_BATCH)
inline int leqthan(ELEMENT_TYPE volatile * point, ELEMENT_TYPE volatile * batch_point)
{
	return (point == batch_point);
}
#endif

#if defined(PROD_BATCH)
inline void produce(queue_t * q, ELEMENT_TYPE value)
{
	if( leqthan(q->tail, q->batch_tail) ) {
		q->batch_tail = q->tail + PROD_BATCH_SIZE;
		if (q->batch_tail >= QUEUE_PTR_TAIL_ORIG(q))
			q->batch_tail = QUEUE_PTR_HEAD_ORIG(q);

		while ((*q->batch_tail).data)
			wait_ticks(20000);
	}
	QUEUE_PTR_TAIL_VAL(q) = value;
	QUEUE_PTR_TAIL(q) ++;
	if ( QUEUE_PTR_TAIL(q) >= QUEUE_PTR_TAIL_ORIG(q))
		QUEUE_PTR_TAIL(q) = QUEUE_PTR_HEAD_ORIG(q);
}
#else
inline void produce(queue_t * q, ELEMENT_TYPE value)
{
	while (QUEUE_PTR_TAIL_VAL(q).data);
	QUEUE_PTR_TAIL_VAL(q) = value;
	QUEUE_PTR_TAIL(q) ++;
	if ( QUEUE_PTR_TAIL(q) >= QUEUE_PTR_TAIL_ORIG(q))
		QUEUE_PTR_TAIL(q) = QUEUE_PTR_HEAD_ORIG(q);
}
#endif

inline int insert(queue_t *q, ELEMENT_TYPE value)
{
	produce(q, value);
	return 0;
}
	


#if defined(CONS_BATCH)

inline void trashing_detect(queue_t * q)
{
	q->batch_head = q->head + CONS_BATCH_SIZE;
	if (q->batch_head >= QUEUE_PTR_TAIL_ORIG(q))
		q->batch_head = QUEUE_PTR_HEAD_ORIG(q); 

#if defined(AVOID_DEADLOCK)
	//uint32_t batch_size = CONS_BATCH_SIZE >> 1;
	unsigned long batch_size = CONS_BATCH_SIZE ;
	while (!(*q->batch_head).data) {
		wait_ticks(5000);
		q->batch_head = q->head + batch_size;
		if (q->batch_head >= QUEUE_PTR_TAIL_ORIG(q))
			q->batch_head = QUEUE_PTR_HEAD_ORIG(q);
		/* batch_size should be larger than 1 */
		if( batch_size > 1 ) {
			batch_size = batch_size >> 1;
		}
	}
#else
	while (!(*q->batch_head))
		wait_ticks(20000); 
#endif
}

inline ELEMENT_TYPE consume(queue_t * q)
{
	ELEMENT_TYPE value;
	if( leqthan(q->head, q->batch_head) ) {
		trashing_detect(q);
	}
	value = QUEUE_PTR_HEAD_VAL(q);
	QUEUE_PTR_HEAD_VAL(q).data = 0x0;
	QUEUE_PTR_HEAD_VAL(q).len = 0;
	QUEUE_PTR_HEAD(q)++;
	if (QUEUE_PTR_HEAD(q) >= QUEUE_PTR_TAIL_ORIG(q))
		QUEUE_PTR_HEAD(q) = QUEUE_PTR_HEAD_ORIG(q);
	return value;
}

#else

inline ELEMENT_TYPE consume(queue_t * q)
{
	ELEMENT_TYPE value;
	while (!(QUEUE_PTR_HEAD_VAL(q).data));
	value = QUEUE_PTR_HEAD_VAL(q);
	QUEUE_PTR_HEAD_VAL(q).data = 0x0;
	QUEUE_PTR_HEAD_VAL(q).len = 0;
	QUEUE_PTR_HEAD(q)++;
	if (QUEUE_PTR_HEAD(q) >= QUEUE_PTR_TAIL_ORIG(q))
		QUEUE_PTR_HEAD(q) = QUEUE_PTR_HEAD_ORIG(q);

	return value;
}

#endif

inline int extract(queue_t *q, ELEMENT_TYPE * value)
{
	*value = consume( q );
	return 0;
}

/*************************************************/
/********** Consumer *****************************/
/*************************************************/

#if 0
void           *
consumer(void *arg)
{
	uint32_t 	cpu_id;
	void           *value;
	unsigned long 	cur_mask;
	uint32_t	rand_t = 1;
	uint64_t	i;
	unsigned long	seed;
#if defined(FIFO_DEBUG)
	void	        *old_value = NULL;
#endif

	INIT_INFO * init = (INIT_INFO *) arg;
	cpu_id = init->cpu_id;
	pthread_barrier_t *barrier = init->barrier;

	//cur_mask = (0x2<<(2*cpu_id));
	//cur_mask = 0x4;
        if(cpu_id < 4)
                cur_mask = (0x2<<(2*cpu_id));
        else
                cur_mask = (0x1<<(2*(cpu_id-4)));
	

	printf("consumer %d:  ---%lu----\n", cpu_id, cur_mask);
	if (sched_setaffinity(0, sizeof(cur_mask), &cur_mask) < 0) {
		printf("Error: sched_getaffinity\n");
		return NULL;
	}

	seed = read_tsc();

	printf("Consumer created...\n");
	pthread_barrier_wait(barrier);

	QUEUE_START(cpu_id) = read_tsc();
#if defined(ADJUST_SLIP)
	adjust_slip( QUEUE_PTR(cpu_id) );
#endif

	for (i = 1; i <= TEST_SIZE; i++) {
		value = (void *)consume(QUEUE_PTR(cpu_id));

#if defined(WORKLOAD_DEBUG)
		//wait_ticks(CONS_WORK_CYCLES);
		workload(&seed);
#endif

#if defined(ADJUST_SLIP)
		if ( (i & 0x1F) == 0 ) {
			adjust_slip( QUEUE_PTR(cpu_id) );
		}
#endif

#if defined(FIFO_DEBUG)
		assert(((unsigned long)old_value + 1) == (unsigned long)value);
		old_value = value;
#endif
	}
	QUEUE_STOP(cpu_id) = read_tsc();

#if defined(WORKLOAD_DEBUG)
	printf("consumer: %d cycles/op\n", ((QUEUE_STOP(cpu_id) - QUEUE_START(cpu_id)) / ((TEST_SIZE + 1)))
	       - AVG_WORKLOAD - CONS_WORK_CYCLES );
#else
	printf("consumer: %d cycles/op\n", ((QUEUE_STOP(cpu_id) - QUEUE_START(cpu_id)) / ((TEST_SIZE + 1))));
#endif

	pthread_barrier_wait(barrier);
	return NULL;
}

/*************************************************/
/********** Producer *****************************/
/*************************************************/


void
producer(void *arg, uint32_t num)
{
	uint64_t start_p;
	uint64_t stop_p;
	//pthread_barrier_t *barrier = (pthread_barrier_t *)arg;
	uint64_t	i;
	int32_t j;
	unsigned long cur_mask;
	INIT_INFO * init = (INIT_INFO *) arg;
	pthread_barrier_t *barrier = init->barrier;

	cur_mask = (0x1 << 1);
	printf("producer %d:  ---%lu----\n", 0, cur_mask);
	if (sched_setaffinity(0, sizeof(cur_mask), &cur_mask) < 0) {
		printf("Error: sched_getaffinity\n");
		return ;
	}

	pthread_barrier_wait(barrier);

	start_p = read_tsc();
	/* (CONS_BATCH_SIZE) is the penalty of Batch Processing */
	for (i = 1; i <= TEST_SIZE + CONS_BATCH_SIZE; i++) {
		for (j=1; j<num; j++) {
			produce(QUEUE_PTR(j), (ELEMENT_TYPE)i);
#if defined(INCURE_DEBUG)
			if(i==(TEST_SIZE >> 1))
				produce(QUEUE_PTR(j), (void *)i);
#endif
			//wait_ticks(PROD_WORK_CYCLES/(num-1));
		}
	}
	stop_p = read_tsc();

#if defined(WORKLOAD_DEBUG)
	printf("prod %d cycles/op\n", ((stop_p - start_p) / ((TEST_SIZE + 1)*(num -1)))-PROD_WORK_CYCLES/(num-1));
#else
	printf("prod %d cycles/op\n", (stop_p - start_p) / ((TEST_SIZE + 1)*(num -1)));
#endif

	pthread_barrier_wait(barrier);
}

#endif
