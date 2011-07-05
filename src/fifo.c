#include "fifo.h"
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <parallel.h>

#if defined(FIFO_DEBUG)
#include <assert.h>
#endif


/* the number of producer is one */
FIFO_CTRL fifo_g[MAX_CPU_CORES];
FIFO_BUFFER buffer_g[MAX_CPU_CORES];

static inline uint32_t myrand(uint32_t *next, uint32_t cpu_id)
{
	*next = *next * (1103515245 ) + 12345 + cpu_id * 16;
	return((uint64_t)(*next/65535) % 32768);
}


static inline uint64_t read_tsc()
{
	uint64_t        time;
	uint32_t        msw   , lsw;
	__asm__         __volatile__("rdtsc\n\t"
			"movl %%edx, %0\n\t"
			"movl %%eax, %1\n\t"
			:         "=r"         (msw), "=r"(lsw)
			:
			:         "%edx"      , "%eax");
	time = ((uint64_t) msw << 32) | lsw;
	return time;
}

inline void
wait_ticks(uint64_t ticks)
{
        uint64_t        current_time;
        uint64_t        time = read_tsc();
        time += ticks;
        do {
                current_time = read_tsc();
        } while (current_time < time);
}

/* Insert: called by the producer */
inline int insert(FIFO_CTRL * fifo, FIFO_BUFFER * buffer, ELEMENT_TYPE element)
{
	uint32_t afterNextWrite = ELEM_NEXT(FIFO_NEXT_WRITE(fifo));
	if( afterNextWrite == FIFO_LOCAL_READ(fifo) ) {
		if( afterNextWrite == FIFO_READ(fifo) ) {
			return INSERT_FAILED;
		}
		FIFO_LOCAL_READ(fifo) = FIFO_READ(fifo);
	}
	BUFFER_ELEM(buffer, FIFO_NEXT_WRITE(fifo)) = element;
	FIFO_NEXT_WRITE(fifo) = afterNextWrite;
	FIFO_W_BATCH(fifo) ++;
	if( FIFO_W_BATCH(fifo) >= FIFO_BATCH_SIZE(fifo) ) {
		FIFO_WRITE(fifo) = FIFO_NEXT_WRITE(fifo);
		FIFO_W_BATCH(fifo) = 0;
	}
	return SUCCESS;
}

/* Extract: called by the consumer */
inline int extract(FIFO_CTRL * fifo, FIFO_BUFFER * buffer, ELEMENT_TYPE * element)
{
	if( FIFO_NEXT_READ(fifo) == FIFO_LOCAL_WRITE(fifo) ) {
		if( FIFO_NEXT_READ(fifo) == FIFO_WRITE(fifo)) {
			return EXTRACT_FAILED;
		}
		FIFO_LOCAL_WRITE(fifo) = FIFO_WRITE(fifo);
	}
	*element = BUFFER_ELEM(buffer, FIFO_NEXT_READ(fifo));
	FIFO_NEXT_READ(fifo) = ELEM_NEXT(FIFO_NEXT_READ(fifo));
	FIFO_R_BATCH(fifo) ++;
	if( FIFO_R_BATCH(fifo) >= FIFO_BATCH_SIZE(fifo) ) {
		FIFO_READ(fifo) = FIFO_NEXT_READ(fifo);
		FIFO_R_BATCH(fifo) = 0;
	}
	return SUCCESS;
}

#if 0
/*************************************************/
/********** Consumer *****************************/
/*************************************************/

/*  Input: thread control message (arg) */
void * consumer(void *arg)
{
	uint32_t	cpu_id;
	uint32_t 	value;
	int		result;
	unsigned long cur_mask;
	uint64_t        i;
        uint64_t        start_c;
        uint64_t        stop_c;
	uint32_t	rand_t = 1;
	FIFO_ELEM	elem;
#if defined(FIFO_DEBUG)
	int64_t		old_value = -1;
#endif


	INIT_INFO * init = (INIT_INFO *) arg;
	cpu_id = INIT_ID(init);
	pthread_barrier_t *barrier = INIT_BAR(init);

#if 1
	cur_mask = (0x1<<(cpu_id));
	printf("consumer %d:  ---%lu----\n", cpu_id, cur_mask);
	if (sched_setaffinity(0, sizeof(cur_mask), &cur_mask) < 0) {
		printf("Error: sched_getaffinity\n");
		return NULL;
	}
#endif

	printf("Consumer created...\n");
	pthread_barrier_wait(barrier);

	start_c = read_tsc();
	for (i = 1; i <= TEST_SIZE; i++) {
		do{
			result = extract(&fifo_g[cpu_id-1], &buffer_g[cpu_id-1], &elem);
		} while( result != SUCCESS );
		
		value = FIFO_ELEM_SIZE(&elem);

#if defined(WORKLOAD_DEBUG)
		wait_ticks(CONS_WORK_CYCLES); /* FIXME */
		workload(myrand(&rand_t, cpu_id));
#else
		wait_ticks(CONS_WORK_CYCLES);
#endif

#if defined(FIFO_DEBUG)
	/* suppose the producer advances the value of elements */
		assert((old_value + 1) == value);
		old_value = value;
#endif
	}
	stop_c = read_tsc();

	printf("consumer: %d cycles/op\n", ((stop_c - start_c) / ((TEST_SIZE + 1))) - CONS_WORK_CYCLES );
	pthread_barrier_wait(barrier);

	return NULL;
}


/*************************************************/
/********** Producer *****************************/
/*************************************************/

/* Input: (1) thread control message (arg) and the number of consumers (num) */
void producer(void *arg, uint32_t num)
{
        pthread_barrier_t *barrier = (pthread_barrier_t *)arg;
        uint64_t        i;
        int32_t 	j;
	int		result;
        unsigned long cur_mask;
        uint64_t        start_p;
        uint64_t        stop_p;
	FIFO_ELEM	elem;

#if 1
        cur_mask = (0x1);
        printf("producer %d:  ---%lu----\n", 0, cur_mask);
        if (sched_setaffinity(0, sizeof(cur_mask), &cur_mask) < 0) {
                printf("Error: sched_getaffinity\n");
                return ;
        }
#endif

        pthread_barrier_wait(barrier);

        start_p = read_tsc();
	/* (TEST_SIZE + BATCH_SIZE): to dump all the data into fifo */ 
        for (i = 1; i <= (TEST_SIZE + BATCH_SIZE + 2); i++) {
		FIFO_ELEM_SIZE(&elem) = i;
		for(j=0; j<num; j++) { /* the number of consumer is num */
			do {
				result = insert(&fifo_g[j], &buffer_g[j], elem);
			}while (result != SUCCESS);
			wait_ticks(PROD_WORK_CYCLES/num);
		}
        }
        stop_p = read_tsc();

	printf("producer: %d cycles/op\n", ((stop_p - start_p) / ((TEST_SIZE + 1)*(num))) - (PROD_WORK_CYCLES/num) - WAIT_TICKS_LATENCY);
        pthread_barrier_wait(barrier);
	
}

#endif

int fifo_init(int num)
{
	if(num > MAX_CPU_CORES) {
		return -1;
	}
	memset(&fifo_g[num], 0, sizeof(FIFO_CTRL));
	FIFO_BATCH_SIZE(&fifo_g[num]) = BATCH_SIZE;

	/* consumer starts from buffer[1] */
	FIFO_WRITE(&fifo_g[num]) = ELEM_NEXT(FIFO_READ(&fifo_g[num]));
	FIFO_NEXT_WRITE(&fifo_g[num]) = FIFO_WRITE(&fifo_g[num]);


	memset(&buffer_g[num], 0, sizeof(FIFO_BUFFER));
	
	return 0;
}

