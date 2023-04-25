#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */

 

/*
	1. `struct thread'가 너무 커져서는 안 됨. 이 경우 커널 스택을 위한 공간이 충분하지 않음
	우리의 기본 'struct thread'는 크기가 몇 바이트에 불과합니다. 1kB 미만으로 유지되어야 함
	2. 둘째, 커널 스택이 너무 커져서는 안 됩니다. 스택이 오버플로되면 스레드 상태가 손상됩니다. 
	따라서 커널 함수는 큰 구조나 배열을 정적이 아닌 로컬 변수로 할당해서는 안 됩니다. 
	대신 malloc() 또는 palloc_get_page()와 함께 동적 할당을 사용합니다.

 이러한 문제 중 하나의 첫 번째 증상은 아마도 실행 중인 스레드의 'struct thread'의 'magic' 멤버가 TRADE_MAGIC으로 설정되었는지 확인하는 thread_current()의 어설션 오류일 것입니다. 
 스택 오버플로는 일반적으로 이 값을 변경하여 어설션을 트리거합니다. 
`elem' 멤버는 이중적인 목적을 가지고 있습니다. 실행 대기열(thread.c)의 요소이거나 세마포 대기 목록(synch.c)의 요소일 수 있습니다. 
준비 상태의 스레드만 실행 대기열에 있고 차단된 상태의 스레드만 세마포 대기 목록에 있기 때문에 이 두 가지 방법만 사용할 수 있습니다. */

struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */

	/* 추가된 속성 */
	int64_t wakeup_tick;

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

/* ----------- P-1 Alarm clock ------------ */
void thread_sleep (int64_t ticks);               /* Thread를 blocked 상태로 만들고 sleep queue에 삽입하여 대기 */
void thread_awake (int64_t ticks);               /* Sleep queue에서 깨워야 할 thread를 찾아서 wake */
void update_next_tick_to_awake (int64_t ticks);      /* Thread들이 가진 tick 값에서 최소 값을 저장 */
int64_t get_next_tick_to_awake (void);               /* 최소 tick값을 반환 */

/* Priority Scheduling */
/* 현재 수행중인 스레드와 가장 높은 우선순위의 스레드의 우선순위를 비교하여 스케줄링 */
void test_max_priority (void);   
/* 인자로 주어진 스레드들의 우선순위를 비교 */   
bool cmp_priority (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

#endif /* threads/thread.h */
