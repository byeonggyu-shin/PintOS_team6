#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
/* 구조 스레드의 'magic' 멤버에 대한 임의 값
스택 오버플로를 탐지하는 데 사용
자세한 내용은 스레드 맨 위에 있는 큰 주석을 참조 */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
/* TRADE_READY 상태의 프로세스, 즉 실행 준비가 되었지만 실제로 실행되지 않는 프로세스 목록 */
static struct list ready_list;

/* 블록시킨 스레드 리스트 */
static struct list sleep_list;

/* 리스트의 sleep_list의 스레드에서 가장 이른 next_tick_to_awake
 만약 타이머 대기 중인 스레드가 없다면 INT64_MAX로 지정 */
static int64_t next_tick_to_awake;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
/* 초기 스레드, init.c:main()을 실행하는 스레드 */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
/* 거짓인 경우(기본값) 라운드 로빈 스케줄러를 사용합니다.
참인 경우 다단계 피드백 대기열 스케줄러를 사용합니다.
커널 명령줄 옵션 "-olfqs"에 의해 제어됩니다. */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

/* Returns true if T appears to point to a valid thread. */
/* T가 유효한 스레드를 가리키는 것 같으면 true를 반환 */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
/* 실행 중인 스레드를 반환합니다.
 CPU의 스택 포인터 'rsp'를 읽은 다음 페이지의 시작 부분으로 반올림합니다. 
'struct thread'는 항상 페이지의 시작 부분에 있고 스택 포인터는 중간에 있기 때문에 현재 스레드를 찾습니다. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
	/*
	현재 실행 중인 코드를 스레드로 변환하여 스레드 시스템을 초기화합니다.
	이것은 일반적으로 작동할 수 없으며 이 경우에만 로더 때문에 가능합니다.
	스택의 맨 아래 부분을 페이지 경계에 배치하는 데 주의했습니다.
	실행 대기열 및 Tid 잠금을 초기화
	함수를 호출한 후 sread_create()로 스레드를 만들기 전에 페이지 할당자를 초기화해야 합니다.
	함수가 완료될 때까지 thread_current()를 호출하는 것은 안전하지 않습니다.
	*/
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);

	list_init (&sleep_list);
	next_tick_to_awake = INT64_MAX;

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
/* 인터럽트를 활성화하여 선제적 스레드 스케줄링을 시작, 유휴 스레드 생성 */
void
thread_start (void) {
	/* Create the idle thread. */
	/* idle_started semaphore 생성 및 초기화 */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
/* 지정된 초기 우선 순위를 사용하여 NAME이라는 새 커널 스레드를 생성합니다. 
이 스레드는 인수로 AUX를 전달하는 FUNCTION을 실행하고 준비 대기열에 추가합니다.
새 스레드에 대한 스레드 식별자를 반환하거나 생성이 실패할 경우 TID_ERROR를 반환합니다.

thread_start()가 호출된 경우 sread_create()가 반환되기 전에 새 스레드가 예약될 수 있습니다.

thread_create()가 반환하기 전에 종료할 수도 있습니다.
반대로 원래 스레드는 새 스레드가 예약되기 전에 임의의 시간 동안 실행될 수 있습니다. 순서를 지정해야 할 경우 세마포 또는 다른 형식의 동기화를 사용합니다.

제공된 코드는 새 스레드의 '우선 순위' 멤버를 우선 순위로 설정하지만 실제 우선 순위 스케줄링은 구현되지 않습니다.
우선순위 스케줄링은 문제 1-3의 목표입니다. */
/* 새로운 스레드를 생성하고 초기화하는 함수 */
tid_t      
thread_create (const char *name, int priority, thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);

	/* compare priority to current running thread and yield it */
	// if (t->priority > thread_current()->priority)
	// 	thread_yield();

	test_max_priority ();
	
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
/* 차단된 스레드 T를 실행 준비 상태로 전환합니다.
	T가 차단되지 않은 경우 오류입니다. 
	(실행 중인 스레드를 준비하려면 thread_yield()를 사용합니다.)

이 함수는 실행 중인 스레드를 선점하지 않습니다.
이것은 중요할 수 있습니다. 호출자가 인터럽트 자체를 비활성화한 경우 스레드를 원자적으로 차단 해제하고 다른 데이터를 업데이트할 수 있습니다. */
void
thread_unblock (struct thread *t) {
	/* 인터럽트 레벨을 저장할 변수를 선언, 변수는 후에 인터럽트를 복원할 때 사용 */
	enum intr_level old_level;
	/* t가 유효한 스레드인지 확인, 검사를 통해 무효한 스레드 포인터가 함수에 전달되는 것을 방지 */
	ASSERT (is_thread (t));
	/* 인터럽트를 비활성화하고 이전 인터럽트 레벨을 old_level에 저장 
		스레드 상태 변경 과정 중 인터럽트가 발생하지 않도록 보장 */
	old_level = intr_disable ();
	/* 스레드 t의 상태가 블록되었는지 확인 
	검사를 통해 이미 블록되지 않은 스레드에 대해 함수가 호출되는 것을 방지*/
	ASSERT (t->status == THREAD_BLOCKED);

		// /* 블록된 스레드 t를 ready_list에 추가 
		// 스케줄러가 다음 실행할 스레드를 선택할 때 고려함*/
		// list_push_back (&ready_list, &t->elem);		
		
	/* 우선순위 비교후 삽입 */
	list_insert_ordered(&ready_list, &t->elem, cmp_priority, NULL);
	/* 스레드 t의 상태를 대기(THREAD_READY) 상태로 변경 */
	t->status = THREAD_READY;
	/* 인터럽트 레벨을 이전 상태인 old_level로 복원
		함수 실행 전 인터럽트 설정이 복원되어 인터럽트가 다시 발생할 수 있게 됨*/
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
/* 현재 스레드의 일정을 취소하고 삭제합니다. 호출자에게 돌아가지 않습니다. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the schedule-r's whim. */
/* CPU 반환, 현재 스레드는 sleep으로 전환되지 않으며 스케줄러에 따라 즉시 다시 예약될 수 있습니다*/
void
thread_yield (void) {
	struct thread *curr = thread_current ();  		 /* 현재 실행 중인 스레드를 가져와 curr 변수에 저장 */
	enum intr_level old_level;               			 /* 인터럽트 레벨을 저장할 변수 old_level을 선언 */

	ASSERT (!intr_context ());          		       /* 현재 인터럽트 컨텍스트가 아닌지 확인 , 인터럽트 컨텍스트에서 호출되어서는 안됨*/
/* 현재 인터럽트 레벨을 비활성화하고, 이전 인터럽트 레벨을 old_level에 저장 이
	스레드 전환 과정 중 인터럽트가 발생하지 않도록 함 */
	old_level = intr_disable ();              		 
	if (curr != idle_thread) 											 /* 현재 스레드가 유휴 스레드가 아닌 경우 다음 단계를 수행 */
	{
		// list_push_back (&ready_list, &curr->elem);   /* 현재 스레드를 준비 리스트에 추가, 다른 스레드가 실행될 수 있는 기회를 제공 */
		list_insert_ordered(&ready_list,&curr->elem, cmp_priority, NULL);
	}	
	do_schedule (THREAD_READY);										 /* 스케줄러를 호출하여 다음 실행할 스레드를 선택, 현재 스레드를 양보 */
	intr_set_level (old_level);									   /* 이전 인터럽트 레벨을 복원, 인터럽트가 다시 발생할 수 있게 됩 */
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	thread_current ()-> original_priority = new_priority;

	refresh_priority();
	test_max_priority();	
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_current ()->priority;
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	return 0;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;
	/* priority */
	t->original_priority = priority;
	list_init(&t->donators_list);
	t->lock_to_wait_on = NULL;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
/* 예약할 다음 스레드를 선택하고 반환합니다.
실행 대기열이 비어 있지 않은 경우 실행 대기열에서 스레드를 반환해야 합니다. 
(실행 중인 스레드가 계속 실행될 수 있으면 실행 대기열에 있게 됩니다.)
실행 대기열이 비어 있으면 idle_thread를 반환합니다. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =	list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}


/**
 *  지금부터 ticks 이후에 다시 깨우도록 하고 이 스레드를 블락
*/
void
thread_sleep (int64_t tick)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  /* idle 스레드는 sleep되지 않아야 하며,
  	 해당 스레드 코드는 이 함수를 호출하지 않습니다.*/ 
  ASSERT (!intr_context ());

  /* 이전 인터럽트 레벨을 저장 */
  old_level = intr_disable ();

	cur->wakeup_tick = tick;

  /* 아무 스레드를 깨워야 하는 가장 이른 틱 갱신 */ 
  update_next_tick_to_awake (tick);
  /* 타이머 대기 리스트에 이 스레드를 추가 */ 
	if (cur != idle_thread){
  	list_push_back (&sleep_list, &cur->elem);
	}
  do_schedule (THREAD_BLOCKED);
  /* 인터럽트 레벨을 처음 상태 재할당 */ 
  intr_set_level (old_level);
}

/** 
 * sleep_list에서 깨워야 하는 모든 스레드를 블락 상태에서
 * 대기 상태로 바꾸며, 다음 깨우기 시간을 새로 계산합니다.
*/
void 
thread_awake(int64_t current_tick)
{
	struct thread *t;
	struct list_elem * cur = list_begin(&sleep_list);
	struct list_elem *next;
	struct list_elem *tail = list_end(&sleep_list);
	
	while (cur != tail) {
		t = list_entry(cur, struct thread, elem);
		next = list_next(cur);
		if (t->wakeup_tick <= current_tick) {
			list_remove(cur);
			thread_unblock(t);
		}
		else {
			update_next_tick_to_awake(t->wakeup_tick);
		}
		cur = next;
	}
}


/**
 *  커널은 타이머 대기 중인 스레드의 깨우기 목표 틱 중에서 
 * 가장 빨리 도래하는 스레드의 깨우기 목표 틱을 계속 유지합니다. 값을 갱신합니다.
*/ 
void
update_next_tick_to_awake (int64_t tick)
{
  	if (tick < next_tick_to_awake) {
		next_tick_to_awake = tick;
	}
}

// update_next_tick_to_awake에서 설명한 틱 값을 반환합니다.
int64_t
get_next_tick_to_awake (void)
{
  return next_tick_to_awake;
}

/**
 * 스레드의 우선순위를 비교하고, 첫 번째 인자의 우선순위가 높으면 1을 반환하고, 그렇지 않으면 0을 반환
*/
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
	struct thread *thread_a = list_entry(a, struct thread, elem);
	struct thread *thread_b = list_entry(b, struct thread, elem);
	/*첫  번째 인자의 우선순위가 높으면 1을 반환, 두 번째 인자의 우선순위가 높으면 0을 반환*/
	return thread_a->priority > thread_b->priority ? 1 : 0;
}

/**
 * 스레드를 비교하여, 현재 스레드의 우선순위가 더 낮을 경우 스레드 교체
*/
void test_max_priority(void) {
	struct thread *current_thread = running_thread();
	struct thread *highest_priority_thread;

	if (list_empty(&ready_list)){
		return;
	}

	highest_priority_thread = list_entry(list_begin(&ready_list), struct thread, elem);

	/* 현재 스레드의 우선순위와 가장 높은 우선순위를 가진 스레드 비교 */ 
	if (current_thread->priority < highest_priority_thread->priority)
		/* 현재 스레드의 우선순위가 더 낮은 경우, 스케줄링 */ 
		thread_yield();
}

struct thread* get_child_by_tid(tid_t tid){
	struct thread *curr = thread_current();
	struct thread *child;
	struct list_elem *e;
	for(e = list_begin(&curr->child_list); list_end(&curr->child_list); e = list_next(e)){
		child = list_entry(e, struct thread, child_elem);
		if (child->tid == tid)break;
	}
	return child;
}