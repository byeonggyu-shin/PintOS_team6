#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
/* OS 부팅 이후의 타이머 틱 수 */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
/* 타이머 눈금당 루프 수 timer_calibrate()에 의해 초기화*/
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);

/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
/* 초당 PIT_FREQ 횟수를 인터럽트하도록 8254 PIT(Programmable Interval Timer)를 설정하고 해당 인터럽트를 등록 */
void
timer_init (void) {
	/* 8254 input frequency divided by TIMER_FREQ, rounded to
	   nearest. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

	outb (0x43, 0x34);    /* CW: counter 0, LSB then MSB, mode 2, binary. */
	outb (0x40, count & 0xff);
	outb (0x40, count >> 8);

	intr_register_ext (0x20, timer_interrupt, "8254 Timer");
}

/* Calibrates loops_per_tick, used to implement brief delays. */
/* 짧은 지연을 구현하는 데 사용되는 loops_per_tick을 보정 */
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	ASSERT (intr_get_level () == INTR_ON);
	printf ("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. */
	loops_per_tick = 1u << 10;
	while (!too_many_loops (loops_per_tick << 1)) {
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
		if (!too_many_loops (high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
/* OS가 부팅된 이후의 타이머 ticks 반환 */
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable ();
	int64_t t = ticks;
	intr_set_level (old_level);
	barrier ();
	return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
/* THEN 이후 경과된 타이머 눈금 수를 반환, 이 값은 timer_ticks()가 반환한 값이어야 함 */
int64_t
timer_elapsed (int64_t then) {
	return timer_ticks () - then;
}

/* Suspends execution for approximately TICKS timer ticks. */
void
timer_sleep (int64_t ticks) {         /* ticks 만큼 시스템을 일시 중지 */
	int64_t start = timer_ticks ();     /* 현재 시스템의 틱 수를 가져와 start 변수에 저장 */
	ASSERT (intr_get_level () == INTR_ON);    /* 인터럽트 상태 확인 */	

	/* busy_waiting */
	// while (timer_elapsed (start) < ticks)
	// 	thread_yield ();
	if(ticks < 0){                      /* 틱 수가 음수인 경우 함수를 종료 */
		return;
	} else {
		thread_sleep (start + ticks);     /* 현재 스레드를 주어진 틱 수만큼 일시 중지 */
	}
} 

/* Suspends execution for approximately MS milliseconds. */
/* 약 MS 밀리초 동안 실행을 일시 중단 */
void
timer_msleep (int64_t ms) {
	real_time_sleep (ms, 1000);
}

/* Suspends execution for approximately US microseconds. */
/* 약 US 밀리초 동안 실행을 일시 중단 */
void
timer_usleep (int64_t us) {
	real_time_sleep (us, 1000 * 1000);
}

/* Suspends execution for approximately NS nanoseconds. */
/* 약 NS 밀리초 동안 실행을 일시 중단 */
void
timer_nsleep (int64_t ns) {
	real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
/* 타이머 통계를 인쇄 */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/* Timer interrupt handler. */
static void
timer_interrupt (struct intr_frame *args UNUSED) {
	ticks++;
	thread_tick ();
	thread_awake(ticks); // 깨우기
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
/* LOOPS 반복이 둘 이상의 타이머 눈금을 대기하면 true를 반환하고, 그렇지 않으면 false를 반환 */
static bool
too_many_loops (unsigned loops) {
	/* Wait for a timer tick. */
	int64_t start = ticks;
	while (ticks == start)
		barrier ();

	/* Run LOOPS loops. */
	start = ticks;
	busy_wait (loops);

	/* If the tick count changed, we iterated too long. */
	barrier ();
	return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
/* Iterates 통해서 짧은 지연을 구현하기 위해 간단한 루프 LOOPS times을 반복 
코드 정렬이 타이밍에 상당한 영향을 미칠 수 있으므로 이 함수가 다른 위치에서 다르게 인라인된 경우 결과를 예측하기 어려울 수 있으므로 NO_INLINE으로 표시됩니다. */
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0)
		barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
/* 약 NUM/DENOM 초 동안 sleep으로 전환 */
static void
real_time_sleep (int64_t num, int32_t denom) {
	/* Convert NUM/DENOM seconds into timer ticks, rounding down.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom;

	ASSERT (intr_get_level () == INTR_ON);
	if (ticks > 0) {
		/* We're waiting for at least one full timer tick.  Use
		   timer_sleep() because it will yield the CPU to other
		   processes. */
			 /* 최초 하나의 풀 타이머 티켓을 기다림
다른 프로세스에 CPU를 제공하므로 timer_sleep()을 사용*/
		timer_sleep (ticks);
	} else {
		/* Otherwise, use a busy-wait loop for more accurate
		   sub-tick timing.  We scale the numerator and denominator
		   down by 1000 to avoid the possibility of overflow. */
		/* 그렇지 않은 경우 사용 중 대기 루프를 사용하여 보다 정확한 하위 체크 표시 시간을 지정
		분자와 분모를 1000씩 축소하여 오버플로의 가능성을 방지 */
		ASSERT (denom % 1000 == 0);
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
	}
}
