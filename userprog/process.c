#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

void argument_stack(char **argv, int argc, struct intr_frame *_if);
/* General process initializer for initd and other process. */
/*  initd 및 기타 프로세스에 대한 일반 프로세스 이니셜라이저 */
static void 
process_init (void) {
	struct thread *current = thread_current ();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
/*  file_name이 주어지면 초기 사용자 프로세스를 위한 새 스레드를 생성하는 역할 */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;         /* file_name의 복사본을 저장 */
	tid_t tid;             /* tid 변수를 선언하며 새로 생성된 스레드의 스레드 ID를 저장 */

	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	/* file_name의 내용을 fn_copy에서 할당된 메모리로 복사하여 PGSIZE를 초과하지 않도록 함*/
	strlcpy (fn_copy, file_name, PGSIZE);

	/* Create a new thread to execute FILE_NAME. */
	/* file_name, 기본 우선 순위 PRI_DEFAULT 및 initd 함수를 스레드 함수로 사용하여 새 스레드를 생성 */
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)              /* 스레드 생성이 실패하고 tid가 TID_ERROR와 같으면 */
		palloc_free_page (fn_copy);      /* fn_copy에 할당된 메모리가 해제 */
	/* 새로 생성된 스레드의 스레드 ID tid를 반환 */
	return tid;
}

/* A thread function that launches first user process. */
/* 첫 번째 사용자 프로세스를 시작하는 스레드 함수 */
static void
initd (void *f_name) {
#ifdef VM                  /* VM 옵션이 활성화된 경우 */
	/* 현재 스레드의 추가 페이지 테이블을 초기화 */
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init ();                    /* 데이터 구조와 리소스를 설정하여 프로세스를 초기화 */

	if (process_exec (f_name) < 0)      /* f_name으로 사용자 프로세스를 실행하려고 시도 */
		PANIC("Fail to launch initd\n");

	/* 제어 흐름이 이 지점에 도달하지 않아야 함을 나타넴 
	프로그램이 사용자 프로세스를 성공적으로 실행하거나 실패할 경우 패닉 상태여야 하기 때문 */
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
/* 현재 프로세스를 name으로 복제
 스레드를 생성할 수 없는 경우 새 프로세스의 스레드 ID 또는 TID_ERROR를 반환 */
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	return thread_create (name,
			PRI_DEFAULT, __do_fork, thread_current ());
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: parent_page가 커널 페이지인 경우 즉시 반환 */

	/* 2. TODO: 부모의 페이지 맵 레벨 4에서 VA 해결  */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	/* 3. TODO: 자식에게 새로운 PAL_USER 페이지를 할당하고 결과를 NEWPAGE로 설정 */


	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	/* 4. TODO: 부모 페이지를 새 페이지로 복제하여 부모 페이지의 쓰기 가능 여부를 확인
		(결과에 따라 쓰기 가능으로 설정) */

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	/* 5. TODO: 쓰기 가능한 권한으로 주소 VA의 하위 페이지 테이블에 새 페이지를 추가 */

	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		/* 6. TODO: 페이지 삽입에 실패한 경우 오류 처리를 수행합니다. */

	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current ();
	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	struct intr_frame *parent_if;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/

	process_init ();

	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);
error:
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
/* 현재 실행 컨텍스트를 지정된 file_name(f_name)으로 전환
	프로세스 실행에 실패하면 -1을 반환*/
int
process_exec (void *f_name) {
	char *file_name = f_name;        /* 입력 매개변수 f_name을 file_name이라는 문자 포인터로 캐스트 */
	bool success;                    /* 새 프로세스를 로드한 결과를 저장 */
 
	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	/* 스레드 구조에서 intr_frame을 사용할 수 없음
	 현재 스레드가 스케줄링을 변경할 때 실행 정보를 구성원에게 저장하기 때문 */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	/* 현재 프로세스와 관련된 리소스를 해제 */
	process_cleanup ();

	/* parsing을 위한 변수 선언*/
	char *argv[128];           
	int argc = 0;
	char *token, *save_ptr;
	/* argument parsing */
	for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)){
			argv[argc] = token;
			argc++;
	}

	/* And then load the binary */
	/* 새 프로세스의 바이너리를 메모리에 로드하고 초기 상태를 설정 */
	success = load (file_name, &_if);

	/* If load failed, quit. */
	if (!success){                      /* 로드 작업이 실패하면 -1을 반환 */
		palloc_free_page (file_name);      /* file_name에 할당된 메모리를 해제 */
		return -1; 
	}
	/* command line에서 받은 인자들을 스택에 차곡차곡 쌓는다. */
	argument_stack(argv, argc, &_if);

	_if.R.rdi = argc;			         // 첫 번째 인자 argc를 RDI
	 /* argv 할당시 커널 스택에서의 char *argv[128]의 주소이므로
	  유저 스택에 쌓은 argv의 주소인 if.rsp+8을 할당 */
	_if.R.rsi = _if.rsp + 8;	     // 두 번째 인자 argv를 RSI 

	/* 작업이 끝났으므로 동적할당한 file_name이 담긴 메모리 free */
	palloc_free_page (file_name);

	/* Start switched process. */
	/*  IRET(interrupt return) 작업을 수행하여 새 프로세스의 컨텍스트로 전환 */
	do_iret (&_if);       
	/* 이 지점에 절대 도달해서는 안 됨을 나타내는 매크로 */            
	NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	while(1){};  /* infinite loop 추가 */
	return -1;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */

	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
/* 다음 스레드에서 사용자 코드를 실행하기 위해 CPU를 설정
	모든 컨텍스트 스위치에서 호출 */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	/* 다음 스레드의 페이지 테이블을 활성화 */
	pml4_activate (next->pml4);          /* CPU의 CR3 레지스터가 다음 스레드의 PML4(최상위 페이지 테이블)의 기본 주소로 설정 */

	/* Set thread's kernel stack for use in processing interrupts. */
	/* 다음 스레드의 커널 스택으로 TSS(Task State Segment)를 업데이트 
	 ->다음 스레드에서 인터럽트를 처리할 때 올바른 커널 스택이 사용 */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
/* ELF(Executable and Linkable Format) 실행 파일을 현재 스레드의 주소 공간으로 로드하는 역할*/
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();        /* 현재 스레드 */
	struct ELF ehdr;                             /* 헤더 정보를 저장할 ELF 헤더 구조 */
	struct file *file = NULL;                    /* 열린 파일에 대한 참조를 보유할 파일 포인터 */
	off_t file_ofs;                              /* 파일 위치를 추적하기 위해 파일 오프셋 변수 */
	bool success = false;                        /* 성공 플래그를 false로 초기화 */
	int i;                                       /* 루프 카운터 변수 */

	char *token, *save_ptr;
	char *argv[64];  
	/* file_name 자체를 parsing하기보단, 안전하게 복사본을 새로 만들자 */
	char* file_name_copy[48];
	memcpy(file_name_copy, file_name, strlen(file_name)+1);  /* strlen은 \0을 빼고 세 주므로(\n?). */

	/* strtok_r() 사용 준비 */

	int argc = 0;
	for (token = strtok_r(file_name_copy, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)){
			argv[argc] = token;
			argc++;
	}

	/* Allocate and activate page directory. */
	/* 현재 스레드에 대한 새 페이지 디렉토리를 할당하고 활성화 */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	/* 실행 파일을 열고 파일을 열 수 없는 경우 오류를 처리 */
	file = filesys_open (argv[0]);
	if (file == NULL) {
		printf ("load: %s: open failed\n", argv[0]);
		goto done;
	}

	/* Read and verify executable header. */
	/*  ELF 헤더를 읽고 확인 
		헤더가 잘못된 경우 오류 메시지를 인쇄하고 "done" 레이블로 이동 */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	/* 파일 오프셋을 프로그램 헤더의 시작 부분으로 초기화 */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {                       /* 모든 프로그램 헤더를 읽는 루프를 시작 */
		struct Phdr phdr;             
		/* 읽을 수 없는 경우 오류를 처리 */
		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {               /* type에 따라 헤더를 처리*/
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	/* setup_stack을 호출하여 프로세스의 초기 스택을 설정 */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	// file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
/* USER_STACK에서 제로 페이지를 매핑하여 최소 스택 생성 */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;                      /* 커널 페이지를 나타내는 부호 없는 8비트 정수에 대한 포인터를 선언 */
	bool success = false;                /* 스택 설정이 성공했는지 여부를 나타내는 데 사용 */

	/* PAL_USER 및 PAL_ZERO 플래그로 사용자 스택에 새 페이지를 할당
		PAL_USER는 페이지가 사용자 모드용임을 지정하고 PAL_ZERO는 할당된 페이지가 0이 되어야 함 */
	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {                 /* 할당된 커널 페이지(kpage)가 NULL(할당 성공)이 아닌지 확인 */
		/* install_page 함수를 호출하여 할당된 커널 페이지(kpage)를 페이지 크기를 뺀 사용자 스택 주소에 매핑 */
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)							      	 /* install_page 함수 호출이 성공했는지 확인*/
			/* 성공하면 인터럽트 프레임(if_)의 초기 스택 포인터를 USER_STACK으로 설정 */
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);        /* 할당된 커널 페이지(kpage)를 해제 */
	} 
	/* 스택 설정이 성공했는지 여부를 나타내는 success 변수를 반환 */
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */

void 
argument_stack(char **argv, int argc, struct intr_frame *_if){
	char *arg_address[128];

	// 1. Save argument strings (character by character)
	// if_->rsp = 0x47480000(USER_STACK)
	for (int i = argc - 1; i >= 0; i--)  // 가장 idx가 큰 argv부터 쌓는다.
	{
		int argv_len = strlen(argv[i]);  // argv[1] = "onearg", argv_len = 6
		_if->rsp -= (argv_len + 1);
		memcpy(_if->rsp, argv[i], argv_len + 1);
		arg_address[i] = _if->rsp;
	}

	// 2. Word-align padding
	while(_if->rsp % 8 != 0){
		_if->rsp--;
		*(uint8_t *)(_if->rsp) = 0;
	}
	// 3. Pointers to the argument strings
	size_t PTR_SIZE = sizeof(char *);  // PTR_SIZE == 8
	for (int i = argc; i >= 0; i--)
    {
        _if->rsp = _if->rsp - PTR_SIZE;
        if (i == argc)  // 맨 위에는 padding?
            memset(_if->rsp, 0, PTR_SIZE);
        else
            memcpy(_if->rsp, &arg_address[i], PTR_SIZE);
    }
			// 4. Return address
	_if->rsp -= PTR_SIZE;
	memset(_if -> rsp, 0, PTR_SIZE);
}


// void argument_stack (char **argv, int argc, struct intr_frame *if_)
// {
// 	char *arg_address[128];
// 	// 거꾸로 삽입

// 	/* 맨 끝 NULL 값 (arg[4]) 제외하고 스택에 저장 */
// 	for (int i = argc-1; i >= 0; i--) {
// 		int argv_len = strlen(argv[i]) + 1;
// 		/* if_ -> rsp: 현재 user stack에서 현재 위치를 가리키는 스택 포인터
// 		   각 인자에서 인자 크기(argv_len)를 읽고
// 		   (이 때 각 인자에 sentinel이 포함되어 있으니 +1 - strlen에서는 sentinel 빼고 읽음)
// 		   그 크기만큼 rsp를 내려준다. 그 다음 빈 공간만큼 memcpy */
// 		if_->rsp = if_->rsp - (argv_len); // 받아온 길이 만큼 스택 크기 늘려줌
// 		memcpy (if_->rsp, argv[i], argv_len); // 늘려준 스택 공간에 해당 인자 복사
// 		arg_address[i] = if_->rsp; // arg_address에 인자 복사한 시작 주소값 저장
// 	}

// 	/* word_align : 8의 배수 맞추기 위해 padding 삽입 */
// 	while (if_->rsp % SAU != 0) {
// 		if_->rsp--;
// 		memset(if_->rsp, 0, sizeof(uint8_t));
// 	}

// 	/* word_align 이후 argv[4]~argv[0]의 주소 넣어준다 */
// 	for (int i = argc; i >= 0; i--) {
// 		if_->rsp = if_->rsp - SAU; // 8바이트만큼 내리고
// 		if (i == argc) { // 가장 위에는 0 넣음
// 			memset (if_->rsp, 0, sizeof(char **));
// 		}
// 		else { // 나머지에는 arg_address 안에 들어있는 값 가져오기
// 			memcpy (if_->rsp, &arg_address[i], sizeof(char **)); // 8bytes
// 		}
// 	}

// 	/* Fake return address */
// 	if_->rsp -= sizeof(void *);
// 	memset (if_->rsp, 0, sizeof(void *));

// 	/* Set rdi, rsi (rdi : 문자열 목적지 주소, rsi : 문자열 출발지 주소)*/
// 	if_->R.rdi = argc;
// 	if_->R.rsi = if_->rsp + SAU;
// }