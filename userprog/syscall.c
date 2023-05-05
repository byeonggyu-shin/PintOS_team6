#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
/* Project-2 */
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "kernel/stdio.h"
#include "threads/palloc.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* add function */
void check_address(void *addr);
void get_argument(void *rsp, int **arg, int count);

/* system call */
void halt(void);
void exit(int status);
tid_t fork (const char *thread_name, struct intr_frame *f);
int exec (const char *cmd_line);
int wait (tid_t child_tid UNUSED);                          /* process_wait()으로 대체 필요 */
bool create (const char *file, unsigned initial_size);     	
bool remove (const char *file);					               
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

/* */
const int STDIN = 0;
const int STDOUT = 1;

/* syscall 메커니즘 초기화 */
void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	/*  syscall_entry가 사용자 및 스택을 커널 모드 스택으로 스왑할 때까지 인터럽트 서비스를 실행하면 안 됩니다. 
	따라서 FLAG_FL을 마스킹했습니다. */
	write_msr(MSR_SYSCALL_MASK,	FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&filesys_lock);

}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	printf ("system call!\n");
	// thread_exit ();
	char *f_copy;

	switch(f->R.rax) {
		case SYS_HALT:
			halt();  // 리턴값과 인자 둘 다 없다.
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			if (exec(f->R.rdi) == -1)
				exit(-1);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			exit(-1);
			break;
	}

}

/**
 * 주소 값이 유저 영역에서 사용하는 주소 값인지 확인 하는 함수
 * Pintos에서는 시스템 콜이 접근할 수 있는 주소를 0x8048000~0xc0000000으로 제한함
 * 유저 영역을 벗어난 영역일 경우 프로세스 종료(exit(-1))
*/
void check_address(void *addr){
	if (addr == NULL || !is_user_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL)
		exit(-1);
}

/* 유저 스택에 있는 인자들을 커널에 저장하는 함수
스택 포인터(rsp)에 count(인자의 개수) 만큼의 데이터를 arg에 저장  */
void get_argument(void *rsp, int **arg, int count){
	rsp = (int64_t *)rsp + 2;         // stack pointer에서 2칸 (16byte) 위로 할당 : |argc|"argv"|...
	for (int i=0; i<count; i++){
		arg[i] = rsp;
		rsp = (int64_t *)rsp + 1;
	}
}

/* 현재 스레드의 fd_table에서 지정된 fd의 유효성을 확인 */
static struct file *
get_file_from_fd_table(int fd) {
	struct thread *curr = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT) {            
		return NULL;
	}

	return curr->fd_table[fd];	/*return fd of current thread. if fd_table[fd] == NULL, it automatically returns NULL*/
}

/* Remove give fd from current thread fd_table */
/* 현재 스레드의 fd_table에서 지정된 파일 설명자 'fd'를 제거 */
void
remove_file_from_fdt(int fd)
{
	struct thread *cur = thread_current();

	if (fd < 0 || fd >= FDCOUNT_LIMIT) /* Error - invalid fd */
		return;

	cur->fd_table[fd] = NULL;
}

/* Find available spot in fd_talbe, put file in  */
/* 파일 설명자 테이블에서 사용 가능한 위치를 찾고 지정된 파일을 테이블에 추가 */
int 
add_file_to_fdt(struct file *file) {
	struct thread *curr = thread_current();
	struct file **fdt = curr->fd_table;

	while (curr->fd_idx < FDCOUNT_LIMIT && fdt[curr->fd_idx]) {            /* fd table 반복 */
		curr->fd_idx++;
	}

	if (curr->fd_idx >= FDCOUNT_LIMIT) {
		return -1;
	}

	fdt[curr->fd_idx] = file;
	return curr->fd_idx;
}

  
/* pintos를 종료시키는 시스템 콜 */
void halt(void){
	power_off();
}

/* 현재 프로세스를 종료시키는 시스템 콜 */
void exit(int status){
	struct thread *curr = thread_current();
	curr->exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status);
	
	thread_exit();
}

/* THREAD_NAME이라는 이름을 가진 현재 프로세스의 복제본인 새 프로세스 생성 */
tid_t fork (const char *thread_name, struct intr_frame *f) {
	// check_address(thread_name);
	return process_fork(thread_name, f);
}

/* 현재의 프로세스가 cmd_line에서 이름이 주어지는 실행가능한 프로세스로 변경 */
int
exec(const char *cmd_line) {
	check_address(cmd_line);                     /* 메모리 주소의 유효성을 검사 */

	char *cmd_line_cp;                           /* 명령줄의 복사본을 저장하는 데 사용할 포인터 'cmd_line_cp'를 선언 */
	
	int size = strlen(cmd_line);                 /* 명령줄 문자열의 길이를 계산하여 'size' 변수에 저장 */
	cmd_line_cp = palloc_get_page(PAL_ZERO);
	if (cmd_line_cp == NULL) {                   /* 메모리 할당이 성공적이었는지 여부를 확인 */
		exit(-1);
	}
	/* 명령줄 문자열('cmd_line')을 null-terminator를 포함하여 새로 할당된 메모리 페이지('cmd_line_cp')에 복사 */
	strlcpy (cmd_line_cp, cmd_line, size + 1);  
	/* 복사된 명령줄 문자열을 인수로 하여 'process_exec' 함수를 호출 */
	if (process_exec(cmd_line_cp) == -1) {    
		return -1;                                 /* 실패 시 -1 리턴*/
	}

	NOT_REACHED();                              
	return 0;
}

/* 파일을 생성하는 시스템 콜 */
bool create (const char *file , unsigned initial_size){
	check_address(file);
	return filesys_create(file, initial_size);
}

/* 파일을 삭제하는 시스템 콜 */
bool remove (const char *file){
	check_address(file);
	return filesys_remove(file);
}

/*  file(첫 번째 인자)이라는 이름을 가진 파일 실행
해당 파일이 성공적으로 열렸다면, 파일 식별자로 불리는 비음수 정수(0또는 양수)를 반환하고, 
실패했다면 -1를 반환합니다. 0번 파일식별자와 1번 파일식별자는 이미 역할이 지정되어 있습니다. 
0번은 표준 입력(STDIN_FILENO)을 의미하고 1번은 표준 출력(STDOUT_FILENO)을 의미 */
int
open (const char *file) {
	check_address(file);                             
	lock_acquire(&filesys_lock);                     
	/* 주소값 검증 실패 시 락 해제 후 종료*/
	if (file == NULL) {                    
		lock_release(&filesys_lock);
		exit(-1);
	}

	struct file *open_file = filesys_open(file);
	/* 파일 열기 실패 시 락 해체 후 종료*/
	if (open_file == NULL) {
		lock_release(&filesys_lock);
		return -1;
	}
	/* 열린 파일을 현재 스레드의 파일 디스크립터 테이블에 추가
	, 반환된 파일 디스크립터 값을 저장 */
	int fd = add_file_to_fdt(open_file);

	if (fd == -1) {               /* fd 테이블에 추가 할 수 없는 경우 */
		file_close(open_file);      /* 파일 닫기 */
	}

	lock_release(&filesys_lock);
	return fd;
}

/*  fd(첫 번째 인자)로서 열려 있는 파일의 크기가 몇 바이트인지 반환 */
int
filesize (int fd) {
	struct file *open_file = get_file_from_fd_table(fd);
	
	if (open_file == NULL) {
		return -1;
	}
	return file_length(open_file);
}

/* buffer 안에 fd 로 열려있는 파일로부터 size 바이트를 읽습니다. 
실제로 읽어낸 바이트의 수 를 반환합니다 (파일 끝에서 시도하면 0). 
파일이 읽어질 수 없었다면 -1을 반환합니다.(파일 끝이라서가 아닌 다른 조건에 때문에 못 읽은 경우)  */
/**
 * buffer 안에 fd 로 열려있는 파일로부터 size 바이트 읽음
 * 
*/
int
read (int fd, void *buffer, unsigned size) {
	check_address(buffer);
	lock_acquire(&filesys_lock);

	int ret;
	struct thread *curr = thread_current();
	struct file *file_obj = get_file_from_fd_table(fd);

	if (file_obj == NULL) {	/* if no file in fdt, return -1 */
		lock_release(&filesys_lock);
		return -1;
	}
	/* STDIN */
	if (fd == STDIN) {
		int i;
		unsigned char *buf = buffer;          /* 주어진 크기만큼 데이터를 읽어서 버퍼에 저장 */
		for (i = 0; i < size; i++) {
			char c = input_getc();
			*buf++ = c;
			if (c == '\0')
				break;
		}
		ret = i;
	}
	/* STDOUT */
	else if (fd == STDOUT) {
		ret = -1;
	}
	else {	
		ret = file_read(file_obj, buffer, size);
	}

	lock_release(&filesys_lock);
	
	return ret;
}

/* 주어진 fd에 해당하는 파일에 버퍼의 데이터를 쓰는 시스템 콜 */
int
write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);                   /* 버퍼 주소가 유효한지 확인 */
	lock_acquire(&filesys_lock);            

	int ret;
	struct file *file_obj = get_file_from_fd_table(fd);
	
	if (file_obj == NULL) {
		lock_release(&filesys_lock);
		return -1;
	}

	/* STDOUT */
	if (fd == STDOUT) {
		putbuf(buffer, size);		/* to print buffer strings on the display*/
		ret = size;
	}
	/* STDIN */
	else if (fd == STDIN) {
		ret = -1;
	}
	else {
		/* 파일에 주어진 크기만큼 데이터를 쓰고 쓴 데이터 크기를 ret에 저장 */
		ret = file_write(file_obj, buffer, size);
	}

	lock_release(&filesys_lock);

	return ret;
}

/* fd의 파일 포인터를 주어진 위치로 이동시키는 함수 */
void
seek (int fd, unsigned position) {
	struct file *file_obj = get_file_from_fd_table(fd);

	if (file_obj == NULL) {
		return;
	}
	
	if (fd <= 1) {
		return;
	}
	/* 파일 포인터를 주어진 위치(position)로 이동 */
	file_seek(file_obj, position);
}

/* fd의 파일 포인터 위치를 반환하는 함수 */
unsigned
tell (int fd) {
	struct file *file_obj = get_file_from_fd_table(fd);

	if (file_obj == NULL) {
		return;
	}

	if (fd <= 1) {
		return;
	}
	/* fd가 표준 입력 또는 표준 출력인 경우, 함수를 종료 */
	file_tell(file_obj);	
}

/* 주어진 파일 디스크립터를 닫는 함수 */
void
close (int fd) {
	/* fd에 해당하는 파일을 현재 스레드의 fd_table에서 찾음 */
	struct file *file_obj = get_file_from_fd_table(fd);

	if (file_obj == NULL) {
		return;
	}

	if (fd <= 1) {
		return;
	}
	/* 현재 스레드의 파일 디스크립터 테이블에서 파일 디스크립터를 제거 */
	remove_file_from_fdt(fd);

	file_close(file_obj);
}