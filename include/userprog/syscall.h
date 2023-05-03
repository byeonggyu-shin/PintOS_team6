#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* read(), write() 시스템 콜에서 파일 접근하기 전에 lock을 획득하도록 구현 */
struct lock filesys_lock;

#endif /* userprog/syscall.h */
