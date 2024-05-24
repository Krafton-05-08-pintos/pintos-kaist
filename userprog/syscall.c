#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

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

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */

bool validation(uint64_t *ptr){
	/* ptr이 커널 영역인지 확인 (커널영역에 접근하면 안됨) */
	printf("-----------validation start %p-----------\n", ptr);
	if(is_kernel_vaddr(ptr))
		return false;
	return true;
}

void set_kernel_stack(struct intr_frame *f){
	
}

void sys_halt(){
	printf("--------start sys_halt--------\n");
	power_off();
}

void sys_exit(int status){
	struct thread *cur_t = thread_current();
	printf("%s: exit(%d)", cur_t->name, status);
	sema_up();
	thread_exit();
	
	return;
}

int sys_exec (const char *cmd_line){
	int result = process_exec (cmd_line);
	if (result = -1){
		return -1;
	}
}

void sys_write(struct intr_frame *f)
{
    if (!validation(f->R.rsi))
    {
        printf("is not valid\n");
        sys_exit(0);
    }
	/* 표준 출력 */
	if(f->R.rdi == 1)
    	putbuf(f->R.rsi, f->R.rdx);
	else{
		printf("아직 파일 디스크립터 구현 안함\n");
	}
}


void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	uint64_t number = f->R.rax;
	
	printf("system call number : %d\n", number);
	printf("f->rdi : %d\n", f->R.rdi);
	printf("f->rsi : %s\n", f->R.rsi);
	printf("f->rdx : %d\n", f->R.rdx);
	printf("f->r10 : %d\n", f->R.r10);
	printf("f->r8 : %d\n", f->R.r8);
	printf("f->r9 : %d\n", f->R.r9);
	printf("SYS_HALT : %d\n", SYS_HALT);

	switch(number){
		case SYS_HALT:
			sys_halt();
			// set_kernel_stack(f);
			break;
		// case SYS_EXIT:
		// 	sys_exit(0);
		// 	set_kernel_stack(f);
		// 	break;
		case SYS_FORK:
			if(!validation(f->R.rdi)){
				printf("is not valid\n");
				sys_exit(0);
			}
		// 	set_kernel_stack(f);
		// 	sys_fork();
		// 	break;
		// case SYS_EXEC:
		// 	if(!validation(f->R.rdi)){
		// 		printf("is not valid\n");
		// 		sys_exit(0);
		// 	}
		// 	set_kernel_stack(f);
		// 	sys_exec();
		// 	break;
		case SYS_WAIT:
			sys_wait();
			set_kernel_stack(f);
			break;
		case SYS_WRITE:
            sys_write(f);
            // printf("%s", f->R.rsi);
			return;
		default:
			break;
	}


	printf ("system call!\n");
	thread_exit ();
}
