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

void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	uint64_t number = f->R.rax;
	// validation(f);
	// set_kernel_stack(f);

	switch(number){
		case SYS_HALT:
			sys_halt();
			break;
		case SYS_EXIT:
			sys_exit();
			break;
		case SYS_FORK:
			if(!validation(f->R.rdi)){
				printf("is not valid\n");
				sys_exit();
			}
			sys_fork();
			break;
		case SYS_EXEC:
			if(!validation(f->R.rdi)){
				printf("is not valid\n");
				sys_exit();
			}
			sys_exec();
			break;
		case SYS_WAIT:
			sys_wait();
			break;
		default:
			break;
	}


	printf ("system call!\n");
	thread_exit ();
}
