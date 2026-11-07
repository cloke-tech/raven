#ifdef __APPLE__
.text
.globl _start
_start:
	int3
	syscall
	int3
	ud2
#else
.section .text
.global _start
_start:
	int3
	syscall
	int3
	ud2

.section .note.GNU-stack,"",@progbits
#endif
