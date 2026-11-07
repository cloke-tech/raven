// ClokeOS: see context_darwin.h
#ifdef __APPLE__
__asm__(
	".text\n"
	".globl _raven_context_switch\n"
	"_raven_context_switch:\n"
	"\tpushq %rbp\n\tpushq %rbx\n\tpushq %r12\n\tpushq %r13\n\tpushq %r14\n\tpushq %r15\n"
	"\tmovq %rsp, (%rdi)\n"
	"\tmovq (%rsi), %rsp\n"
	"\tpopq %r15\n\tpopq %r14\n\tpopq %r13\n\tpopq %r12\n\tpopq %rbx\n\tpopq %rbp\n"
	"\tretq\n"
	".globl _raven_context_start\n"
	"_raven_context_start:\n"
	"\tmovq %r13, %rdi\n"
	"\tmovq %r14, %rsi\n"
	"\tcallq *%r12\n"
	"\tud2\n");
#endif
