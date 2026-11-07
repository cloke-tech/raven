// ClokeOS: PureDarwin's libSystem has no getcontext/makecontext/swapcontext; the guest threads' coroutines use this small x86-64 version
#pragma once
#ifdef __APPLE__
#include <cstddef>
#include <cstdarg>
#include <cstdint>
#include <cstring>

struct RavenContext {
	void *stack_pointer = nullptr;
	struct { void *ss_sp = nullptr; size_t ss_size = 0; } uc_stack;
	RavenContext *uc_link = nullptr;
};

extern "C" void raven_context_switch(RavenContext *from, RavenContext *to);
extern "C" void raven_context_start();

static inline int getcontext(RavenContext *context)
{
	context->stack_pointer = nullptr;
	return 0;
}

static inline void makecontext(RavenContext *context, void (*function)(), int count, ...)
{
	va_list arguments;
	va_start(arguments, count);
	uint64_t first = count > 0 ? uint64_t(va_arg(arguments, unsigned)) : 0, second = count > 1 ? uint64_t(va_arg(arguments, unsigned)) : 0;
	va_end(arguments);
	auto top = reinterpret_cast<uintptr_t>(context->uc_stack.ss_sp) + context->uc_stack.ss_size;
	top &= ~uintptr_t(15);
	auto *frame = reinterpret_cast<uint64_t *>(top - 9 * 8);
	frame[0] = 0;                                        // r15
	frame[1] = second;                                   // r14: second argument
	frame[2] = first;                                    // r13: first argument
	frame[3] = reinterpret_cast<uint64_t>(function);     // r12: function
	frame[4] = 0;                                        // rbx
	frame[5] = 0;                                        // rbp
	frame[6] = reinterpret_cast<uint64_t>(&raven_context_start);
	frame[7] = frame[8] = 0;
	context->stack_pointer = frame;
}

static inline int swapcontext(RavenContext *from, RavenContext *to)
{
	raven_context_switch(from, to);
	return 0;
}
#endif
