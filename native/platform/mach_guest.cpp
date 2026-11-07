// ClokeOS: guest-process control on XNU, see mach_guest.h
#ifdef __APPLE__
#include "platform/mach_guest.h"

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <spawn.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdexcept>
#include <vector>

extern char **environ;
// Defined by darwin_compat.h as an alias of the Linux user_regs_struct
#include "platform/darwin_compat.h"
#undef ptrace

namespace {

// PureDarwin's kernel prints a line for every mach_vm_allocate on another task; mach_vm_map without an object does the same silently
constexpr mach_vm_address_t anywhere_start = 0x100000000000ULL;

kern_return_t allocate(mach_port_t task, mach_vm_address_t *address, mach_vm_size_t size, int flags)
{
	if ((flags & VM_FLAGS_ANYWHERE) && *address == 0)
		*address = anywhere_start;
	return mach_vm_map(task, address, size, 0, flags, MACH_PORT_NULL, 0, FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_ALL, VM_INHERIT_NONE);
}

std::mutex children_lock;
std::mutex images_lock;
std::map<int, std::pair<void *, size_t>> images;
std::map<pid_t, raven::NativeChild *> children;

#pragma pack(4)
struct ExceptionRequest {
	mach_msg_header_t head;
	mach_msg_body_t body;
	mach_msg_port_descriptor_t thread, task;
	NDR_record_t ndr;
	exception_type_t exception;
	mach_msg_type_number_t code_count;
	int64_t code[2];
	char padding[512];
};
struct ExceptionReply {
	mach_msg_header_t head;
	NDR_record_t ndr;
	kern_return_t result;
};
#pragma pack()

[[noreturn]] void fail(const std::string &what, kern_return_t result)
{
	throw std::runtime_error("native " + what + ": " + mach_error_string(result));
}

void protect(mach_port_t task, uint64_t address, uint64_t size, int protection)
{
	vm_prot_t rights = VM_PROT_NONE;
	if (protection & PROT_READ) rights |= VM_PROT_READ;
	if (protection & PROT_WRITE) rights |= VM_PROT_WRITE;
	if (protection & PROT_EXEC) rights |= VM_PROT_EXECUTE;
	const auto result = mach_vm_protect(task, address, size, FALSE, rights);
	if (result != KERN_SUCCESS) {
		if (std::getenv("RAVEN_TRACE_API")) {
			vm_region_basic_info_data_64_t info;
			mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
			mach_port_t object;
			mach_vm_address_t probe = address;
			mach_vm_size_t probed = 0;
			const auto found = mach_vm_region(task, &probe, &probed, VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_t>(&info), &count, &object);
			std::fprintf(stderr, "raven: mprotect %llx+%llx to %d failed; region %llx+%llx found=%d prot=%d max=%d shared=%d\n", (unsigned long long)address,
				(unsigned long long)size, int(rights), (unsigned long long)probe, (unsigned long long)probed, int(found), int(info.protection),
				int(info.max_protection), int(info.shared));
		}
		fail("mprotect", result);
	}
}

}

void raven_register_image(int descriptor, void *storage, size_t size)
{
	std::lock_guard lock(images_lock);
	images[descriptor] = {storage, size};
}

void raven_unregister_image(int descriptor)
{
	std::lock_guard lock(images_lock);
	images.erase(descriptor);
}

uint64_t raven_low_gap(pid_t pid, uint64_t size, uint64_t limit)
{
	raven::NativeChild *child = nullptr;
	{
		std::lock_guard lock(children_lock);
		const auto found = children.find(pid);
		if (found != children.end())
			child = found->second;
	}
	return child ? child->low_gap(size, limit) : 0;
}

long raven_ptrace(enum __ptrace_request request, pid_t pid, void *address, void *data)
{
	raven::NativeChild *child = nullptr;
	{
		std::lock_guard lock(children_lock);
		const auto found = children.find(pid);
		if (found != children.end())
			child = found->second;
	}
	if (!child) {
		errno = ESRCH;
		return -1;
	}
	return child->request(request, address, data);
}

ssize_t raven_process_vm_readv(pid_t pid, const struct iovec *local, unsigned long, const struct iovec *remote, unsigned long, unsigned long)
{
	raven::NativeChild *child = nullptr;
	{
		std::lock_guard lock(children_lock);
		const auto found = children.find(pid);
		if (found != children.end())
			child = found->second;
	}
	if (!child) { errno = ESRCH; return -1; }
	return child->read_memory(reinterpret_cast<uint64_t>(remote->iov_base), local->iov_base, local->iov_len);
}

ssize_t raven_process_vm_writev(pid_t pid, const struct iovec *local, unsigned long, const struct iovec *remote, unsigned long, unsigned long)
{
	raven::NativeChild *child = nullptr;
	{
		std::lock_guard lock(children_lock);
		const auto found = children.find(pid);
		if (found != children.end())
			child = found->second;
	}
	if (!child) { errno = ESRCH; return -1; }
	return child->write_memory(reinterpret_cast<uint64_t>(remote->iov_base), local->iov_base, local->iov_len);
}

namespace raven {

NativeChild::NativeChild(std::span<const int>, const std::string &bootstrap, std::chrono::milliseconds timeout)
	: deadline(std::chrono::steady_clock::now() + timeout)
{
	posix_spawnattr_t attributes;
	posix_spawnattr_init(&attributes);
	posix_spawnattr_setflags(&attributes, POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETPGROUP);
	posix_spawnattr_setpgroup(&attributes, 0);
	char *arguments[] = {const_cast<char *>(bootstrap.c_str()), nullptr};
	const int spawned = posix_spawn(&pid, bootstrap.c_str(), nullptr, &attributes, arguments, environ);
	posix_spawnattr_destroy(&attributes);
	if (spawned != 0) {
		pid = -1;
		throw std::runtime_error("cannot start native guest: " + std::string(std::strerror(spawned)));
	}
	mach_port_t guest_task = MACH_PORT_NULL;
	kern_return_t result = task_for_pid(mach_task_self(), pid, &guest_task);
	if (result != KERN_SUCCESS) {
		kill(pid, SIGKILL);
		waitpid(pid, nullptr, 0);
		pid = -1;
		fail("task_for_pid (run as root)", result);
	}
	task = guest_task;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exception_port);
	mach_port_insert_right(mach_task_self(), exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND);
	result = task_set_exception_ports(task, EXC_MASK_BREAKPOINT | EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC |
		EXC_MASK_SOFTWARE | EXC_MASK_EMULATION | EXC_MASK_SYSCALL | EXC_MASK_MACH_SYSCALL, exception_port, EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, x86_THREAD_STATE64);
	if (result != KERN_SUCCESS) {
		stop();
		fail("task_set_exception_ports", result);
	}
	{
		std::lock_guard lock(children_lock);
		children[pid] = this;
	}
	listener = std::thread([this] { listen(); });
	try {
		task_resume(task);
		const int status = wait();
		if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
			throw std::runtime_error("native bootstrap did not reach setup trap");
		user_regs_struct registers{};
		request(PTRACE_GETREGS, nullptr, &registers);
		gate = registers.rip - 1;
		uint32_t code = 0;
		if (read_memory(gate, &code, sizeof code) != ssize_t(sizeof code) || code != 0xcc050fcc)
			throw std::runtime_error("native bootstrap syscall gate is invalid");
	} catch (...) {
		stop();
		throw;
	}
}

NativeChild::~NativeChild()
{
	stop();
}

void NativeChild::set_timeout(std::chrono::milliseconds timeout)
{
	if (timeout.count() <= 0)
		throw std::runtime_error("native execution requires a positive timeout");
	deadline = std::chrono::steady_clock::now() + timeout;
}

void NativeChild::enable_parallel()
{
	throw std::runtime_error("parallel native execution is not supported on ClokeOS");
}

pid_t NativeChild::clone_task(uint64_t)
{
	throw std::runtime_error("parallel native execution is not supported on ClokeOS");
}

void NativeChild::stop()
{
	closing = true;
	if (pid != -1) {
		{
			std::lock_guard lock(children_lock);
			children.erase(pid);
		}
		kill(pid, SIGKILL);
	}
	if (listener.joinable())
		listener.join();
	if (pid != -1) {
		int status = 0;
		while (waitpid(pid, &status, 0) == -1 && errno == EINTR) {}
		pid = -1;
	}
	if (thread != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), thread);
		thread = MACH_PORT_NULL;
	}
	if (exception_port != MACH_PORT_NULL) {
		mach_port_destroy(mach_task_self(), exception_port);
		exception_port = MACH_PORT_NULL;
	}
	if (task != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), task);
		task = MACH_PORT_NULL;
	}
	pending = false;
}

void NativeChild::listen()
{
	ExceptionRequest message;
	while (!closing) {
		const kern_return_t result = mach_msg(&message.head, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, sizeof message, exception_port, 20, MACH_PORT_NULL);
		if (result == KERN_SUCCESS) {
			Event event{Event::stopped, 0, message.thread.name, SIGSEGV, 0, 0, {}};
			if (message.task.name != MACH_PORT_NULL)
				mach_port_deallocate(mach_task_self(), message.task.name);
			const int64_t code0 = message.code_count > 0 ? message.code[0] : 0;
			const int64_t code1 = message.code_count > 1 ? message.code[1] : 0;
			switch (message.exception) {
			case EXC_BREAKPOINT:
				event.signal = SIGTRAP;
				event.code = code0 == 1 ? 2 /* TRAP_TRACE */ : 1 /* TRAP_BRKPT */;
				break;
			case EXC_BAD_ACCESS:
				event.signal = SIGSEGV;
				event.code = code0 == KERN_INVALID_ADDRESS ? 1 : code0 == KERN_PROTECTION_FAILURE ? 2 : 0x80;
				event.address = code0 == KERN_INVALID_ADDRESS || code0 == KERN_PROTECTION_FAILURE ? uint64_t(code1) : 0;
				if (std::getenv("RAVEN_TRACE_API")) {
					vm_region_basic_info_data_64_t info{};
					mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
					mach_port_t object;
					mach_vm_address_t probe = uint64_t(code1);
					mach_vm_size_t probed = 0;
					const auto found = mach_vm_region(task, &probe, &probed, VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_t>(&info), &count, &object);
					x86_thread_state64_t seg{};
					mach_msg_type_number_t seg_count = x86_THREAD_STATE64_COUNT;
					thread_get_state(message.thread.name, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&seg), &seg_count);
					uint8_t stubdata[16] = {};
					if (compat_ready)
						read_memory(stub + 0x40, stubdata, sizeof stubdata);
					std::fprintf(stderr, "raven: segments cs=%llx fs=%llx gs=%llx rip=%llx rsp=%llx; ldt code=%x data=%x fs=%x; stub data: %02x%02x %02x%02x far %02x%02x%02x%02x %02x%02x\n",
						(unsigned long long)seg.__cs, (unsigned long long)seg.__fs, (unsigned long long)seg.__gs, (unsigned long long)seg.__rip, (unsigned long long)seg.__rsp,
						ldt_code, ldt_data, ldt_fs, stubdata[1], stubdata[0], stubdata[3], stubdata[2], stubdata[7], stubdata[6], stubdata[5], stubdata[4], stubdata[9], stubdata[8]);
					std::fprintf(stderr, "raven: access fault code=%lld addr=%llx; region %llx+%llx found=%d prot=%d max=%d\n", (long long)code0, (unsigned long long)code1,
						(unsigned long long)probe, (unsigned long long)probed, int(found), int(info.protection), int(info.max_protection));
				}
				break;
			case EXC_BAD_INSTRUCTION:
				event.signal = SIGILL;
				event.code = 1;
				break;
			case EXC_SYSCALL:
			case EXC_MACH_SYSCALL:
				event.signal = SIGTRAP | 0x80;
				event.code = 0;
				event.address = uint64_t(code0) & 0xffffff;
				break;
			case EXC_ARITHMETIC:
				event.signal = SIGFPE;
				event.code = 1;
				break;
			default:
				event.signal = SIGILL;
				event.code = 1;
			}
			if (std::getenv("RAVEN_TRACE_STOPS"))
				std::fprintf(stderr, "raven: guest exception %d code=%lld,%llx -> signal %d\n", int(message.exception), (long long)code0, (unsigned long long)code1, event.signal);
			event.message.assign(reinterpret_cast<uint8_t *>(&message.head), reinterpret_cast<uint8_t *>(&message.head) + sizeof message.head);
			{
				std::lock_guard lock(mutex);
				events.push_back(std::move(event));
			}
			ready.notify_all();
			continue;
		}
		int status = 0;
		const pid_t exited = waitpid(pid, &status, WNOHANG);
		if (exited == pid && (WIFEXITED(status) || WIFSIGNALED(status))) {
			{
				std::lock_guard lock(mutex);
				events.push_back(Event{Event::exited, status, 0, 0, 0, 0, {}});
			}
			ready.notify_all();
			return;
		}
	}
}

int NativeChild::wait(const std::function<bool()> *)
{
	std::unique_lock lock(mutex);
	if (!ready.wait_until(lock, deadline, [&] { return !events.empty(); }))
		return -1;
	Event event = std::move(events.front());
	events.pop_front();
	if (event.kind == Event::exited) {
		pid = -1;
		return event.status;
	}
	if (thread != MACH_PORT_NULL && thread != event.thread)
		mach_port_deallocate(mach_task_self(), thread);
	thread = event.thread;
	pending = true;
	pending_message = std::move(event.message);
	last_signal = event.signal;
	last_code = event.code;
	last_address = event.address;
	return (event.signal << 8) | 0x7f;
}

void NativeChild::reply(kern_return_t result)
{
	if (!pending)
		return;
	pending = false;
	armed = false;
	mach_msg_header_t request;
	std::memcpy(&request, pending_message.data(), sizeof request);
	ExceptionReply answer{};
	answer.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(request.msgh_bits), 0);
	answer.head.msgh_size = sizeof answer;
	answer.head.msgh_remote_port = request.msgh_remote_port;
	answer.head.msgh_local_port = MACH_PORT_NULL;
	answer.head.msgh_id = request.msgh_id + 100;
	answer.ndr = NDR_record;
	answer.result = result;
	mach_msg(&answer.head, MACH_SEND_MSG | MACH_SEND_TIMEOUT, sizeof answer, 0, MACH_PORT_NULL, 1000, MACH_PORT_NULL);
}

ssize_t NativeChild::read_memory(uint64_t address, void *buffer, size_t size)
{
	mach_vm_size_t done = 0;
	const kern_return_t result = mach_vm_read_overwrite(task, address, size, reinterpret_cast<mach_vm_address_t>(buffer), &done);
	if (result != KERN_SUCCESS) {
		errno = EFAULT;
		return -1;
	}
	return ssize_t(done);
}

ssize_t NativeChild::write_memory(uint64_t address, const void *buffer, size_t size)
{
	const kern_return_t result = mach_vm_write(task, address, reinterpret_cast<vm_offset_t>(buffer), mach_msg_type_number_t(size));
	if (result != KERN_SUCCESS) {
		errno = EFAULT;
		return -1;
	}
	return ssize_t(size);
}

void NativeChild::set_gs_base(uint64_t base)
{
	if (base == gs_base)
		return;
	// The guest sets its own GS base: the thread runs the machine-dependent call _thread_set_tsd_base at the bootstrap gate and stops
	// at the next trap there; its registers are put back afterwards.
	x86_thread_state64_t saved;
	mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
	if (thread_get_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&saved), &count) != KERN_SUCCESS)
		throw std::runtime_error("cannot read guest registers");
	x86_thread_state64_t call = saved;
	call.__rip = gate + 1;
	call.__rax = 0x3000003;
	call.__rdi = base;
	call.__rsi = 0;
	thread_set_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&call), count);
	reply(KERN_SUCCESS);
	const auto previous = deadline;
	deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	const int status = wait();
	deadline = previous;
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
		throw std::runtime_error("native GS base call did not reach its trap");
	count = x86_THREAD_STATE64_COUNT;
	x86_thread_state64_t after;
	thread_get_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&after), &count);
	if (after.__rip != gate + 4)
		throw std::runtime_error("native GS base call stopped outside its gate");
	thread_set_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&saved), x86_THREAD_STATE64_COUNT);
	gs_base = base;
}

uint64_t NativeChild::low_gap(uint64_t size, uint64_t limit)
{
	constexpr uint64_t granularity = 0x10000;
	uint64_t candidate = 0x20000;
	for (;;) {
		mach_vm_address_t probe = candidate;
		mach_vm_size_t probed = 0;
		vm_region_basic_info_data_64_t info;
		mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
		mach_port_t object;
		if (mach_vm_region(task, &probe, &probed, VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_t>(&info), &count, &object) != KERN_SUCCESS)
			return candidate < limit && limit - candidate >= size ? candidate : 0;
		if (probe >= limit)
			return candidate < limit && limit - candidate >= size ? candidate : 0;
		if (probe >= candidate && probe - candidate >= size)
			return candidate;
		candidate = std::max(candidate, (probe + probed + granularity - 1) & ~(granularity - 1));
	}
}

// Runs one system call of the guest's own thread at the bootstrap gate (the thread stops at the next trap there) and restores its registers.
uint64_t NativeChild::inject_syscall(uint64_t number, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t *flags)
{
	x86_thread_state64_t saved;
	mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
	if (thread_get_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&saved), &count) != KERN_SUCCESS)
		throw std::runtime_error("cannot read guest registers");
	x86_thread_state64_t call = saved;
	call.__rip = gate + 1;
	call.__rax = number;
	call.__rdi = a1;
	call.__rsi = a2;
	call.__rdx = a3;
	thread_set_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&call), count);
	reply(KERN_SUCCESS);
	const auto previous = deadline;
	deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
	const int status = wait();
	deadline = previous;
	if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
		throw std::runtime_error("native guest system call did not reach its trap");
	x86_thread_state64_t after;
	count = x86_THREAD_STATE64_COUNT;
	thread_get_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&after), &count);
	if (after.__rip != gate + 4)
		throw std::runtime_error("native guest system call stopped outside its gate");
	if (flags)
		*flags = after.__rflags;
	thread_set_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&saved), x86_THREAD_STATE64_COUNT);
	return after.__rax;
}

// i386_set_ldt of the machine-dependent calls (class 3, number 5); index 0xffffffff lets the kernel choose
uint64_t NativeChild::install_ldt_entry(uint32_t index, uint64_t descriptor)
{
	write_memory(stub_address + 0x800, &descriptor, sizeof descriptor);
	uint64_t flags = 0;
	const uint64_t result = inject_syscall(0x3000005, index, stub_address + 0x800, 1, &flags);
	if (flags & 1)
		throw std::runtime_error("i386_set_ldt failed: " + std::to_string(result));
	return result;
}

void NativeChild::ensure_compat()
{
	if (compat_ready)
		return;
	// The entry stub: loads DS, ES and FS from its data and jumps far into the 32-bit code; no general register is touched.
	mach_vm_address_t where = stub_address;
	if (mach_vm_map(task, &where, 4096, 0, VM_FLAGS_FIXED, MACH_PORT_NULL, 0, FALSE, VM_PROT_ALL, VM_PROT_ALL, VM_INHERIT_NONE) != KERN_SUCCESS)
		throw std::runtime_error("cannot map the 32-bit entry stub");
	stub = stub_address;
	ldt_code = uint16_t((install_ldt_entry(0xffffffffu, 0x00CFFA000000FFFFULL) << 3) | 7);
	ldt_data = uint16_t((install_ldt_entry(0xffffffffu, 0x00CFF2000000FFFFULL) << 3) | 7);
	// the FS descriptor is rewritten for every TEB; its index is chosen now
	ldt_fs_index = uint32_t(install_ldt_entry(0xffffffffu, 0x00CFF2000000FFFFULL));
	ldt_fs = uint16_t((ldt_fs_index << 3) | 7);
	uint8_t code[128] = {};
	size_t at = 0;
	auto rel = [&](size_t instruction_end, size_t target) { return int32_t(int64_t(target) - int64_t(instruction_end)); };
	const size_t data = 0x40;                       // ds_sel at 0x40, fs_sel at 0x42, far pointer at 0x44 (eip, cs)
	code[at++] = 0x8e; code[at++] = 0x1d; { const int32_t r = rel(at + 4, data); std::memcpy(code + at, &r, 4); at += 4; }       // mov ds_sel(%rip),%ds
	code[at++] = 0x8e; code[at++] = 0x05; { const int32_t r = rel(at + 4, data); std::memcpy(code + at, &r, 4); at += 4; }       // mov ds_sel(%rip),%es
	code[at++] = 0x8e; code[at++] = 0x25; { const int32_t r = rel(at + 4, data + 2); std::memcpy(code + at, &r, 4); at += 4; }   // mov fs_sel(%rip),%fs
	code[at++] = 0xff; code[at++] = 0x2d; { const int32_t r = rel(at + 4, data + 4); std::memcpy(code + at, &r, 4); at += 4; }   // ljmp *far(%rip)
	std::memcpy(code + data, &ldt_data, 2);
	std::memcpy(code + data + 2, &ldt_fs, 2);
	write_memory(stub, code, sizeof code);
	compat_ready = true;
}

long NativeChild::request(enum __ptrace_request operation, void *address, void *data)
{
	switch (operation) {
	case PTRACE_CONT:
	case PTRACE_SYSEMU:
		if (!pending) {
			errno = ESRCH;
			return -1;
		}
		reply(KERN_SUCCESS);
		return 0;
	case PTRACE_SINGLESTEP: {
		x86_thread_state64_t state;
		mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
		thread_get_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), &count);
		state.__rflags |= 0x100;
		thread_set_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), count);
		reply(KERN_SUCCESS);
		return 0;
	}
	case PTRACE_SETOPTIONS:
		return 0;
	case PTRACE_GETREGS: {
		if (!pending) { errno = ESRCH; return -1; }
		x86_thread_state64_t state;
		mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
		if (thread_get_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), &count) != KERN_SUCCESS) {
			errno = ESRCH;
			return -1;
		}
		auto &r = *static_cast<user_regs_struct *>(data);
		r = {};
		r.r15 = state.__r15; r.r14 = state.__r14; r.r13 = state.__r13; r.r12 = state.__r12; r.rbp = state.__rbp; r.rbx = state.__rbx;
		r.r11 = state.__r11; r.r10 = state.__r10; r.r9 = state.__r9; r.r8 = state.__r8; r.rax = state.__rax; r.rcx = state.__rcx;
		r.rdx = state.__rdx; r.rsi = state.__rsi; r.rdi = state.__rdi; r.orig_rax = last_signal == (SIGTRAP | 0x80) ? last_address : uint64_t(-1); r.rip = state.__rip;
		r.cs = state.__cs; r.eflags = state.__rflags; r.rsp = state.__rsp; r.ss = 0x2b; r.fs_base = 0; r.gs_base = gs_base;
		r.fs = state.__fs; r.gs = state.__gs;
		if (compat_ready && (state.__cs == ldt_code || armed)) {
			if (armed)
				r.rip = armed_eip;
			// the guest stopped in compatibility mode: the registers read as under Linux (selectors 0x23 and 0x2b, FS entry 0)
			r.cs = 0x23;
			r.ss = r.ds = r.es = 0x2b;
			r.fs = 7;
			r.gs = 0;
		}
		return 0;
	}
	case PTRACE_SETREGS: {
		if (!pending) { errno = ESRCH; return -1; }
		const auto &r = *static_cast<const user_regs_struct *>(data);
		if (std::getenv("RAVEN_TRACE_STOPS"))
			std::fprintf(stderr, "raven: setregs rip=%llx rsp=%llx cs=%llx rax=%llx\n", (unsigned long long)r.rip, (unsigned long long)r.rsp, (unsigned long long)r.cs, (unsigned long long)r.rax);
		x86_thread_state64_t state;
		mach_msg_type_number_t count = x86_THREAD_STATE64_COUNT;
		if (thread_get_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), &count) != KERN_SUCCESS) {
			errno = ESRCH;
			return -1;
		}
		state.__r15 = r.r15; state.__r14 = r.r14; state.__r13 = r.r13; state.__r12 = r.r12; state.__rbp = r.rbp; state.__rbx = r.rbx;
		state.__r11 = r.r11; state.__r10 = r.r10; state.__r9 = r.r9; state.__r8 = r.r8; state.__rax = r.rax; state.__rcx = r.rcx;
		state.__rdx = r.rdx; state.__rsi = r.rsi; state.__rdi = r.rdi; state.__rip = r.rip; state.__rflags = r.eflags; state.__rsp = r.rsp;
		if (r.cs == 0x23) {
			// 32-bit code: the thread re-enters compatibility mode through the stub, whose far pointer holds the target
			ensure_compat();
			const uint32_t eip = uint32_t(r.rip);
			uint8_t far[6];
			std::memcpy(far, &eip, 4);
			std::memcpy(far + 4, &ldt_code, 2);
			write_memory(stub + 0x44, far, 6);
			state.__rip = stub;
			state.__rsp = uint32_t(r.rsp);
			armed = true;
			armed_eip = eip;
		} else
			armed = false;
		if (thread_set_state(thread, x86_THREAD_STATE64, reinterpret_cast<thread_state_t>(&state), count) != KERN_SUCCESS) {
			errno = EIO;
			return -1;
		}
		if (r.cs != 0x23 && r.gs_base != gs_base)
			set_gs_base(r.gs_base);
		return 0;
	}
	case PTRACE_GETSIGINFO: {
		auto *info = static_cast<siginfo_t *>(data);
		*info = {};
		info->si_signo = last_signal;
		info->si_code = last_code;
		info->si_addr = reinterpret_cast<void *>(last_address);
		return 0;
	}
	case PTRACE_GETFPREGS: {
		if (!pending) { errno = ESRCH; return -1; }
		x86_float_state64_t plain;
		mach_msg_type_number_t count = x86_FLOAT_STATE64_COUNT;
		if (thread_get_state(thread, x86_FLOAT_STATE64, reinterpret_cast<thread_state_t>(&plain), &count) != KERN_SUCCESS) {
			errno = EIO;
			return -1;
		}
		std::memcpy(data, &plain.__fpu_fcw, 512);
		return 0;
	}
	case PTRACE_GETREGSET:
	case PTRACE_SETREGSET: {
		if (!pending) { errno = ESRCH; return -1; }
		auto *vector = static_cast<iovec *>(data);
		const bool avx = true;
		x86_avx_state64_t state;
		mach_msg_type_number_t count = x86_AVX_STATE64_COUNT;
		kern_return_t result = thread_get_state(thread, x86_AVX_STATE64, reinterpret_cast<thread_state_t>(&state), &count);
		bool have_avx = avx && result == KERN_SUCCESS;
		if (!have_avx) {
			x86_float_state64_t plain;
			count = x86_FLOAT_STATE64_COUNT;
			if (thread_get_state(thread, x86_FLOAT_STATE64, reinterpret_cast<thread_state_t>(&plain), &count) != KERN_SUCCESS) {
				errno = EIO;
				return -1;
			}
			std::memset(&state, 0, sizeof state);
			std::memcpy(&state, &plain, sizeof plain);
		}
		const size_t size = have_avx ? 832 : 576;
		auto *fx = reinterpret_cast<uint8_t *>(&state.__fpu_fcw);
		auto *high = reinterpret_cast<uint8_t *>(&state.__fpu_ymmh0);
		if (operation == PTRACE_GETREGSET) {
			if (vector->iov_len < size) { errno = EINVAL; return -1; }
			auto *out = static_cast<uint8_t *>(vector->iov_base);
			std::memset(out, 0, size);
			std::memcpy(out, fx, 512);
			const uint64_t mask = have_avx ? 7 : 3;
			std::memcpy(out + 512, &mask, 8);
			if (have_avx)
				std::memcpy(out + 576, high, 256);
			vector->iov_len = size;
			return 0;
		}
		if (vector->iov_len < 512) { errno = EINVAL; return -1; }
		const auto *in = static_cast<const uint8_t *>(vector->iov_base);
		std::memcpy(fx, in, 512);
		if (have_avx && vector->iov_len >= 832)
			std::memcpy(high, in + 576, 256);
		const kern_return_t set = have_avx ? thread_set_state(thread, x86_AVX_STATE64, reinterpret_cast<thread_state_t>(&state), x86_AVX_STATE64_COUNT) :
			thread_set_state(thread, x86_FLOAT_STATE64, reinterpret_cast<thread_state_t>(&state), x86_FLOAT_STATE64_COUNT);
		if (set != KERN_SUCCESS) { errno = EIO; return -1; }
		return 0;
	}
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA: {
		uint64_t word = 0;
		errno = 0;
		if (read_memory(reinterpret_cast<uint64_t>(address), &word, sizeof word) != ssize_t(sizeof word)) {
			errno = EIO;
			return -1;
		}
		return long(word);
	}
	case PTRACE_POKEUSER:
		return 0;
	default:
		errno = ENOSYS;
		return -1;
	}
}

uint64_t NativeChild::syscall(uint64_t number, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6)
{
	switch (number) {
	case SYS_mmap: {
		uint64_t address = a1;
		const uint64_t size = a2;
		const int protection = int(a3), flags = int(a4);
		const int descriptor = int(a5);
		const uint64_t offset = a6;
		const bool fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE);
		const int placement = (fixed && address ? VM_FLAGS_FIXED : VM_FLAGS_ANYWHERE) | ((flags & MAP_FIXED) ? VM_FLAGS_OVERWRITE : 0);
		kern_return_t result;
		if (flags & MAP_ANON) {
			if (flags & MAP_FIXED)
				mach_vm_deallocate(task, address, size);
			mach_vm_address_t where = address;
			if ((flags & MAP_32BIT) && !address) {
				where = low_gap(size, 0x100000000ULL);
				if (!where)
					throw std::runtime_error("native mmap: no 32-bit address space left");
				result = allocate(task, &where, size, VM_FLAGS_FIXED);
			} else
				result = allocate(task, &where, size, (fixed && address ? VM_FLAGS_FIXED : VM_FLAGS_ANYWHERE));
			if (result != KERN_SUCCESS)
				fail("mmap", result);
			if (protection != (PROT_READ | PROT_WRITE))
				protect(task, where, size, protection);
			return where;
		}
		std::pair<void *, size_t> image{nullptr, 0};
		{
			std::lock_guard lock(images_lock);
			const auto found = images.find(descriptor);
			if (found != images.end())
				image = found->second;
		}
		if (image.first && offset == 0 && size <= image.second) {
			// a PE image: its pages are copied into guest memory and the host's view is replaced by a shared view of them
			if (flags & MAP_FIXED)
				mach_vm_deallocate(task, address, size);
			mach_vm_address_t where = address;
			result = allocate(task, &where, size, (fixed && address ? VM_FLAGS_FIXED : VM_FLAGS_ANYWHERE));
			if (result != KERN_SUCCESS)
				fail("mmap of an image", result);
			result = mach_vm_write(task, where, reinterpret_cast<vm_offset_t>(image.first), mach_msg_type_number_t(size));
			if (result != KERN_SUCCESS)
				fail("copy of an image", result);
			vm_address_t host = reinterpret_cast<vm_address_t>(image.first);
			vm_prot_t current = VM_PROT_NONE, maximum = VM_PROT_NONE;
			result = vm_remap(mach_task_self(), &host, size, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, task, where, FALSE, &current, &maximum, VM_INHERIT_NONE);
			if (result != KERN_SUCCESS)
				fail("sharing of an image", result);
			if (protection != (PROT_READ | PROT_WRITE))
				protect(task, where, size, protection);
			return where;
		}
		// a shared object: the host maps it, a memory entry names its pages, and the guest maps the entry
		void *view = mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, descriptor, off_t(offset));
		if (view == MAP_FAILED)
			view = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, off_t(offset));
		if (view == MAP_FAILED)
			throw std::runtime_error("native mmap: cannot map the shared object in the host: " + std::string(std::strerror(errno)));
		// vm_remap without copying shares the host's pages with the guest
		vm_address_t remapped = address;
		vm_prot_t current = VM_PROT_NONE, maximum = VM_PROT_NONE;
		const int remap_flags = (fixed && address ? VM_FLAGS_FIXED : VM_FLAGS_ANYWHERE) | ((flags & MAP_FIXED) ? VM_FLAGS_OVERWRITE : 0);
		if ((remap_flags & VM_FLAGS_ANYWHERE) && remapped == 0)
			remapped = anywhere_start;
		result = vm_remap(task, &remapped, size, 0, remap_flags, mach_task_self(), reinterpret_cast<vm_address_t>(view), FALSE, &current, &maximum,
			VM_INHERIT_NONE);
		munmap(view, size);
		if (result != KERN_SUCCESS)
			fail("mmap of a shared object", result);
		const mach_vm_address_t where = remapped;
		if (protection != (VM_PROT_READ | VM_PROT_WRITE))
			protect(task, where, size, protection);
		return where;
	}
	case SYS_mprotect:
		protect(task, a1, a2, int(a3));
		return 0;
	case SYS_munmap: {
		const auto result = mach_vm_deallocate(task, a1, a2);
		if (result != KERN_SUCCESS)
			fail("munmap", result);
		return 0;
	}
	case SYS_madvise: {
		// MADV_DONTNEED: the pages read as zero again
		mach_vm_address_t where = a1;
		mach_vm_size_t size = a2;
		vm_region_basic_info_data_64_t info;
		mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
		mach_port_t object;
		mach_vm_address_t probe = a1;
		mach_vm_size_t probed = 0;
		if (mach_vm_region(task, &probe, &probed, VM_REGION_BASIC_INFO_64, reinterpret_cast<vm_region_info_t>(&info), &count, &object) != KERN_SUCCESS || probe > a1)
			return 0;
		const vm_prot_t rights = info.protection;
		mach_vm_deallocate(task, where, size);
		if (allocate(task, &where, size, VM_FLAGS_FIXED) != KERN_SUCCESS)
			throw std::runtime_error("native madvise: cannot re-create the pages");
		if (rights != (VM_PROT_READ | VM_PROT_WRITE))
			mach_vm_protect(task, where, size, FALSE, rights);
		return 0;
	}
	case SYS_openat: {
		// the descriptor named as /proc/<pid>/fd/<n> is the host's own: the guest and the host share one descriptor table here
		char path[128] = {};
		if (read_memory(a2, path, sizeof path - 1) < 0)
			throw std::runtime_error("native openat: cannot read the path");
		const char *marker = std::strstr(path, "/fd/");
		if (!marker)
			throw std::runtime_error("native openat: unsupported path");
		return uint64_t(std::atoi(marker + 4));
	}
	case SYS_modify_ldt: {
		// func 1: write one entry (struct user_desc: entry, base, limit, flags); the guest's TEB descriptor, always entry 0 under Linux
		if (a1 != 1)
			throw std::runtime_error("native modify_ldt: only writing an entry is supported");
		uint32_t fields[4] = {};
		if (read_memory(a2, fields, sizeof fields) < 0)
			throw std::runtime_error("native modify_ldt: cannot read the descriptor");
		ensure_compat();
		const uint64_t base = fields[1], limit = fields[2];
		const uint64_t descriptor = (limit & 0xffff) | ((base & 0xffffff) << 16) | (uint64_t(0xF2) << 40) | (((limit >> 16) & 0xf) << 48) |
			(uint64_t((fields[3] & 0x10) ? 0xc : 0x4) << 52) | ((base >> 24) << 56);
		install_ldt_entry(ldt_fs_index, descriptor);
		return 0;
	}
	case SYS_close:
		return 0;
	default:
		throw std::runtime_error("native syscall " + std::to_string(number) + " is not available on ClokeOS");
	}
}

}
#endif
