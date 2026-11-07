// ClokeOS: the guest-process control of cpu/native_cpu.cpp on XNU. Raven drives its x86-64 guest with ptrace (stops, registers,
// memory, injected system calls); here the same operations are made from a Mach task port and exception messages, and
// ptrace() and the wait statuses are emulated on top of them so that native_cpu.cpp stays as it is.
#pragma once
#ifdef __APPLE__
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <thread>
#include <mach/kern_return.h>
#include <sys/types.h>
#include <sys/uio.h>

// Linux numbers: only tokens for NativeChild::syscall, which maps them to Mach VM calls
#undef SYS_mmap
#undef SYS_mprotect
#undef SYS_munmap
#undef SYS_madvise
#undef SYS_close
#undef SYS_openat
#undef SYS_recvmsg
#undef SYS_clone
#undef SYS_modify_ldt
#undef SYS_prctl
#undef SYS_seccomp
#define SYS_close 3
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_madvise 28
#define SYS_recvmsg 47
#define SYS_clone 56
#define SYS_modify_ldt 154
#define SYS_prctl 157
#define SYS_openat 257
#define SYS_seccomp 317
#define MAP_FIXED_NOREPLACE 0x00100000
#define MAP_32BIT 0x00400000
#define MADV_DONTNEED_LINUX 4
#ifndef AT_FDCWD
#define AT_FDCWD (-100)
#endif
#ifndef MSG_CMSG_CLOEXEC
#define MSG_CMSG_CLOEXEC 0
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#define __WALL 0

enum __ptrace_request {
	PTRACE_TRACEME = 0, PTRACE_PEEKTEXT = 1, PTRACE_PEEKDATA = 2, PTRACE_PEEKUSER = 3, PTRACE_POKEUSER = 6, PTRACE_CONT = 7,
	PTRACE_SINGLESTEP = 9, PTRACE_GETREGS = 12, PTRACE_SETREGS = 13, PTRACE_GETFPREGS = 14, PTRACE_SYSEMU = 31, PTRACE_SETOPTIONS = 0x4200,
	PTRACE_GETEVENTMSG = 0x4201, PTRACE_GETSIGINFO = 0x4202, PTRACE_GETREGSET = 0x4204, PTRACE_SETREGSET = 0x4205,
};
#define PTRACE_O_EXITKILL 0
#define PTRACE_O_TRACESYSGOOD 0
#define PTRACE_O_TRACECLONE 0
#define PTRACE_O_TRACESECCOMP 0
#define PTRACE_EVENT_CLONE 3
#define PTRACE_EVENT_SECCOMP 7
#define NT_X86_XSTATE 0x202
#ifndef TRAP_BRKPT
#define TRAP_BRKPT 1
#endif
#ifndef TRAP_TRACE
#define TRAP_TRACE 2
#endif

#define RAVEN_DEBUGREG_OFFSET 0
struct user_fpregs_struct { unsigned char head[160]; unsigned int xmm_space[64]; unsigned char tail[96]; };

// the ptrace requests of native_cpu.cpp; pid names a NativeChild
long raven_ptrace(enum __ptrace_request request, pid_t pid, void *address, void *data);
#define ptrace raven_ptrace
ssize_t raven_process_vm_readv(pid_t pid, const struct iovec *local, unsigned long local_count, const struct iovec *remote, unsigned long remote_count, unsigned long flags);
ssize_t raven_process_vm_writev(pid_t pid, const struct iovec *local, unsigned long local_count, const struct iovec *remote, unsigned long remote_count, unsigned long flags);
#define process_vm_readv raven_process_vm_readv
#define process_vm_writev raven_process_vm_writev

uint64_t raven_low_gap(pid_t pid, uint64_t size, uint64_t limit);

// A PE image is backed by a shared memory object that cannot be mapped executable; mapping it into the guest copies it into guest memory
// and re-points the host's view at those pages.
void raven_register_image(int descriptor, void *storage, size_t size);
void raven_unregister_image(int descriptor);

namespace raven {

class NativeChild {
public:
	NativeChild(std::span<const int> image_fds, const std::string &bootstrap, std::chrono::milliseconds timeout);
	~NativeChild();
	NativeChild(const NativeChild &) = delete;
	NativeChild &operator=(const NativeChild &) = delete;
	pid_t pid = -1;
	uint64_t gate = 0;
	int wait(const std::function<bool()> *served = nullptr);
	uint64_t syscall(uint64_t number, uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0, uint64_t a4 = 0, uint64_t a5 = 0, uint64_t a6 = 0);
	void stop();
	void send_descriptor(int) {}
	int descriptor_socket() const { return -1; }
	void set_timeout(std::chrono::milliseconds timeout);
	void enable_parallel();
	pid_t clone_task(uint64_t);
	bool take_stop(pid_t, int &) { return false; }
	void stop_task(pid_t) {}
	void pause_task() {}
	int execution_descriptor() const { return -1; }
	void drain_execution() {}
	void set_slice(std::chrono::steady_clock::duration) {}
	void ensure_slice(std::chrono::steady_clock::time_point) {}
	void clear_slice() {}

	// the emulated ptrace operations
	long request(enum __ptrace_request request, void *address, void *data);
	ssize_t read_memory(uint64_t address, void *buffer, size_t size);
	ssize_t write_memory(uint64_t address, const void *buffer, size_t size);
	// the lowest free 64 KiB aligned gap below `limit` for a 32-bit guest's allocation
	uint64_t low_gap(uint64_t size, uint64_t limit);

private:
	struct Event {
		enum Kind { stopped, exited } kind;
		int status;
		uint32_t thread;
		int signal, code;
		uint64_t address;
		std::vector<uint8_t> message;
	};
	void listen();
	void reply(kern_return_t result);
	void set_gs_base(uint64_t base);
	// 32-bit (compatibility mode) guests: the LDT, the entry stub and the translation of the ptrace registers
	uint64_t inject_syscall(uint64_t number, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t *flags = nullptr);
	void ensure_compat();
	uint64_t install_ldt_entry(uint32_t index, uint64_t descriptor);
	bool compat_ready = false, armed = false;
	uint32_t armed_eip = 0;
	uint16_t ldt_code = 0, ldt_data = 0, ldt_fs = 0;
	uint32_t ldt_fs_index = 0;
	uint64_t stub = 0;
	static constexpr uint64_t stub_address = 0x10000;
	uint32_t task = 0, exception_port = 0, thread = 0;
	std::chrono::steady_clock::time_point deadline;
	std::thread listener;
	std::mutex mutex;
	std::condition_variable ready;
	std::deque<Event> events;
	std::atomic<bool> closing{false};
	bool pending = false;
	std::vector<uint8_t> pending_message;
	int last_signal = 0, last_code = 0;
	uint64_t last_address = 0;
	uint64_t gs_base = 0;
	std::map<uint64_t, uint64_t> host_views;
};

}
#endif
