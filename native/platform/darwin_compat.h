// ClokeOS: the Linux interfaces Raven uses that XNU does not have. Included into every source file on Darwin
// (CMake adds -include). Keep this file free of logic that belongs in the Mach backend (cpu/native_cpu_mach.cpp).
#pragma once
#ifdef __APPLE__
#ifndef __APPLE_USE_RFC_3542
#define __APPLE_USE_RFC_3542 1
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ucred.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

// ptrace's register block: the Mach backend fills it from x86_THREAD_STATE64
struct user_regs_struct {
	unsigned long long r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags, rsp, ss,
		fs_base, gs_base, ds, es, fs, gs;
};

// memfd_create: an unlinked POSIX shared memory object
#define MFD_CLOEXEC 0x0001u
#define MFD_ALLOW_SEALING 0x0002u
static inline int memfd_create(const char *name, unsigned flags)
{
	static unsigned counter;
	char path[64];
	snprintf(path, sizeof path, "/raven.%d.%u", int(getpid()), __atomic_add_fetch(&counter, 1, __ATOMIC_RELAXED));
	(void)name;
	const int fd = shm_open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
	if (fd < 0)
		return -1;
	shm_unlink(path);
	if (flags & MFD_CLOEXEC)
		fcntl(fd, F_SETFD, FD_CLOEXEC);
	return fd;
}
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define F_SEAL_WRITE 0x0008

// socket and pipe flags
#define SOCK_CLOEXEC 0x10000000
#define SOCK_NONBLOCK 0x20000000
#define MSG_CMSG_CLOEXEC 0
#define POLLRDHUP 0
#define SO_PEERCRED LOCAL_PEERCRED
#define CLOCK_BOOTTIME CLOCK_MONOTONIC
#define CLOCK_MONOTONIC_COARSE CLOCK_MONOTONIC
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#define TCP_KEEPIDLE TCP_KEEPALIVE
#define st_mtim st_mtimespec
#define st_atim st_atimespec
#define st_ctim st_ctimespec
#define O_PATH 0
#define O_NOATIME 0
#define O_DIRECT 0

static inline void raven_apply_flags(int fd, int flags)
{
	if (fd < 0)
		return;
	if (flags & SOCK_CLOEXEC)
		fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (flags & SOCK_NONBLOCK)
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}
static inline int raven_socket(int domain, int type, int protocol)
{
	const int fd = socket(domain, type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK), protocol);
	raven_apply_flags(fd, type);
	return fd;
}
static inline int raven_socketpair(int domain, int type, int protocol, int sv[2])
{
	// Darwin has no SOCK_SEQPACKET for AF_UNIX: datagram sockets keep the message boundaries
	int base = type & ~(SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (domain == AF_UNIX && base == 5 /* Linux SOCK_SEQPACKET */)
		base = SOCK_DGRAM;
	const int rc = socketpair(domain, base, protocol, sv);
	if (rc == 0) {
		raven_apply_flags(sv[0], type);
		raven_apply_flags(sv[1], type);
	}
	return rc;
}
static inline int accept4(int fd, struct sockaddr *address, socklen_t *length, int flags)
{
	const int result = accept(fd, address, length);
	raven_apply_flags(result, flags);
	return result;
}
static inline int raven_pipe2(int fds[2], int flags)
{
	const int rc = pipe(fds);
	if (rc == 0) {
		raven_apply_flags(fds[0], flags & O_NONBLOCK ? SOCK_NONBLOCK | SOCK_CLOEXEC * !!(flags & O_CLOEXEC) : SOCK_CLOEXEC * !!(flags & O_CLOEXEC));
		raven_apply_flags(fds[1], flags & O_NONBLOCK ? SOCK_NONBLOCK | SOCK_CLOEXEC * !!(flags & O_CLOEXEC) : SOCK_CLOEXEC * !!(flags & O_CLOEXEC));
	}
	return rc;
}
#define pipe2 raven_pipe2

// peer credentials of a UNIX socket: struct ucred and SO_PEERCRED
struct ucred { pid_t pid; uid_t uid; gid_t gid; };
#undef SO_PEERCRED
#define SO_PEERCRED 0x5ea1
static inline int raven_getsockopt(int fd, int level, int option, void *value, socklen_t *length)
{
	if (level == SOL_SOCKET && option == SO_PEERCRED) {
		ucred *credentials = static_cast<ucred *>(value);
		pid_t pid = 0;
		socklen_t size = sizeof pid;
		uid_t uid;
		gid_t gid;
		if (getpeereid(fd, &uid, &gid) != 0 || getsockopt(fd, 0 /* SOL_LOCAL */, 0x002 /* LOCAL_PEERPID */, &pid, &size) != 0)
			return -1;
		credentials->pid = pid;
		credentials->uid = uid;
		credentials->gid = gid;
		*length = sizeof(ucred);
		return 0;
	}
	return getsockopt(fd, level, option, value, length);
}
#define getsockopt raven_getsockopt

// reentrant netdb lookups: Darwin has only the non-reentrant ones
#include <netdb.h>
#include <mutex>
static inline std::mutex &raven_netdb_lock() { static std::mutex lock; return lock; }
static inline int getservbyname_r(const char *name, const char *protocol, servent *result, char *, size_t, servent **found)
{
	std::lock_guard lock(raven_netdb_lock());
	const servent *entry = getservbyname(name, protocol);
	*found = entry ? (*result = *entry, result) : nullptr;
	return 0;
}
static inline int getservbyport_r(int port, const char *protocol, servent *result, char *, size_t, servent **found)
{
	std::lock_guard lock(raven_netdb_lock());
	const servent *entry = getservbyport(port, protocol);
	*found = entry ? (*result = *entry, result) : nullptr;
	return 0;
}
static inline int getprotobyname_r(const char *name, protoent *result, char *, size_t, protoent **found)
{
	std::lock_guard lock(raven_netdb_lock());
	const protoent *entry = getprotobyname(name);
	*found = entry ? (*result = *entry, result) : nullptr;
	return 0;
}
static inline int getprotobynumber_r(int number, protoent *result, char *, size_t, protoent **found)
{
	std::lock_guard lock(raven_netdb_lock());
	const protoent *entry = getprotobynumber(number);
	*found = entry ? (*result = *entry, result) : nullptr;
	return 0;
}

// processors
struct cpu_set_t { unsigned long bits[16]; };
#define CPU_ZERO(set) memset((set), 0, sizeof(cpu_set_t))
#define CPU_SET(cpu, set) ((set)->bits[(cpu) / 64] |= 1ul << ((cpu) % 64))
#define CPU_ISSET(cpu, set) (((set)->bits[(cpu) / 64] >> ((cpu) % 64)) & 1ul)
static inline int CPU_COUNT(const cpu_set_t *set) { int n = 0; for (unsigned long w : set->bits) n += __builtin_popcountl(w); return n; }
static inline int sched_getaffinity(pid_t, size_t, cpu_set_t *set)
{
	memset(set, 0, sizeof *set);
	const long online = sysconf(_SC_NPROCESSORS_ONLN);
	for (long cpu = 0; cpu < online && cpu < 1024; cpu++)
		CPU_SET(cpu, set);
	return 0;
}
static inline int sched_getcpu() { return -1; }

static inline int ppoll(struct pollfd *descriptors, nfds_t count, const struct timespec *timeout, const void *)
{
	return poll(descriptors, count, timeout ? int(timeout->tv_sec * 1000 + (timeout->tv_nsec + 999999) / 1000000) : -1);
}
#ifndef SI_KERNEL
#define SI_KERNEL 0x80
#endif
#ifndef TRAP_HWBKPT
#define TRAP_HWBKPT 4
#endif
#define GRND_NONBLOCK 1
#define GRND_RANDOM 2
static inline ssize_t getrandom(void *buffer, size_t length, unsigned)
{
	size_t done = 0;
	while (done < length) {
		const size_t chunk = length - done > 256 ? 256 : length - done;
		if (getentropy(static_cast<char *>(buffer) + done, chunk) != 0)
			return done ? ssize_t(done) : -1;
		done += chunk;
	}
	return ssize_t(length);
}
#include <filesystem>
#include <mach-o/dyld.h>
// /proc/self/exe
static inline std::filesystem::path raven_self_exe(std::error_code &error)
{
	char buffer[4096];
	uint32_t size = sizeof buffer;
	if (_NSGetExecutablePath(buffer, &size) != 0) {
		error = std::make_error_code(std::errc::filename_too_long);
		return {};
	}
	return std::filesystem::canonical(buffer, error);
}
static inline std::filesystem::path raven_self_exe()
{
	std::error_code error;
	const auto path = raven_self_exe(error);
	if (error)
		throw std::filesystem::filesystem_error("cannot find the running program", error);
	return path;
}

// the replacements for the /proc/<pid>/stat reads: state, and the CPU time in nanoseconds
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
struct RavenProcess { bool exists = false, zombie = false; unsigned long long cpu_ns = 0; };
static inline RavenProcess raven_process(pid_t pid)
{
	RavenProcess result;
	proc_taskallinfo info{};
	if (proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &info, sizeof info) == int(sizeof info)) {
		result.exists = true;
		result.zombie = info.pbsd.pbi_status == SZOMB;
		result.cpu_ns = info.ptinfo.pti_total_user + info.ptinfo.pti_total_system;
	}
	return result;
}
static inline std::string raven_process_path(pid_t pid)
{
	char path[PROC_PIDPATHINFO_MAXSIZE];
	const int length = proc_pidpath(pid, path, sizeof path);
	return length > 0 ? std::string(path, size_t(length)) : std::string();
}
// fcntl: sealing is not available; sealed objects are only a safety net, so the requests succeed
template <class... Arguments> static inline int raven_fcntl(int descriptor, int command, Arguments... arguments)
{
	if (command == F_ADD_SEALS)
		return 0;
	if (command == F_GET_SEALS)
		return 0xf;
	return ::fcntl(descriptor, command, arguments...);
}
#define fcntl raven_fcntl
#define socket raven_socket
#define socketpair raven_socketpair
#endif
