// ClokeOS: eventfd as a datagram socket connected to itself: write(8 bytes) posts an event, read returns one
#pragma once
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstring>
#define EFD_CLOEXEC 0x80000
#define EFD_NONBLOCK 0x800
#define EFD_SEMAPHORE 1
typedef uint64_t eventfd_t;
static inline int eventfd(unsigned initial, int flags)
{
	static unsigned counter;
	const int fd = ::socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;
	sockaddr_un address{};
	address.sun_family = AF_UNIX;
	std::snprintf(address.sun_path, sizeof address.sun_path, "/tmp/.raven-ev.%d.%u", int(::getpid()), __atomic_add_fetch(&counter, 1, __ATOMIC_RELAXED));
	address.sun_len = uint8_t(sizeof address);
	if (::bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof address) != 0 ||
		::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof address) != 0) {
		::close(fd);
		return -1;
	}
	::unlink(address.sun_path);
	if (flags & EFD_CLOEXEC)
		::fcntl(fd, F_SETFD, FD_CLOEXEC);
	if (flags & EFD_NONBLOCK)
		::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
	if (initial) {
		const uint64_t value = initial;
		[[maybe_unused]] const auto written = ::write(fd, &value, sizeof value);
	}
	return fd;
}
