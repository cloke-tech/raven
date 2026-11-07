// ClokeOS: sysinfo from sysctl
#pragma once
#include <cstdint>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/types.h>
struct sysinfo { long uptime; unsigned long loads[3], totalram, freeram, sharedram, bufferram, totalswap, freeswap; unsigned short procs;
	unsigned long totalhigh, freehigh; unsigned mem_unit; };
static inline int sysinfo(struct sysinfo *info)
{
	*info = {};
	uint64_t memory = 0;
	size_t length = sizeof memory;
	sysctlbyname("hw.memsize", &memory, &length, nullptr, 0);
	timeval boot{};
	length = sizeof boot;
	int name[2] = {CTL_KERN, KERN_BOOTTIME};
	if (sysctl(name, 2, &boot, &length, nullptr, 0) == 0) {
		timeval now{};
		gettimeofday(&now, nullptr);
		info->uptime = long(now.tv_sec - boot.tv_sec);
	}
	info->totalram = memory;
	info->freeram = memory / 2;
	info->mem_unit = 1;
	return 0;
}
