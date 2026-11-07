// ClokeOS: futex on a word in shared memory (every process of the prefix maps it) through the ulock calls of libsystem_kernel
#pragma once
#include <cstdint>
extern "C" int __ulock_wait(uint32_t operation, void *address, uint64_t value, uint32_t timeout_us);
extern "C" int __ulock_wake(uint32_t operation, void *address, uint64_t wake_value);
#define RAVEN_UL_COMPARE_AND_WAIT_SHARED 3u
#define RAVEN_ULF_WAKE_ALL 0x100u
#define RAVEN_FUTEX_WAKE_ALL(word) __ulock_wake(RAVEN_UL_COMPARE_AND_WAIT_SHARED | RAVEN_ULF_WAKE_ALL, (word), 0)
#define RAVEN_FUTEX_WAIT(word, seen) __ulock_wait(RAVEN_UL_COMPARE_AND_WAIT_SHARED, (word), (seen), 0)
