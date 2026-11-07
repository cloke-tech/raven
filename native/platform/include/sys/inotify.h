// ClokeOS: no inotify on XNU yet; change notifications report failure (FindFirstChangeNotification fails with an error)
#pragma once
#include <cerrno>
#include <cstdint>
#define IN_NONBLOCK 0x800
#define IN_CLOEXEC 0x80000
#define IN_ACCESS 0x1
#define IN_MODIFY 0x2
#define IN_ATTRIB 0x4
#define IN_CLOSE_WRITE 0x8
#define IN_CLOSE_NOWRITE 0x10
#define IN_OPEN 0x20
#define IN_MOVED_FROM 0x40
#define IN_MOVED_TO 0x80
#define IN_CREATE 0x100
#define IN_DELETE 0x200
#define IN_DELETE_SELF 0x400
#define IN_MOVE_SELF 0x800
#define IN_ONLYDIR 0x1000000
#define IN_DONT_FOLLOW 0x2000000
#define IN_EXCL_UNLINK 0x4000000
#define IN_MASK_ADD 0x20000000
#define IN_ISDIR 0x40000000
#define IN_Q_OVERFLOW 0x4000
#define IN_IGNORED 0x8000
struct inotify_event { int wd; uint32_t mask, cookie, len; char name[]; };
static inline int inotify_init1(int) { errno = ENOSYS; return -1; }
static inline int inotify_add_watch(int, const char *, uint32_t) { errno = ENOSYS; return -1; }
static inline int inotify_rm_watch(int, int) { errno = ENOSYS; return -1; }
