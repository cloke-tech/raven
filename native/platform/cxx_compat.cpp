// ClokeOS: PureDarwin's libc++ (20.5) stubs std::uncaught_exceptions with an abort, and iostream sentries call it.
#ifdef __APPLE__
#include <exception>

extern "C" void *__cxa_get_globals() noexcept;

namespace std {
int uncaught_exceptions() noexcept
{
	struct Globals { void *caught; unsigned int uncaught; };
	return int(static_cast<Globals *>(__cxa_get_globals())->uncaught);
}
}
#endif
