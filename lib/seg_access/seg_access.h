#ifdef _WIN32
#include <intrin.h>
#endif

#include <stdint.h>

#ifdef _M_X64
uint64_t readgsqword(uint64_t offset);
#endif

#ifdef _M_IX86
uint32_t readfsdword(uint64_t offset);
#endif