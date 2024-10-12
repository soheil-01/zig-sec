#include "seg_access.h"

#ifdef _M_X64
uint64_t readgsqword(uint64_t offset) {
    return __readgsqword(offset);
}
#endif

#ifdef _M_IX86
uint32_t readfsdword(uint64_t offset) {
    return __readfsdword(offset);
}
#endif