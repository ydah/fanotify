#include <stdio.h>
#include "../ext/fanotify/compat.h"

int main(void)
{
#define X(name) printf(#name "=%llu\n", (unsigned long long)(name));
#include "constants.def"
#undef X
    printf("FAN_NOFD=%d\n", FAN_NOFD);
    printf("AT_FDCWD=%d\n", AT_FDCWD);
    return 0;
}
