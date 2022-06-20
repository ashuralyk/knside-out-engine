
#include "ltime.h"

long int g_time = 0;
long int g_clock = 0;

long int ltime(long int *ptr) {
    if (ptr != 0) {
        *ptr = g_time;
    }
    return g_time;
}

long int lclock(void)
{
    return g_clock;
}