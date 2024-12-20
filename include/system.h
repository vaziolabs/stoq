#ifndef SYSTEM_H
#define SYSTEM_H

#include "utils.h"
#include <time.h>
#include <sys/time.h>

// Define CLOCK_MONOTONIC if not available
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#if defined(__APPLE__)
#include <mach/clock.h>
#include <mach/mach.h>

// macOS doesn't have clock_gettime, so we need to implement it
#ifndef HAVE_CLOCK_GETTIME
static inline int clock_gettime(int clk_id, struct timespec *ts) {
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;
    return 0;
}
#endif

#endif

#if defined(__WIN32__)
#include <windows.h>
// Windows implementation if needed
#endif

#endif