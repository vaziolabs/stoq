#include "system.h"
#include <ngtcp2/ngtcp2.h>

// Helper function for timestamp (same as client)
ngtcp2_tstamp get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}