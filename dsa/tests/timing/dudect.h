/*
 * dudect: dude, is my code constant time?
 * https://github.com/oreparaz/dudect
 *
 * Released under the MIT License (MIT)
 * Copyright (c) 2017 Oscar Reparaz
 *
 * Simplified single-header version for constant-time testing.
 */

#ifndef DUDECT_H
#define DUDECT_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
#else
#include <time.h>
#endif

#define DUDECT_NUMBER_PERCENTILES 100
#define DUDECT_ENOUGH_MEASUREMENTS 10000
#define DUDECT_TESTS 1000000

typedef struct {
    double mean[2];
    double m2[2];
    double n[2];
} dudect_ctx_t;

static inline void dudect_ctx_init(dudect_ctx_t *ctx) {
    memset(ctx, 0, sizeof(dudect_ctx_t));
}

static inline void dudect_ctx_update(dudect_ctx_t *ctx, int cls, double val) {
    ctx->n[cls]++;
    double delta = val - ctx->mean[cls];
    ctx->mean[cls] += delta / ctx->n[cls];
    ctx->m2[cls] += delta * (val - ctx->mean[cls]);
}

static inline double dudect_ctx_t_value(dudect_ctx_t *ctx) {
    double var0 = ctx->m2[0] / (ctx->n[0] - 1);
    double var1 = ctx->m2[1] / (ctx->n[1] - 1);
    double num = ctx->mean[0] - ctx->mean[1];
    double den = sqrt(var0 / ctx->n[0] + var1 / ctx->n[1]);
    if (den < 1e-10) return 0.0;
    return num / den;
}

static inline uint64_t dudect_get_time(void) {
#ifdef __APPLE__
    return mach_absolute_time();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

/*
 * Result interpretation:
 * |t| < 2.0  : No evidence of timing leak (good)
 * |t| < 4.5  : Possible timing leak, needs more samples
 * |t| >= 4.5 : Strong evidence of timing leak (bad)
 */
typedef enum {
    DUDECT_NO_LEAK_EVIDENCE = 0,
    DUDECT_POSSIBLE_LEAK = 1,
    DUDECT_LEAK_FOUND = 2
} dudect_result_t;

static inline dudect_result_t dudect_interpret(double t) {
    double abs_t = fabs(t);
    if (abs_t < 2.0) return DUDECT_NO_LEAK_EVIDENCE;
    if (abs_t < 4.5) return DUDECT_POSSIBLE_LEAK;
    return DUDECT_LEAK_FOUND;
}

static inline const char* dudect_result_str(dudect_result_t r) {
    switch (r) {
        case DUDECT_NO_LEAK_EVIDENCE: return "No leak evidence";
        case DUDECT_POSSIBLE_LEAK: return "Possible leak (needs more samples)";
        case DUDECT_LEAK_FOUND: return "TIMING LEAK FOUND";
    }
    return "Unknown";
}

#endif /* DUDECT_H */
