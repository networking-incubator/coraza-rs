/*
 * The C half of benches/speed.rs: times libinjection itself, the C library,
 * on the inputs the port is timed on, and in the same way.
 *
 *     speed <sqli|xss> <seconds>
 *
 * Reads one hex-encoded input per line on stdin, then runs the detection
 * over all of them, round after round, for about <seconds>. Prints the time
 * the best round took per input, in nanoseconds, and the number of inputs
 * detected.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libinjection.h"

/* Rounds are made long enough for the clock not to matter. */
#define MIN_ROUND_NS 1e7

struct input {
    char *data;
    size_t len;
};

typedef int (*detect_fn)(const char *s, size_t len);

static int detect_sqli(const char *s, size_t len) {
    char fingerprint[8];
    return libinjection_sqli(s, len, fingerprint) == LIBINJECTION_RESULT_TRUE;
}

static int detect_xss(const char *s, size_t len) {
    return libinjection_xss(s, len) == LIBINJECTION_RESULT_TRUE;
}

static int hex_value(int c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* One round: `passes` passes over the inputs. Returns how long it took. */
static double run_round(detect_fn detect, const struct input *inputs,
                        size_t count, size_t passes, size_t *hits) {
    size_t pass;
    size_t i;
    double start = now_ns();

    *hits = 0;
    for (pass = 0; pass < passes; pass++) {
        for (i = 0; i < count; i++) {
            *hits += (size_t)detect(inputs[i].data, inputs[i].len);
        }
    }
    return now_ns() - start;
}

int main(int argc, char **argv) {
    detect_fn detect;
    double budget_ns;
    struct input *inputs = NULL;
    size_t count = 0;
    size_t cap = 0;
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t n;
    size_t passes = 1;
    size_t hits = 0;
    size_t rounds = 0;
    double best = 0;
    double started;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <sqli|xss> <seconds>\n", argv[0]);
        return 2;
    }
    detect = strcmp(argv[1], "xss") == 0 ? detect_xss : detect_sqli;
    budget_ns = atof(argv[2]) * 1e9;

    while ((n = getline(&line, &line_cap, stdin)) > 0) {
        size_t len = 0;
        size_t i;

        while (len * 2 + 1 < (size_t)n && line[len * 2] != '\n') {
            len++;
        }
        if (count == cap) {
            cap = cap ? cap * 2 : 1024;
            inputs = realloc(inputs, cap * sizeof(*inputs));
        }
        inputs[count].len = len;
        inputs[count].data = malloc(len ? len : 1);
        if (inputs == NULL || inputs[count].data == NULL) {
            return 1;
        }
        for (i = 0; i < len; i++) {
            inputs[count].data[i] = (char)(hex_value(line[2 * i]) << 4 |
                                           hex_value(line[2 * i + 1]));
        }
        count++;
    }
    free(line);
    if (count == 0) {
        return 1;
    }

    while (run_round(detect, inputs, count, passes, &hits) < MIN_ROUND_NS) {
        passes *= 2;
    }

    started = now_ns();
    while (rounds < 3 || now_ns() - started < budget_ns) {
        double took = run_round(detect, inputs, count, passes, &hits);
        if (rounds == 0 || took < best) {
            best = took;
        }
        rounds++;
    }

    printf("%f %zu\n", best / (double)(passes * count), hits / passes);
    return 0;
}
