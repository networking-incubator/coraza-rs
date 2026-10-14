/*
 * Copyright Coraza Kubernetes Operator contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libinjection.h"

static int hex_value(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

int main(void) {
    char *line = NULL;
    size_t capacity = 0;
    ssize_t line_len;

    while ((line_len = getline(&line, &capacity, stdin)) >= 0) {
        char *separator = memchr(line, '\t', (size_t)line_len);
        size_t encoded_len;
        size_t input_len;
        char *input;
        char fingerprint[8] = {0};
        int sqli;
        int xss;
        size_t i;

        while (line_len > 0 && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r')) {
            line[--line_len] = '\0';
        }
        if (separator == NULL || memchr(separator + 1, '\t', (size_t)(line + line_len - separator - 1)) != NULL) {
            fprintf(stderr, "malformed request line\n");
            free(line);
            return 2;
        }
        encoded_len = (size_t)(line + line_len - separator - 1);
        if (encoded_len % 2 != 0) {
            fprintf(stderr, "odd-length hex input\n");
            free(line);
            return 2;
        }
        input_len = encoded_len / 2;
        input = malloc(input_len == 0 ? 1 : input_len);
        if (input == NULL) {
            perror("malloc");
            free(line);
            return 1;
        }
        for (i = 0; i < input_len; i++) {
            int high = hex_value(separator[1 + 2 * i]);
            int low = hex_value(separator[2 + 2 * i]);
            if (high < 0 || low < 0) {
                fprintf(stderr, "invalid hex input\n");
                free(input);
                free(line);
                return 2;
            }
            input[i] = (char)((high << 4) | low);
        }

        sqli = libinjection_sqli(input, input_len, fingerprint) == LIBINJECTION_RESULT_TRUE;
        xss = libinjection_xss(input, input_len) == LIBINJECTION_RESULT_TRUE;
        printf("%.*s\t%d\t%s\t%d\n", (int)(separator - line), line, sqli, sqli ? fingerprint : "", xss);
        free(input);
    }

    free(line);
    return ferror(stdin) ? 1 : 0;
}
