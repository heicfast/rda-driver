/*
 * selftest_main.c - gcc-runnable driver for the fuzzer's invariant set
 * (used where libFuzzer is unavailable; the CI ubuntu job runs the real
 * libFuzzer build). Exercises the same LLVMFuzzerTestOneInput path with
 * adversarial inputs derived from the reference grammar and boundary cases.
 *
 * Licensed under the MIT license. See LICENSE.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../src/shared/inc/rda_compat.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int g_inputs;
static int g_failures;

static void Feed(const char *label, const uint8_t *data, size_t size) {
    g_inputs++;
    if (size > (1u << 20)) {
        g_failures++;
        return;
    }
    LLVMFuzzerTestOneInput(data, size);
    (void)label;
}

int main(void) {
    uint8_t buf[2048];
    size_t i;

    /* Grammar-shaped inputs (UTF-16LE). */
    static const char *shapes[] = {
        "\\1\\0\\0",
        "\\123456\\0\\2",
        "\\999\\Volume\\3",
        "\\0\\199\\0",
        "\\55\\7",
        "\\",
        "\\\\",
        "\\abc\\0",
        "\\12\\x9",
        "\\12\\Volume",
        "\\12\\Volume\\",
        "\\12\\Volume\\xy",
        "\\4294967295\\0\\0",
        "\\+7\\0",
        "\\00000\\0",
        "\\9\\Volume\\4294967295",
    };
    for (i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++) {
        size_t n = strlen(shapes[i]);
        size_t j;

        for (j = 0; j < n && j * 2 + 1 < sizeof(buf); j++) {
            buf[j * 2] = (uint8_t)shapes[i][j];
            buf[j * 2 + 1] = 0;
        }
        Feed("shape", buf, j * 2);
    }

    /* Pure random inputs. */
    {
        uint32_t rng = 0xBEEF1234u;

        for (i = 0; i < 4000; i++) {
            size_t len;
            size_t j;

            rng = rng * 1103515245u + 12345u;
            len = (rng >> 16) % 512;
            for (j = 0; j < len; j++) {
                rng = rng * 1103515245u + 12345u;
                buf[j] = (uint8_t)(rng >> 24);
            }
            Feed("random", buf, len);
        }
    }

    /* Boundary sizes. */
    Feed("empty", buf, 0);
    Feed("one", buf, 1);
    Feed("odd", buf, 5);

    printf("selftest: %d inputs, %d failures\n", g_inputs, g_failures);
    return g_failures == 0 ? 0 : 1;
}
