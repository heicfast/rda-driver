#!/bin/bash
# Local sanity check: compile and run the portable unit tests with gcc.
# Mirrors what CI does on Ubuntu (and what CTest does on Windows).
set -e
cd "$(dirname "$0")/.."
gcc -std=c11 -Wall -Wextra -Werror -Wno-unused-parameter \
    -I src/shared/inc \
    tests/unit/test_compat.c \
    -o /tmp/rda_test_compat
/tmp/rda_test_compat
