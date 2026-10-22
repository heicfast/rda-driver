# fuzz/Makefile - libFuzzer + selftest builds for the RDA portable logic layer.
#
# Targets:
#   fuzz       - build fuzz_classify with libFuzzer+ASan+UBSan (needs clang;
#                 the GitHub ubuntu runners ship clang-18)
#   run        - run a 60s fuzz round with the seed corpus
#   selftest   - gcc build: run the full invariant set over a fixed input
#                 set (used where clang is unavailable, e.g. local Linux)
#   unit       - run the portable unit tests under ASan+UBSan
#
# All builds compile with -Wall -Wextra -Werror -std=c11 (the same
# discipline as the driver itself; the shared logic must stay clean).

CC      ?= clang
GCC     ?= gcc
CFLAGS  := -std=c11 -O1 -g -Wall -Wextra -Werror -I../src/shared/inc
SAN     := -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer
ASAN    := -fsanitize=address,undefined -fno-omit-frame-pointer

.PHONY: fuzz run selftest unit clean

fuzz: fuzz_classify

fuzz_classify: fuzz_classify.c ../src/shared/inc/rda_compat.h ../src/shared/inc/rda_ioctl.h
	$(CC) $(CFLAGS) $(SAN) -o $@ fuzz_classify.c

run: fuzz_classify
	mkdir -p corpus_out seeds
	printf '\\123\\0\\0\x00\x00' > seeds/s1
	printf '\\999\\Volume\\3' > seeds/s2
	./fuzz_classify -max_total_time=60 -max_len=1024 seeds corpus_out

selftest: selftest_main.c fuzz_classify.c ../src/shared/inc/rda_compat.h
	$(GCC) $(CFLAGS) $(ASAN) -o selftest selftest_main.c fuzz_classify.c
	./selftest

unit: ../tests/unit/test_compat.c
	$(GCC) $(CFLAGS) $(ASAN) -o unit_asan ../tests/unit/test_compat.c
	./unit_asan

clean:
	rm -f fuzz_classify selftest unit_asan
	rm -rf corpus_out
