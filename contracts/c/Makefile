TARGET := riscv64-unknown-elf
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
STRIP := $(TARGET)-strip
# CFLAGS := -Os -DCKB_NO_MMU -D__riscv_soft_float -D__riscv_float_abi_soft -DCKB_C_STDLIB_PRINTF -fvisibility=hidden
CFLAGS := -fPIC -Os -fno-builtin-memcmp -fno-builtin-printf -nostdlib -nostartfiles -fvisibility=hidden
STDLIB := deps/ckb-c-stdlib
APP_CFLAGS := $(CFLAGS) -Ilua -Ic -I$(STDLIB) -I$(STDLIB)/molecule -Wall -Werror -Wno-unused-function -Wno-nonnull-compare -Wno-unused-value
LDFLAGS := -lm -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections
BUILDER_DOCKER := thewawar/ckb-capsule:2021-12-25

via-docker:
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make all"
	cp ./build/insideout $(ARGS)

all: clean build/insideout

build/insideout: build/main.o build/liblua.a
	$(LD) $^ -o $@ $(LDFLAGS)
	$(STRIP) $@

build/main.o: c/main.c
	mkdir -p build
	$(CC) $(APP_CFLAGS) $< -c -o $@

build/liblua.a:
	KABLETOP=1 make -C ./lua a
	cp ./lua/build/liblua.a $@

clean:
	rm -rf build/*.o build/insideout

clean-all: clean
	rm -rf build/*.a build/debug
	make -C ./lua clean
