#   make                 build the host static library into libs/<platform>/
#   make test            link tests/smoke.c against it and run every fixture
#   make bump V=0.16.5   move to a new mollusk-svm release (see etc/scripts/bump.sh)
#   make clean
#
# args: CC, PLATFORM (defaults to the host), CARGO_TARGET (cross builds).

UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
  OS       := darwin
  SYS_LIBS := -liconv -lm
  export MACOSX_DEPLOYMENT_TARGET ?= 11.0
else
  OS       := linux
  SYS_LIBS := -lgcc_s -lutil -lrt -lpthread -lm -ldl
endif
ifneq ($(filter arm64 aarch64,$(UNAME_M)),)
  ARCH := arm64
else
  ARCH := x64
endif

PLATFORM     ?= $(OS)-$(ARCH)
CARGO_TARGET ?=
TARGET_DIR   := target/$(if $(CARGO_TARGET),$(CARGO_TARGET)/)release
LIB          := libs/$(PLATFORM)/libmollusk.a
FIXTURES     := $(wildcard tests/fixtures/*.so)

.PHONY: all lib test bump clean print-%

all: lib

lib:
	cargo build --release --locked $(if $(CARGO_TARGET),--target $(CARGO_TARGET))
	@mkdir -p libs/$(PLATFORM)
	cp $(TARGET_DIR)/libmollusk.a $(LIB)
	@ls -lh $(LIB) | awk '{print "built", $$9, "(" $$5 ")"}'

build/smoke: tests/smoke.c include/mollusk.h $(LIB)
	@mkdir -p build
	$(CC) -std=c11 -Wall -Wextra -Werror -Iinclude -o $@ $< $(LIB) $(SYS_LIBS)

test: build/smoke
	@for f in $(FIXTURES); do printf '%s: ' $$f; ./build/smoke $$f || exit 1; done

bump:
	@test -n "$(V)" || { echo "usage: make bump V=<mollusk-svm version>"; exit 1; }
	etc/scripts/bump.sh $(V)

clean:
	rm -rf build target

print-%:
	@echo $($*)
