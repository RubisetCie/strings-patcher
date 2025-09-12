# Compilers
CC = gcc

# Compiler flags
override CFLAGS += -ansi

# Linker flags
override LDFLAGS += -flto

# Source files
SRC_FILES = \
	main.c \
	pefile.c \
	elffile.c \
	common.c

# Architecture
ARCH = $(shell $(CC) -dumpmachine)

# Installation prefix
PREFIX = /usr/local

TARGET = string-patch

all: $(TARGET)

$(TARGET): $(SRC_FILES)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

install:
	mkdir -p $(PREFIX)/bin
	cp $(TARGET) $(PREFIX)/bin/

uninstall:
	rm -f $(PREFIX)/bin/$(TARGET)

clean:
	rm -f $(TARGET)
