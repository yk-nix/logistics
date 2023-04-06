CC      := g++
RM      := rm
MV      := mv
SUFFIX  := .cpp
TARGET  := logistics
TOP_DIR := $(PWD)
TMP_DIR := $(TOP_DIR)/.tmp/
LIB_DIR :=
INC_DIR := $(TOP_DIR)/include
TAR_DIR := $(TOP_DIR)/bin
SUB_DIR := src
OPTIONS := 
CFLAGS  := -std=c++11 -I/usr/local/include/activemq-cpp-3.9.5 -I/usr/local/apr/include/apr-1 -DLINUX -D_REENTRANT -D_GNU_SOURCE -g
LIBS    := -lconfig -lrt -L/usr/local/lib -lactivemq-cpp

export CC CPPC RM MV INC_DIR TOP_DIR TMP_DIR SUFFIX OPTIONS CFLAGS

all: CHECKDIR
	@$(foreach dir, $(SUB_DIR), \
	         make -C $(dir);\
	)
	$(CC) $(OPTIONS) -o $(TAR_DIR)/$(TARGET) $(TMP_DIR)* $(LIBS)
	@rm -fr $(TMP_DIR)

CHECKDIR:
	mkdir -p $(TMP_DIR)
clean:
	$(RM) $(TAR_DIR)/$(TARGET)

