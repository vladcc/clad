.PHONY: help
help:
	@echo "make clad LIB_CAPSTONE_INCL_DIR='<path-to-incl-dir>' LIB_CAPSTONE_A='<path-to-static-lib>' LIB_KEYSTONE_INCL_DIR='<path-to-incl-dir>' LIB_KEYSTONE_A='<path-to-static-lib>' - compile clad"
	@echo 'make test  - compile and run internal component tests'
	@echo 'make clean - clean obj/ and bin/'
	@echo 'make help  - this screen'
	
OBJ_DIR := ./obj
BIN_DIR := ./bin
SRC_DIR := ./src
INCL_DIR := $(SRC_DIR)
TEST_DIR := ./tests

CC := g++
CFLAGS := -Wall -Wfatal-errors $(AUX_FLAGS)

CMPL := $(CC)

H2B_DIR := $(SRC_DIR)/hex2bytes
H2B_O := $(OBJ_DIR)/hex2bytes.o

ASMSPLIT_DIR := $(SRC_DIR)/asmsplit
ASMSPLIT_O := $(OBJ_DIR)/asmsplit.o

ERR_DIR := $(SRC_DIR)/err
ERR_O := $(OBJ_DIR)/err.o

DISASM_DIR := $(SRC_DIR)/disasm
DISASM_O := $(OBJ_DIR)/disasm.o

ASM_DIR := $(SRC_DIR)/asm
ASM_O := $(OBJ_DIR)/asm.o

TEST_O := $(OBJ_DIR)/test.o
TEST_BIN := $(BIN_DIR)/test

PARSE_OPTS_DIR := $(SRC_DIR)/parse-opts
PARSE_OPTS_O := $(OBJ_DIR)/parse_opts.o
PARSE_OPTS_DEFN := $(PARSE_OPTS_DIR)/opts_definitions.ic

MAIN_O := $(OBJ_DIR)/main.o
MAIN_BIN := $(BIN_DIR)/clad

LIB_CAPSTONE_A :=
LIB_CAPSTONE_INCL_DIR :=

LIB_KEYSTONE_A :=
LIB_KEYSTONE_INCL_DIR :=

LOCAL_INCL := -I $(INCL_DIR)
CAPSTONE_INCL := -I $(LIB_CAPSTONE_INCL_DIR)
KEYSTONE_INCL := -I $(LIB_KEYSTONE_INCL_DIR)
EXTERN_LIB := $(LIB_CAPSTONE_A) $(LIB_KEYSTONE_A)

.PHONY: clad
clad: $(MAIN_BIN)

$(MAIN_BIN): $(MAIN_O) $(PARSE_OPTS_O) $(ERR_O) $(DISASM_O) $(H2B_O) $(ASM_O) $(ASMSPLIT_O)
	$(CMPL) $^ -o $@ $(EXTERN_LIB) $(LOCAL_INCL) $(CFLAGS)

$(MAIN_O): $(SRC_DIR)/main.c $(PARSE_OPTS_DEFN)
	$(CMPL) -c $< -o $@ $(LOCAL_INCL) $(CFLAGS)

$(PARSE_OPTS_O): $(PARSE_OPTS_DIR)/parse_opts.c
	$(CMPL) -c $^ -o $@ $(LOCAL_INCL) $(CFLAGS)
	
$(ERR_O): $(ERR_DIR)/err.c
	$(CMPL) -c $^ -o $@ $(LOCAL_INCL) $(CFLAGS)

$(DISASM_O): $(DISASM_DIR)/disasm.c
	$(CMPL) -c $^ -o $@ $(LOCAL_INCL) $(CAPSTONE_INCL) $(CFLAGS)

$(ASM_O): $(ASM_DIR)/asm.c
	$(CMPL) -c $^ -o $@ $(LOCAL_INCL) $(KEYSTONE_INCL) $(CFLAGS)


$(PARSE_OPTS_DEFN): $(PARSE_OPTS_DIR)/parse-opts-code-generator/opts-gen.txt
	bash $(PARSE_OPTS_DIR)/gen-opts.sh

.PHONY: test
test: $(TEST_BIN) test_run

test_run:
	$(RUN_PREF) $(TEST_BIN)

$(TEST_BIN): $(TEST_O) $(H2B_O) $(ASMSPLIT_O)
	$(CMPL) $^ -o $@ $(LOCAL_INCL) $(CFLAGS)

$(TEST_O): $(TEST_DIR)/test.c
	$(CMPL) -c $^ -o $@ $(LOCAL_INCL) $(CFLAGS)

$(H2B_O): $(H2B_DIR)/hex2bytes.c
	$(CMPL) -c $^ -o $@ $(LOCAL_INCL) $(CFLAGS)

$(ASMSPLIT_O): $(ASMSPLIT_DIR)/asmsplit.c
	$(CMPL) -c $^ -o $@ $(LOCAL_INCL) $(CFLAGS)

.PHONY: clean
clean:
	rm -f $(OBJ_DIR)/* $(BIN_DIR)/*
