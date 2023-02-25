#ifndef CLAD_DISASM_H
#define CLAD_DISASM_H

#include <stdio.h>

void disasm_print_options(void);
void disasm_print_arch(void);
void disasm_get_cs_version(int * major, int * minor);

void disasm_init(
	const char * arch,
	const char * mode,
	const char * syntax,
	size_t start_addr
);

void disasm_disasm(FILE * where, const char * hex);
void disasm_close(void);

#endif
