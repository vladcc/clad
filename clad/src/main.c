#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "err/err.h"
#include "asm/asm.h"
#include "disasm/disasm.h"
#include "parse-opts/parse_opts.h"

// <constants>
#define MAX_LINE_LEN (1024*2)
#define MAX_STR_NODES 1024
#define MAX_ONE_ASM_INSTR 1024
// </constants>

// <prog-info>
static const char prog_name[] = "clad";
static const char prog_version[] = "1.0.1";

static void print_usage_quit(void)
{
	printf("Use: %s [OPTIONS] <strings|files>\n", prog_name);
	printf("Try: %s --help\n", prog_name);
	exit(EXIT_FAILURE);
}
static void print_version_quit(void)
{	
	printf("%-8s %s\n", prog_name, prog_version);

	{
		int major = 0;
		int minor = 0;
	
		disasm_get_cs_version(&major, &minor);
		printf("Capstone %d.%d\n", major, minor);
	}
	
	{
		unsigned int major = 0;
		unsigned int minor = 0;
	
		asm_get_ks_version(&major, &minor);
		printf("Keystone %d.%d\n", major, minor);
	}
	
	exit(EXIT_SUCCESS);
}
static void print_static_limits_quit(void)
{
	printf("Max length of a line in a file: %d\n", MAX_LINE_LEN);
	printf("Max files and strings given on the command line: %d\n",MAX_STR_NODES);
	printf("Max length of a single assembly instruction: %d\n", MAX_ONE_ASM_INSTR);
	exit(EXIT_SUCCESS);
}
// </prog-info>

// <easy-list>
enum {IS_STRING, IS_FILE};
typedef struct str_node {
	const char * str;
	size_t tag;
	struct str_node * next;
} str_node;

str_node * str_node_new(void)
{
	static str_node pool[MAX_STR_NODES] = {0};
	static size_t ptr = 0;
	
	if (ptr >= MAX_STR_NODES)
	{
		err_quit("silly static limit of %zu file and string arguments reached",
			MAX_STR_NODES);
	}
	
	return (pool + (ptr++));
}

void str_node_push(str_node ** list, const char * str, size_t tag)
{
	str_node * new_node = str_node_new();
	new_node->str = str;
	new_node->tag = tag;
	new_node->next = (NULL == *list) ? NULL : *list;
	*list = new_node;
}

typedef void (*apply)(const char * str, size_t tag, void * arg);
void str_node_apply_rev(str_node * list, apply fn, void * arg)
{
	if (list)
	{			
		str_node_apply_rev(list->next, fn, arg);
		fn(list->str, list->tag, arg);
	}
}
// </easy-list>

// <command-line-options>
typedef struct prog_options {
	const char * arch;
	const char * mode;
	const char * syntax;
	str_node * inputs;
	size_t addr;
	bool assemble;
	bool disassemble;
} prog_options;

static prog_options g_options;

static void save_string(const char * str, void * ctx)
{
	prog_options * opts = (prog_options *)ctx;
	str_node_push(&(opts->inputs), str, IS_STRING);
}
static void save_file(const char * str, void * ctx)
{
	prog_options * opts = (prog_options *)ctx;
	str_node_push(&(opts->inputs), str, IS_FILE);
}

#include "parse-opts/opts_definitions.ic"

static void opts_process(int argc, char * argv[], void * ctx)
{
	if (argc < 2)
		print_usage_quit();
	
	prog_options * opts = (prog_options *)ctx;
	
	opts->disassemble = true;
	opts->assemble = false;
	
#include "parse-opts/opts_process.ic"
}
// </command-line-options>

// <input-errors>
static void file_err_quit(const char * fname)
{
	err_quit("file %s: %s", fname, strerror(errno));
}
static void check_input_tag(size_t tag)
{
	if (tag != IS_STRING && tag != IS_FILE)
		err_quit("bug: invalid input tag %zu", tag);
}
// </input-errors>

// <disasm-processing>
static void disasm_single_file(const char * fname, void * arg)
{
	static char line[MAX_LINE_LEN] = {0};
	
	FILE * fp = fopen(fname, "r");
	if (!fp)
		file_err_quit(fname);
	
	while (fgets(line, MAX_LINE_LEN, fp))
		disasm_disasm(stdout, line);
	
	fclose(fp);
}
static void disasm_single_input(const char * str, size_t tag, void * arg)
{
	check_input_tag(tag);
	if (IS_STRING == tag)
		disasm_disasm(stdout, str);
	else if (IS_FILE == tag)
		disasm_single_file(str, arg);
}
static void disasm_inputs(prog_options * opts)
{
	str_node_apply_rev(opts->inputs, disasm_single_input, NULL);
}
// </disasm-processing>

// <asm-processing>
typedef struct asm_instr_buff {
	char * buff;
	size_t len;
} asm_instr_buff;

static void asm_single_file(const char * fname, void * arg)
{
	static char line[MAX_LINE_LEN] = {0};
	
	FILE * fp = fopen(fname, "r");
	if (!fp)
		file_err_quit(fname);
	
	asm_instr_buff * buff = (asm_instr_buff *)arg;
	while (fgets(line, MAX_LINE_LEN, fp))
		asm_asm(stdout, line, buff->buff, buff->len);
	
	fclose(fp);
}
static void asm_single_input(const char * str, size_t tag, void * arg)
{
	asm_instr_buff * buff = (asm_instr_buff *)arg;
	
	check_input_tag(tag);
	if (IS_STRING == tag)
		asm_asm(stdout, str, buff->buff, buff->len);
	else if (IS_FILE == tag)
		asm_single_file(str, arg);
}
static void asm_inputs(prog_options * opts, asm_instr_buff * buff)
{
	str_node_apply_rev(opts->inputs, asm_single_input, buff);
}
// </asm-processing>

static void run(prog_options * opts)
{
	if (opts->disassemble)
	{
		disasm_init(opts->arch, opts->mode, opts->syntax, opts->addr);
		disasm_inputs(opts);
		disasm_close();
	}
	else if (opts->assemble)
	{
		static char one_instr_buff[MAX_ONE_ASM_INSTR] = {0};
		asm_instr_buff buff = {one_instr_buff, MAX_ONE_ASM_INSTR};
		
		asm_init(opts->arch, opts->mode, opts->syntax, opts->addr);
		asm_inputs(opts, &buff);
		asm_close();
	}
	else
	{
		err_quit("bug: disasm and asm flags are both false");
	}
}

int main(int argc, char * argv[])
{
	err_set_prog_name(prog_name);
	opts_process(argc, argv, &g_options);
	run(&g_options);
	return 0;
}
