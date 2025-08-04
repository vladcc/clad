#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <vector>
#include <string>
#include <fstream>

#include "err/err.h"
#include "asm/asm.h"
#include "disasm/disasm.h"
#include "parse-opts/parse_opts.h"

// <prog-info>
static const char prog_name[] = "clad";
static const char prog_version[] = "1.1.3";

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
// </prog-info>

// <input-gather>
enum {IS_STRING, IS_FILE};
typedef struct input_node {
	const char * str;
	size_t tag;
} input_node;
void input_node_save(std::vector<input_node>& in, const char * str, size_t tag)
{
	in.push_back({str, tag});
}
// </input-gather>

// <command-line-options>
typedef struct prog_options {
	const char * arch;
	const char * mode;
	const char * syntax;
	size_t addr;
	size_t asm_max_instr;
	std::vector<input_node> inputs;
	bool assemble;
	bool disassemble;
	bool coalesce_input;
} prog_options;

static inline prog_options * prog_opts_get(void)
{
	static prog_options opts;
	return &opts;
}

static void save_string(const char * str, void * ctx)
{
	prog_options * opts = (prog_options *)ctx;
	input_node_save(opts->inputs, str, IS_STRING);
}
static void save_file(const char * str, void * ctx)
{
	prog_options * opts = (prog_options *)ctx;
	input_node_save(opts->inputs, str, IS_FILE);
}

#include "parse-opts/opts_definitions.ic"

static void opts_process(int argc, char * argv[], void * ctx)
{
	if (argc < 2)
		print_usage_quit();

	prog_options * opts = (prog_options *)ctx;

	opts->disassemble = true;
	opts->assemble = false;
	opts->asm_max_instr = ASM_MAX_INSTR_DEFAULT;

#include "parse-opts/opts_process.ic"
}
// </command-line-options>

// <input-errors>
static void file_err_quit(std::ifstream& ifs, const char * fname)
{
	ifs.open(fname);
	if (!ifs.is_open())
		err_quit("file %s: %s", fname, strerror(errno));
}
static void check_input_tag(size_t tag)
{
	if (tag != IS_STRING && tag != IS_FILE)
		err_quit("bug: invalid input tag %zu", tag);
}
// </input-errors>

// <input-process>
typedef void (*prcsr)(FILE * where, const char * str);
static void process_string(prcsr fn, FILE * where, const char * what)
{
	fn(where, what);
}
static void process_file(prcsr fn, FILE * where, const char * fname)
{
	std::ifstream in_file;
	file_err_quit(in_file, fname);

	std::string line;
	while (std::getline(in_file, line))
		fn(where, line.c_str());
}
static void input_coalesce(prog_options * opts, std::string& out)
{
	out.clear();

	std::vector<input_node>& in = opts->inputs;
	input_node * node = in.data();
	for (size_t i = 0, end = in.size(); i < end; ++i, ++node)
	{
		check_input_tag(node->tag);
		if (IS_STRING == node->tag)
		{
			out.append(node->str);
		}
		else if (IS_FILE == node->tag)
		{
			std::ifstream in_file;
			file_err_quit(in_file, node->str);

			std::string line;
			while (std::getline(in_file, line))
				out.append(line);
		}

		if (opts->disassemble)
		{
			out.push_back(' ');
		}
		else if (opts->assemble)
		{
			char last = out.back();
			if (last != ';' && last != '\n')
				out.push_back(';');
		}
	}
}
static void process_input(prog_options * opts, prcsr fn)
{
	if (opts->coalesce_input)
	{
		std::string all_input;
		input_coalesce(opts, all_input);
		fn(stdout, all_input.c_str());
	}
	else
	{
		std::vector<input_node>& in = opts->inputs;
		input_node * node = in.data();
		for (size_t i = 0, end = in.size(); i < end; ++i, ++node)
		{
			check_input_tag(node->tag);
			if (IS_STRING == node->tag)
				process_string(fn, stdout, node->str);
			else if (IS_FILE == node->tag)
				process_file(fn, stdout, node->str);
		}
	}
}
static void disasm_inputs(prog_options * opts)
{
	process_input(opts, disasm_disasm);
}
static void asm_inputs(prog_options * opts)
{
	process_input(opts, asm_asm);
}
// </input-process>

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
		asm_init(opts->arch,
			opts->mode, opts->syntax, opts->addr, opts->asm_max_instr);
		asm_inputs(opts);
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

	prog_options * opts = prog_opts_get();
	opts_process(argc, argv, opts);
	run(opts);
	return 0;
}
