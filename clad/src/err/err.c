#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "err.h"

static struct {
	const char * prog_name;
} module;

static void real_err_print(const char * msg, va_list args)
{
	fflush(stdout);
	fprintf(stderr, "%s: error: ", module.prog_name);
	vfprintf(stderr, msg, args);
	fprintf(stderr, "%s", "\n");
}

void err_set_prog_name(const char * name)
{
	module.prog_name = name;
}

void err_out(const char * str, ...)
{
	va_list args;
	va_start(args, str);
	vfprintf(stderr, str, args);
	va_end(args);
}

void err_exit(void)
{
	exit(EXIT_FAILURE);
}

void err_print(const char * msg, ...)
{	
	va_list args;
	va_start(args, msg);
	real_err_print(msg, args);
	va_end(args);
}

void err_quit(const char * msg, ...)
{
	va_list args;
	va_start(args, msg);
	real_err_print(msg, args);
	va_end(args);
	err_exit();
}
