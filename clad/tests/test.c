#include <stdio.h>
#include "test.h"

#include <stdlib.h>
#include <string.h>
#include "hex2bytes/hex2bytes.h"
#include "asmsplit/asmsplit.h"

#define MARK 'X'
#define BUFF_SIZE 16
static bool test_asmsplit(void)
{
	static char buff[BUFF_SIZE] = {0};
	
	{
		buff[0] = MARK;
		char instr[] = "";
		const char * ptr = instr;
		const char * err = NULL;
		
		ptr = asm_instr_next(instr, buff, BUFF_SIZE, &err);
		check(!err);
		check(!ptr);
		check(MARK == buff[0]);
	}
	
	{
		buff[0] = MARK;
		char instr[] = ";;;";
		const char * ptr = instr;
		const char * err = NULL;
		
		buff[0] = MARK;
		ptr = asm_instr_next(ptr, buff, BUFF_SIZE, &err);
		check(!ptr);
		check(MARK == buff[0]);
	}
	
	{
		buff[0] = MARK;
		char instr[] = "\n   ;\n\t\t\n ;   \n\n\n ; ";
		const char * ptr = instr;
		const char * err = NULL;
		
		buff[0] = MARK;
		ptr = asm_instr_next(ptr, buff, BUFF_SIZE, &err);
		check(!ptr);
		check(MARK == buff[0]);
	}
	
	{
		buff[0] = MARK;
		char instr[] = "foo bar baz";
		const char * ptr = instr;
		const char * err = NULL;
		
		ptr = asm_instr_next(instr, buff, 2, &err);
		check(strcmp(err, "asm_instr_next(): instruction string buffer too small") == 0);
		check(!ptr);
		check('f' == buff[0]);
	}
	
	{
		buff[0] = MARK;
		char instr[] = "12345";
		const char * ptr = instr;
		const char * err = NULL;
		
		ptr = asm_instr_next(instr, buff, 5, &err);
		check(strcmp(err, "asm_instr_next(): instruction string buffer too small") == 0);
		check(!ptr);
		check('1' == buff[0]);
	}
	
	{
		buff[0] = MARK;
		char instr[] = "12345";
		const char * ptr = instr;
		const char * err = NULL;
		
		ptr = asm_instr_next(instr, buff, 6, &err);
		check(!err);
		check(ptr);
		check(strcmp(buff, instr) == 0);
	}
	
	{
		buff[0] = MARK;
		char instr[] = "foo bar baz";
		const char * ptr = instr;
		const char * err = NULL;
		
		ptr = asm_instr_next(instr, buff, 0, &err);
		check(!ptr);
		check(MARK == buff[0]);
	}
	
	{
		buff[0] = MARK;
		char instr[] = "foo bar baz";
		const char * ptr = instr;
		const char * err = NULL;
		
		ptr = asm_instr_next(instr, buff, BUFF_SIZE, &err);
		check(ptr);
		check(strcmp(buff, "foo bar baz") == 0);
	}
	
	{
		buff[0] = MARK;
		char instr[] = "   foo;bar\nbaz  ; zig   \n zag  \t \n\n ";
		const char * ptr = instr;
		const char * err = NULL;
		
		ptr = asm_instr_next(ptr, buff, BUFF_SIZE, &err);
		check(ptr);
		check(strcmp(buff, "foo") == 0);
		
		ptr = asm_instr_next(ptr, buff, BUFF_SIZE, &err);
		check(ptr);
		check(strcmp(buff, "bar") == 0);
		
		ptr = asm_instr_next(ptr, buff, BUFF_SIZE, &err);
		check(ptr);
		check(strcmp(buff, "baz") == 0);
		
		ptr = asm_instr_next(ptr, buff, BUFF_SIZE, &err);
		check(ptr);
		check(strcmp(buff, "zig") == 0);
		
		ptr = asm_instr_next(ptr, buff, BUFF_SIZE, &err);
		check(ptr);
		check(strcmp(buff, "zag") == 0);
		
		buff[0] = MARK;
		ptr = asm_instr_next(ptr, buff, BUFF_SIZE, &err);
		check(!ptr);
		check(MARK == buff[0]);
	}
	
	return true;
}

static bool test_hex2bytes(void)
{
	{
		char str[] = "";
		size_t len = 0;
		size_t * ind_map = NULL;
		const char * err = NULL;
		byte * buff = NULL;

		buff = hex2bytes(str, &len, &ind_map, &err);
		check(!buff);
		check(0 == len);
		check(strcmp(err, "hex2bytes(): no hex values in string") == 0);
	}
	
	{
		char str[] = "";
		size_t len = 0;
		size_t * ind_map = NULL;
		byte * buff = NULL;

		buff = hex2bytes(str, &len, &ind_map, NULL);
		check(!buff);
		check(0 == len);
	}

	{
		char str[] = "xyz";
		size_t len = 0;
		size_t * ind_map = NULL;
		const char * err = NULL;
		byte * buff = NULL;

		buff = hex2bytes(str, &len, &ind_map, &err);
		check(!buff);
		check(0 == len);
		check(strcmp(err, "hex2bytes(): no hex values in string") == 0);
	}

	{
		char str[] = "abcd";
		byte vals[] = {0xAB, 0xCD};
		size_t len = 0;
		size_t * ind_map = NULL;
		const char * err = NULL;
		byte * buff = NULL;

		buff = hex2bytes(str, &len, &ind_map, &err);
		check(buff);
		check(2 == len);
		check(memcmp(buff, vals, len) == 0);
		check(0 == ind_map[0]);
		check(2 == ind_map[1]);
		
		free(buff);
		free(ind_map);
	}

	{
		char str[] = "abc";
		byte vals[] = {0xAB, 0xC0};
		size_t len = 0;
		size_t * ind_map = NULL;
		const char * err = NULL;
		byte * buff = NULL;

		buff = hex2bytes(str, &len, &ind_map, &err);
		check(buff);
		check(2 == len);
		check(memcmp(buff, vals, len) == 0);
		check(0 == ind_map[0]);
		check(2 == ind_map[1]);
		
		free(buff);
		free(ind_map);
	}

	{
		char str[] = "0xab 0xcd";
		byte vals[] = {0xAB, 0xCD};
		size_t len = 0;
		size_t * ind_map = NULL;
		const char * err = NULL;
		byte * buff = NULL;

		buff = hex2bytes(str, &len, &ind_map, &err);
		check(buff);
		check(2 == len);
		check(memcmp(buff, vals, len) == 0);
		check(2 == ind_map[0]);
		check(7 == ind_map[1]);
		
		free(buff);
		free(ind_map);
	}

	{
		char str[] = " 0xab, 0Xcd 0xEf }";
		byte vals[] = {0xAB, 0xCD, 0xEF};
		size_t len = 0;
		size_t * ind_map = NULL;
		const char * err = NULL;
		byte * buff = NULL;

		buff = hex2bytes(str, &len, &ind_map, &err);
		check(buff);
		check(3 == len);
		check(memcmp(buff, vals, len) == 0);
		check(3 == ind_map[0]);
		check(9 == ind_map[1]);
		check(14 == ind_map[2]);

		free(buff);
		free(ind_map);
	}

	{
		char str[] = " !0xab, 0Xcd Ef }";
		byte vals[] = {0xCD, 0xEF};
		size_t len = 0;
		size_t * ind_map = NULL;
		const char * err = NULL;
		byte * buff = NULL;

		buff = hex2bytes(str, &len, &ind_map, &err);
		check(buff);
		check(2 == len);
		check(memcmp(buff, vals, len) == 0);
		check(10 == ind_map[0]);
		check(13 == ind_map[1]);
		
		free(buff);
		free(ind_map);
	}

	{
		char str[] = " 0xab, !0Xcd 0xEf }";
		byte vals[] = {0xab, 0xEF};
		size_t len = 0;
		size_t * ind_map = NULL;
		const char * err = NULL;
		byte * buff = NULL;

		buff = hex2bytes(str, &len, &ind_map, &err);
		check(buff);
		check(2 == len);
		check(memcmp(buff, vals, len) == 0);
		check(3 == ind_map[0]);
		check(15 == ind_map[1]);
		
		free(buff);
		free(ind_map);
	}

	{
		char str[] = " 0xab, 0Xcd !0xEf }";
		byte vals[] = {0xab, 0xcd};
		size_t len = 0;
		size_t * ind_map = NULL;
		const char * err = NULL;
		byte * buff = NULL;

		buff = hex2bytes(str, &len, &ind_map, &err);
		check(buff);
		check(2 == len);
		check(memcmp(buff, vals, len) == 0);
		check(3 == ind_map[0]);
		check(9 == ind_map[1]);

		free(buff);
		free(ind_map);
	}

	{
		char str[] = " 0xab, 0Xcd !0xEf }";
		byte vals[] = {0xab, 0xcd};
		size_t len = 0;
		const char * err = NULL;
		byte * buff = NULL;

		buff = hex2bytes(str, &len, NULL, &err);
		check(buff);
		check(2 == len);
		check(memcmp(buff, vals, len) == 0);
		free(buff);
	}

	return true;
}

static ftest tests[] = {
	test_hex2bytes,
	test_asmsplit,
};

//------------------------------------------------------------------------------

int run_tests(void)
{
    int i, end = sizeof(tests)/sizeof(*tests);

    int passed = 0;
    for (i = 0; i < end; ++i)
        if (tests[i]())
            ++passed;

    if (passed != end)
        putchar('\n');

    int failed = end - passed;
    report(passed, failed);
    return failed;
}
//------------------------------------------------------------------------------

int main(void)
{
	return run_tests();
}
//------------------------------------------------------------------------------
