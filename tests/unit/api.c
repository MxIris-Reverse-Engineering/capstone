// Copyright © 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: BSD-3

#include "../../include/capstone/capstone.h"
#include "unit_test.h"
#include <stdio.h>
#include <string.h>

static bool test_cs_mem_setup_fail()
{
	printf("Test test_cs_mem_setup_fail\n");
	cs_opt_mem mem = { .malloc = malloc,
			   .calloc = calloc,
			   .realloc = realloc,
			   .free = free,
			   .vsnprintf = NULL };
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.vsnprintf = vsnprintf;
	mem.malloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.malloc = malloc;
	mem.calloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.calloc = calloc;
	mem.realloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.realloc = realloc;
	mem.free = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);

	return true;
}

static bool test_cs_option_detail_off()
{
	printf("Test test_cs_option_detail_off\n");
#ifdef CAPSTONE_HAS_AARCH64
	// add x2, x3, x4
	const uint8_t code[] = { 0x62, 0x00, 0x04, 0x8b };
	csh handle;
	cs_insn *instruction;
	size_t count;

	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_open(CS_ARCH_AARCH64,
						  CS_MODE_LITTLE_ENDIAN,
						  &handle),
				  CS_ERR_OK);
	CHECK_INT_EQUAL_RET_FALSE(
		(size_t)cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON), CS_ERR_OK);
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(handle, CS_OPT_DETAIL,
						    CS_OPT_OFF),
				  CS_ERR_OK);
	count = cs_disasm(handle, code, sizeof(code), 0x1000, 0, &instruction);
	CHECK_INT_EQUAL_RET_FALSE(count, 1);
	CHECK_NULL_RET_FALSE(instruction->detail);
	cs_free(instruction, count);
	cs_close(&handle);
#endif
	return true;
}

static bool test_cs_disasm_iter_clears_illegal()
{
	printf("Test test_cs_disasm_iter_clears_illegal\n");
#ifdef CAPSTONE_HAS_AARCH64
	// ldr x1, [x1, #8]! writes back into its own transfer register, which the
	// architecture leaves unpredictable; ldr x0, [x1, #8]! does not.
	const uint8_t code[] = { 0x21, 0x8c, 0x40, 0xf8, 0x20, 0x8c, 0x40, 0xf8 };
	const uint8_t *position = code;
	size_t remaining = sizeof(code);
	uint64_t address = 0x1000;
	csh handle;
	cs_insn *instruction;

	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_open(CS_ARCH_AARCH64,
						  CS_MODE_LITTLE_ENDIAN,
						  &handle),
				  CS_ERR_OK);
	instruction = cs_malloc(handle);
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_disasm_iter(handle, &position,
							 &remaining, &address,
							 instruction),
				  true);
	CHECK_INT_EQUAL_RET_FALSE((size_t)instruction->illegal, true);
	// The same buffer again: nothing of the first instruction may remain.
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_disasm_iter(handle, &position,
							 &remaining, &address,
							 instruction),
				  true);
	CHECK_INT_EQUAL_RET_FALSE((size_t)instruction->illegal, false);
	cs_free(instruction, 1);
	cs_close(&handle);
#endif
	return true;
}

int main()
{
	bool result = true;
	result &= test_cs_option_detail_off();
	result &= test_cs_disasm_iter_clears_illegal();
	// Leaves the global allocator unusable, so it has to run last.
	result &= test_cs_mem_setup_fail();

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}
