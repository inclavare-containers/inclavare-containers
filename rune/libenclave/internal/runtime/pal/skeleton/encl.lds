OUTPUT_FORMAT(elf64-x86-64)

SECTIONS
{
	. = 0;
	.tcs : {
		*(.tcs*)
	}

	. = ALIGN(4096);
	.text : {
		*(.text*)
		*(.rodata*)
	}

	. = ALIGN(4096);
	.data : {
		*(.data*)
	}

	/DISCARD/ : {
		*(.data*)
		*(.comment*)
		*(.note*)
		*(.debug*)
		*(.eh_frame*)
	}
}

ASSERT(!DEFINED(.altinstructions), "ALTERNATIVES are not supported in enclaves")
ASSERT(!DEFINED(.altinstr_replacement), "ALTERNATIVES are not supported in enclaves")
ASSERT(!DEFINED(.discard.retpoline_safe), "RETPOLINE ALTERNATIVES are not supported in enclaves")
ASSERT(!DEFINED(.discard.nospec), "RETPOLINE ALTERNATIVES are not supported in enclaves")
ASSERT(!DEFINED(.got.plt), "Libcalls are not supported in enclaves")
