ENTRY(_start)
OUTPUT_FORMAT(elf32-i386)
OUTPUT_ARCH(i386)

SECTIONS
{
    . = 0xC0400000;
    __kernel_start = .;

    .text :AT(0x400000)
    {
        __text_start = .;
        *(.text*)
        __text_end = .;
	/* *(.text .stub .text.* .gnu.linkonce.t.*) */
    }

    . = ALIGN(16);
    .data :
    {
        __data_start = .;
        *(.data)
        *(.data*)
        __data_end = .;
    }

    . = ALIGN(16);
    .bss :
    {
        __bss_start = .;
        *(.bss)
        __bss_end = .;
    }

    . = ALIGN(16);
    __kernel_end = .;

    /DISCARD/ : { *(.note*) }
}
