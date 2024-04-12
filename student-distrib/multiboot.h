/* multiboot.h - Defines used in working with Multiboot-compliant
 * bootloaders (such as GRUB)
 * vim:ts=4 noexpandtab
 */

#ifndef _MULTIBOOT_H
#define _MULTIBOOT_H

#define MULTIBOOT_HEADER_FLAGS          0x00000003
#define MULTIBOOT_HEADER_MAGIC          0x1BADB002
#define MULTIBOOT_BOOTLOADER_MAGIC      0x2BADB002

#define STACK_BOTTOM 0x800000
#define STACK_TOP    0x7fe000
#define INIT_TASK STACK_TOP

#ifndef ASM

/* Types */
#include "types.h"

/* The Multiboot header. */
typedef struct multiboot_header {
    uint32_t magic;
    uint32_t flags;
    uint32_t checksum;
    uint32_t header_addr;
    uint32_t load_addr;
    uint32_t load_end_addr;
    uint32_t bss_end_addr;
    uint32_t entry_addr;
} multiboot_header_t;

/* The section header table for ELF. */
typedef struct elf_section_header_table {
    uint32_t num;
    uint32_t size;
    uint32_t addr;
    uint32_t shndx;
} elf_section_header_table_t;

/* The Multiboot information. */
typedef struct multiboot_info {
    uint32_t flags;
    uint32_t mem_lower;
    uint32_t mem_upper;
    uint32_t boot_device;
    uint32_t cmdline;
    uint32_t mods_count;
    uint32_t mods_addr;
    elf_section_header_table_t elf_sec;
    uint32_t mmap_length;
    uint32_t mmap_addr;
    uint32_t drive_length;
    uint32_t drive_addr;
    uint32_t config_table;
    uint32_t boot_loader_name;
    uint32_t apm_table;
    uint32_t vbe_control_info;
    uint32_t vbe_mode_info;
    uint16_t vbe_mode;
    uint16_t vbe_interface_seg;
    uint16_t vbe_interface_off;
    uint16_t vbe_interface_len;
    uint64_t frame_buffer_addr;
    uint32_t frame_buffer_pitch;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint32_t framebuffer_bpp : 1;
    uint32_t framebuffer_type: 1;
    uint32_t color_info : 5;
} multiboot_info_t;

typedef struct module {
    uint32_t mod_start;
    uint32_t mod_end;
    uint32_t string;
    uint32_t reserved;
} module_t;

/* The memory map. Be careful that the offset 0 is base_addr_low
   but no size. */
typedef struct memory_map {
    uint32_t size;
    uint32_t base_addr_low;
    uint32_t base_addr_high;
    uint32_t length_low;
    uint32_t length_high;
    uint32_t type;
} memory_map_t;

struct drive_struct {
    uint32_t size;
    uint32_t drive_number : 1;
    uint32_t drive_mode : 1;
    uint32_t drive_cylinders : 2;
    uint32_t drive_heads : 1;
    uint32_t drive_sectors : 1;
    uint8_t drive_ports[0];
};

extern void multiboot_info(unsigned long magic, unsigned long addr);

#endif /* ASM */

#endif /* _MULTIBOOT_H */
