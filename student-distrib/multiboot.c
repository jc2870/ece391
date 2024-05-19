#include "multiboot.h"
#include "lib.h"
#include "types.h"
#include "x86_desc.h"


extern const int __kernel_start;
extern const int __kernel_end;
void multiboot_info(unsigned long magic, unsigned long addr)
{
    multiboot_info_t *mbi;
    /* Am I booted by a Multiboot-compliant boot loader? */
    if (magic != MULTIBOOT_BOOTLOADER_MAGIC) {
        panic("Invalid magic number: 0x%#x\n", (unsigned)magic);
        return;
    }

    /* Set MBI to the address of the Multiboot information structure. */
    mbi = (multiboot_info_t *) addr;

    /* Print out the flags. */
    printf("flags = 0x%#x\n", (unsigned)mbi->flags);

    /* Are mem_* valid? */
    if (CHECK_FLAG(mbi->flags, 0))
        printf("mem_lower = %uKB, mem_upper = %uKB\n", (unsigned)mbi->mem_lower, (unsigned)mbi->mem_upper);

    /* Is boot_device valid? */
    if (CHECK_FLAG(mbi->flags, 1)) {
        if ((unsigned long)mbi->boot_device >> 24 == 0x80) {
            printf("boot device is hard disk\n");
        } else if ((unsigned long)mbi->boot_device >> 24 == 0x00) {
            printf("boot device is floppy disk\n");
        } else {
            panic("unrecognized boot device\n");
        }
    }

    /* Is the command line passed? */
    if (CHECK_FLAG(mbi->flags, 2))
        printf("cmdline = %s\n", (char *)pdr2vdr(mbi->cmdline));

    if (CHECK_FLAG(mbi->flags, 3)) {
        int mod_count = 0;
        module_t* mod = (module_t*)pdr2vdr(mbi->mods_addr);
        while (mod_count < mbi->mods_count) {
            printf("module %s start: 0x%lx end: 0x%lx\n",
                    pdr2vdr(mod->string), pdr2vdr(mod->mod_start), pdr2vdr(mod->mod_end));
            mod_count++;
            mod++;
        }
    }

    /* Bits 4 and 5 are mutually exclusive! */
    if (CHECK_FLAG(mbi->flags, 4) && CHECK_FLAG(mbi->flags, 5)) {
        printf("WARNING: Both bits 4 and 5 are set.\n");
        return;
    }

    /* Is the section header table of ELF valid? */
    if (CHECK_FLAG(mbi->flags, 5)) {
        elf_section_header_table_t *elf_sec = &(mbi->elf_sec);
        printf("elf_sec: num = %u, size = 0x%#x, addr = 0x%#x, shndx = 0x%#x\n",
                (unsigned)elf_sec->num, (unsigned)elf_sec->size,
                (unsigned)elf_sec->addr, (unsigned)elf_sec->shndx);
    }

    /* Are mmap_* valid? */
    if (CHECK_FLAG(mbi->flags, 6)) {
        memory_map_t *mmap;
        printf("mmap_addr = 0x%#x, mmap_length = 0x%x\n",
                (unsigned)mbi->mmap_addr, (unsigned)mbi->mmap_length);
        mmap = (memory_map_t *)pdr2vdr(mbi->mmap_addr);
        for (; (unsigned long)mmap < mbi->mmap_addr + mbi->mmap_length;
                mmap = (memory_map_t *)((unsigned long)mmap + mmap->size + sizeof (mmap->size)))
            printf("    size = 0x%x, base_addr = 0x%#x%#x\n    type = 0x%x,  length    = 0x%#x%#x\n",
                    (unsigned)mmap->size,
                    (unsigned)mmap->base_addr_high,
                    (unsigned)mmap->base_addr_low,
                    (unsigned)mmap->type,
                    (unsigned)mmap->length_high,
                    (unsigned)mmap->length_low);
    }
    if (CHECK_FLAG(mbi->flags, 7)) {
        struct drive_struct *drive = (struct drive_struct*)pdr2vdr(mbi->drive_addr);
        printf("drive_addr = 0x%#x, drive_length = 0x%#x\n", mbi->drive_addr, mbi->drive_length);
        for (; (uint32_t)drive < mbi->drive_addr + mbi->drive_length;
             drive = (struct drive_struct*)((uint32_t)drive + drive->size)) {
                printf("\tmode is %d, cylinders is %d, heads is %d, sectors is %d\n",
                    drive->drive_mode, drive->drive_cylinders, drive->drive_heads, drive->drive_sectors);
             }
    }
    if (CHECK_FLAG(mbi->flags, 9)) {
        printf("boot_loader_name is %s\n", pdr2vdr(mbi->boot_loader_name)); // GNU GRUN 0.97
    }
    if (CHECK_FLAG(mbi->flags, 11)) {
        printf("vbe_mode is %d\n", mbi->vbe_mode);
    }
    if (CHECK_FLAG(mbi->flags, 12)) {
        printf("framebuffer is set\n");
    }

    {
        char vendor[12];
        uint32_t regs[4];

        cpuid(0, regs);
        ((unsigned *)vendor)[0] = regs[1]; // EBX
        ((unsigned *)vendor)[1] = regs[3]; // EDX
        ((unsigned *)vendor)[2] = regs[2]; // ECX

        cpuid(1, regs);
        unsigned logical = (regs[1] >> 16) & 0xff;
        printf("there are %u logical cores\n", logical);
        cpuid(4, regs);
        uint32_t cores = ((regs[0] >> 26) & 0x3f) + 1;
        printf("there are %u physical cores\n", cores);
    }

    printf("kernel start is 0x%x, kernel end is 0x%x\n", (usl_t)&__kernel_start, (usl_t)&__kernel_end);
}