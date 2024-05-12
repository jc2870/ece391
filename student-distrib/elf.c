#include "elf.h"
#include "lib.h"
#include "errno.h"

int elf_invalid(Elf32_Ehdr *header)
{
    if (memcmp(header->e_ident, ELFMAG, SELFMAG)) {
        return -EINVAL;
    }

    if (header->e_ident[EI_CLASS] != ELFCLASS32) {
        return -EINVAL;
    }

    if (header->e_ident[EI_VERSION] != EV_CURRENT) {
        return -EINVAL;
    }

    // if (header->e_ident[EI_OSABI] != ELFOSABI_LINUX ||
    //     header->e_ident[EI_OSABI] != ELFOSABI_SYSV ) {
    //     return -EINVAL;
    // }

    /* only support little-endian yet */
    if (header->e_ident[EI_DATA] != ELFDATA2LSB) {
        return -EINVAL;
    }

    return 0;
}

int parse_elf_pheader(Elf32_Ehdr *header)
{
    Elf32_Phdr *pheader = (Elf32_Phdr *)((char *)header + header->e_phoff);
    u32 psize = header->e_phentsize;
    u32 entry_addr = (u32)header->e_entry;
    int i = 0;

    for (i = 0; i < header->e_phnum; ++i) {
        // printf("vaddr: 0x%x paddr: 0x%x: flag:0x%x\n",
        //     pheader->p_vaddr, pheader->p_paddr, pheader->p_flags);

        if ((pheader->p_flags & (PF_MASK)) == (PF_R|PF_X)) {
            break;
        }
        pheader = (Elf32_Phdr*)((char*)pheader + psize);
    }

    panic_on(i == header->e_phnum, "cannot find readonly and execable program header\n");

    return entry_addr - pheader->p_vaddr + (u32)header;
}

int parse_elf(Elf32_Ehdr *header)
{
    if (elf_invalid(header)) {
        return -EINVAL;
    }

    return header->e_entry;
}