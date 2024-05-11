#ifndef _ELF_H
#define _ELF_H
#include "types.h"

typedef u32 Elf32_Addr;
typedef u32 Elf32_Off;
typedef u16 Elf32_Section;
typedef u16 Elf32_Versym;
typedef u8  Elf_Byte;
typedef u16 Elf32_Half;
typedef s32 Elf32_Sword;
typedef u32 Elf32_Word;
typedef s64 Elf32_Sxword;
typedef s64 Elf32_Xword;

#define EI_NIDENT 16

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t      e_type;
    uint16_t      e_machine;
    uint32_t      e_version;
    Elf32_Addr     e_entry;
    Elf32_Off      e_phoff;      /* program header table's file offset in bytes */
    Elf32_Off      e_shoff;      /* section header table's file offset in bytes */
    uint32_t      e_flags;      /* processor-specific flags associated with the file */
    uint16_t      e_ehsize;     /* ELF header's size in bytes */
    uint16_t      e_phentsize;  /* size in bytes of one entry in the file's program header table; */
    uint16_t      e_phnum;      /* number of entries in the program header table */
    uint16_t      e_shentsize;  /* size in bytes of one entry in the file's section header table */
    uint16_t      e_shnum;      /* number of entries in the section header table */
    uint16_t      e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    uint32_t   p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    uint32_t   p_filesz;
    uint32_t   p_memsz;
    uint32_t   p_flags;
    uint32_t   p_align;
} Elf32_Phdr;   /* Program header */

typedef struct {
    uint32_t   sh_name;
    uint32_t   sh_type;
    uint32_t   sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off  sh_offset;
    uint32_t   sh_size;
    uint32_t   sh_link;
    uint32_t   sh_info;
    uint32_t   sh_addralign;
    uint32_t   sh_entsize;
} Elf32_Shdr;   /* Segment header */

typedef struct {
    Elf32_Word n_namesz;
    Elf32_Word n_descsz;
    Elf32_Word n_type;
} Elf32_Nhdr;   /* Note header */

#define	EI_MAG0		0		/* e_ident[] indexes */
#define	EI_MAG1		1
#define	EI_MAG2		2
#define	EI_MAG3		3
#define	EI_CLASS	4
#define	EI_DATA		5
#define	EI_VERSION	6
#define	EI_OSABI	7
#define	EI_PAD		8

#define	ELFMAG0		0x7f		/* EI_MAG */
#define	ELFMAG1		'E'
#define	ELFMAG2		'L'
#define	ELFMAG3		'F'
#define	ELFMAG		"\177ELF"
#define	SELFMAG		4

#define PF_R		0x4
#define PF_W		0x2
#define PF_X		0x1
#define PF_MASK     0x7

enum ELF_CLASS   {ELFCLASSNONE, ELFCLASS32, ELFCLASS64, ELFCLASSNUM};
enum ELF_DATA    {ELFDATANONE, ELFDATA2LSB/* little-endian */, ELFDATA2MSB /* big-endian */};
enum ELF_VER     {EV_NONE, EV_CURRENT};
enum ELF_ABI     {ELFOSABI_NONE, ELFOSABI_SYSV = 1, ELFOSABI_LINUX = 3};
enum ELF_TYPE    {ET_NONE, ET_REL, ET_EXEC, ET_DYN, ET_CORE};
enum ELF_MACHINE {EM_386 = 3};

extern u32 get_elf_entry(Elf32_Ehdr *header);
extern int elf_invalid(Elf32_Ehdr *header);

#endif