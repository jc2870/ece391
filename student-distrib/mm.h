#ifndef _MM_h
#define _MM_h

#include "multiboot.h"
#include "types.h"
#include "list.h"
#include "liballoc.h"
#include "elf.h"

#define PAGE_SIZE 4096
#define PAGE_MASK (PAGE_SIZE-1)

#define MAX_MEMORY (4096ull*1024*1024)     // support 4GB memory

#define SLOTS (MAX_MEMORY/PAGE_SIZE/8)
#define _MAX_ORDER 10
#define MAX_ORDER (_MAX_ORDER+1)    // max free list is 4M(4K * 2^10)

#define MAX_PDE_ENTRY (PAGE_SIZE/sizeof(void*))
#define MAX_PTE_ENTRY MAX_PDE_ENTRY

struct task_struct;

extern void mm_init(unsigned long addr);
extern void enable_paging();

extern void* get_free_pages(char order);
extern void put_pages(usl_t addr, char order);
extern void* get_free_page();
extern void put_page(usl_t addr);
extern void mm_show_statistics(uint32_t ret[MAX_ORDER]);

typedef uint32_t pgd_t;
typedef uint32_t pde_t;
typedef uint32_t pte_t;
typedef uint32_t pfn_t; // page frame number

extern pgd_t *init_pgtbl_dir;

#define PRESENT_BIT 0
#define RW_BIT 1    // 0 read only, 1 read & write
#define US_BIT 2    // User/supervisor; if 0, user-mode accesses are not allowed to the 4-KByte page referenced by this entry
#define PWT_BIT 3   // Page-level write-through. Not used
#define PCD_BIT 4   // Page-level cache disable. Not used
#define ACCESS_BIT 5 // Accessed;indicates whether this entry has been used for linear-address translation
#define DIRTY_BIT 6  // Only used in pde. Dirty;
                    //  indicates whether software has written to the 4-KByte page referenced by this entry
#define PS_BIT 7     // determine that if there is a 4M huge page, we always set to 0, means we disable 4M page
#define GLOBAL_BIT 8 // global page. Not used

#define PERM_P  (1 << PRESENT_BIT)
#define PERM_RW (1 << RW_BIT)
#define PERM_RO (0 << RW_BIT)
#define PERM_US (1 << US_BIT)
#define PERM_KN (0 << US_BIT)

#define HIGH_MEM (896 * 1024 *1024)

struct mm {
    pgd_t *pgdir;    // top level pgdir
};

struct page {
    union{
        u64 val[2];
        struct {
            struct list list;
        };
    };
};

extern void upgtbl_init(struct task_struct *task);
extern void init_task_mm(struct task_struct *task, Elf32_Ehdr *header);
extern void copy_task_mm(struct task_struct *dst, struct task_struct *src);
extern void* alloc_pgdir();
extern int __add_page_mapping(uint32_t vaddr, uint32_t paddr, pgd_t *pgd, u32 perm);
extern int page_bitmap_init(multiboot_info_t *mbi);

#endif