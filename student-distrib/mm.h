#ifndef _MM_h
#define _MM_h

#include "multiboot.h"
#include "types.h"
#include "list.h"
#include "liballoc.h"

#define PAGE_SIZE 4096
#define PAGE_MASK (PAGE_SIZE-1)

#define SLOTS 4096*4
#define _MAX_ORDER 10
#define MAX_ORDER (_MAX_ORDER+1)    // max free list is 4M(4K * 2^10)

extern int init_paging(unsigned long addr);
extern void enable_paging();

extern void* alloc_pages(char order);
extern void free_pages(void* addr, char order);
extern void* alloc_page();
extern void free_page(void* addr);
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

struct mm {
    pgd_t *pgdir;    // top level pgdir
};


extern int kadd_page_mapping(uint32_t linear_addr, uint32_t phy_addr, pgd_t *pgd);
extern int uadd_page_mapping(uint32_t linear_addr, uint32_t phy_addr, pgd_t *pgd);

extern int page_table_init(pgd_t *pgd);

extern void restore_user_cr3();
#endif