#include "mm.h"
#include "lib.h"
#include "errno.h"
#include "multiboot.h"
#include "tasks.h"
#include "types.h"
#include "vga.h"
#include "list.h"

extern const int __text_start;
extern const int __text_end;
extern const int __data_start;
extern const int __data_end;
extern const int __bss_start;
extern const int __bss_end;
extern const int __kernel_start;
extern const int __kernel_end;

/*
 * @reference:
 *  1. Chapter 4 intel manual volume 3
 */

/*
 * @NOTE 1:
 *  对于内核数据(是指__kernel_start~__kernel_end之间的内存，不包含内核栈)，需要有两个不同的虚拟地址映射到同一物理地址。
 *  这是因为1. 为了确保在开启paging后，内核的指令还能继续执行 2. 在跳转到高地址后，内核的指令还能继续执行
 *  对于STACK_TOP到STACK_BOTTOM之间的内存来说，只需要一次映射，这是因为栈并不需要跳转到高地址
 * @NOTE 2:
 *  According to Chapter 4.1.1 intel manual volume 3, there are four paging modes, we use the first mode (32-bit paging),
 *  which means that CR0.PG=1 && CR4.PAE=0. We don't need PCID(which used for tlb cache between multi user processes)
 *  and protection key, and we doesn't support 48bit phy addr, so there is no need to use 4-level and 5-level paging.
 * @TODO: Currently we disabled 4MB page. Support it in future.
*/

/* @NOTE: about mem_bitmap
 *   Currently we use 16k memory used for memory bitmap, every bit represents PAGE_SIZE memory.
 *   mem_bitmap was stored in bss section, because uninited global variable was stored in bss section.
 * @TODO: bitmap has heavy external memory fragment problem, use buddy system to resolve it.
 * @WARN: when memory is larger than 512MB, SLOTS MUST be larger, otherwise unexpected memory overwritten
          will happen.
 */
uint8_t mem_bitmap[SLOTS];
#define BITS_IN_SLOT (sizeof(mem_bitmap[0])*8)
uint64_t phy_mem_base;
uint64_t phy_mem_len;
uint64_t phy_mem_end;
pgd_t *init_pgtbl_dir;

struct free_mem_stcutre {
    struct list free_pages_head[MAX_ORDER];
    uint32_t nr_free_pages[MAX_ORDER];

    uint32_t all_free_pages;
};

static struct free_mem_stcutre phy_mm_stcutre;

static inline struct list* get_free_pages_head(char order)
{
    return &phy_mm_stcutre.free_pages_head[order];
}

void flush_tlb()
{
    restore_cr3();
}

/* @NOTE: caller must hold mm lock */
#define ITERATE_PAGES(free_statements, used_statements)     \
    int __cur_slot, __cur_bit;                                         \
    int ___nr_slots = ((phy_mem_len / PAGE_SIZE) + BITS_IN_SLOT)/BITS_IN_SLOT;  \
    for (__cur_slot = 0; __cur_slot < ___nr_slots; ++__cur_slot) {    \
        /* every bit in uint8 */                   \
        for (__cur_bit = 0; __cur_bit < BITS_IN_SLOT; ++__cur_bit) {         \
            /* See if bit __cur_bit was set.*/                               \
            if (!(mem_bitmap[__cur_slot] & (1 << __cur_bit))) {              \
                free_statements;                                                                    \
            } else {                                                                                \
                used_statements;                                                                    \
            }                                                                                       \
        }                                                                                           \
    }                                                                                               \


/* only alloc 4k size memory, used for alloc page table */
void* alloc_pgdir()
{
    return alloc_page();
}

/* Get the slot and bit which addr belongs to */
void page_bitmap_get_location(unsigned long addr, int *ret_slot, int *ret_bit)
{
    *ret_slot = (addr - phy_mem_base)/PAGE_SIZE/BITS_IN_SLOT;
    *ret_bit = ((addr - phy_mem_base)/PAGE_SIZE)%BITS_IN_SLOT;
}

static inline void __page_bitmap_set(unsigned long addr, int slot, int bit)
{
    mem_bitmap[slot] |= (1 << bit);
}

static inline void __page_bitmap_clear(unsigned long addr, int slot, int bit)
{
    mem_bitmap[slot] &= ~(1 << bit);
}

void page_bitmap_set(void *addr, char order, char v)
{
    int slot, bit, i;
    unsigned long adr = (unsigned long)addr;

    for (i = 0; i < (1 << order); ++i) {
        page_bitmap_get_location(adr, &slot, &bit);
        if (v == 0) {
            __page_bitmap_clear(adr, slot, bit);
        } else {
            __page_bitmap_set(adr, slot, bit);
        }
        adr += PAGE_SIZE;
    }
}

void page_bitmap_set_busy(void *addr, char order)
{
    page_bitmap_set(addr, order, 1);
}

void page_bitmap_set_free(void *addr, char order)
{
    page_bitmap_set(addr, order, 0);
}

int page_bitmap_init(unsigned long addr)
{
    multiboot_info_t *mbi = (multiboot_info_t*)addr;
    uint32_t nr_pages = 0;
    uint32_t nr_slots = 0;
    uint32_t i = 0, j = 0;
    if (CHECK_FLAG(mbi->flags, 6)) {
        memory_map_t *mmap;
        printf("phy memory:\n");
        for (mmap = (memory_map_t *)mbi->mmap_addr;
                (unsigned long)mmap < mbi->mmap_addr + mbi->mmap_length;
                mmap = (memory_map_t *)((unsigned long)mmap + mmap->size + sizeof (mmap->size))) {
            if (mmap->type != 1)
                continue;
            if (!mmap->base_addr_high && !mmap->base_addr_low)
                continue;
            printf("    base_addr = 0x%#x%#x, length = 0x%#x%#x\n",
                    (unsigned)mmap->base_addr_high,
                    (unsigned)mmap->base_addr_low,
                    (unsigned)mmap->length_high,
                    (unsigned)mmap->length_low);
            phy_mem_base = (((unsigned long long)mmap->base_addr_high) << 32) | (unsigned)mmap->base_addr_low;
            phy_mem_len = (((unsigned long long)mmap->length_high) << 32) | (unsigned)mmap->length_low;
            phy_mem_end = phy_mem_base + phy_mem_len;
        }
    }

    if (!phy_mem_len) {
        KERN_INFO("ERROR: no usable memory\n");
        return -ENOMEM;
    }
    /* make memory size aligned to page_size*/
    phy_mem_len &= ~PAGE_MASK;
    /* mark all memory as used */
    memset(mem_bitmap, 0xffffffff, sizeof(mem_bitmap));

    nr_pages = phy_mem_len / PAGE_SIZE;
    nr_slots = (nr_pages+BITS_IN_SLOT)/BITS_IN_SLOT;
    printf("Memory base is %llx, size is %llx, there are %u pages, used %u slots\n",
           phy_mem_base, phy_mem_len, nr_pages, nr_slots);
    printf("bss start is %lx, bss end is %lx\n", (unsigned long)&__bss_start, (unsigned long)&__bss_end);
    printf("kernel start is %lx, kernel end is %lx\n", (unsigned long)&__kernel_start, (unsigned long)&__kernel_end);

    if (nr_slots >= SLOTS) {
        /*
         * qemu -m $memory is too large, or SLOTS was defined too small
         * Ajust one of them, otherwise will happen unexpected memory overwritten.
         */
        KERN_INFO("BUG: error memory. BITS_IN_SLOT is %d, nr_slots is %d, SLOTS is %d\n", BITS_IN_SLOT, nr_slots, SLOTS);
        return -EINVAL;
    }

    /* every uint8 in mem_bitmap array */
    for (i = 0; i < nr_slots; ++i) {
        /* every bit in uint8 */
        for (j = 0; j < BITS_IN_SLOT; ++j) {
            unsigned long cur_addr = PAGE_SIZE * (i*BITS_IN_SLOT + j) + phy_mem_base;
            /* mark kernel memory as used */
            if (cur_addr >= (unsigned long)&__kernel_start && cur_addr < (unsigned long)&__kernel_end) {
                // printf("cur addr %x is in kernel region, continue\n", cur_addr);
                continue;
            }
            /* mark kernel stack as used */
            if (cur_addr >= STACK_TOP && cur_addr < STACK_BOTTOM) {
                // printf("cur addr %x is in stack region, continue\n", cur_addr);
                continue;
            }

            /* Actually it's not necessary, because VIDEM_MEM is lower than phy_mem_base */
            if (cur_addr >= VIDEO_MEM && cur_addr < VIDEO_MEM+PAGE_SIZE) {
                continue;
            }

            /* Mark page as free */
            mem_bitmap[i] &= ~(1 << j);
        }
    }
    ITERATE_PAGES({}, {
        unsigned long cur_addr = PAGE_SIZE * (__cur_slot*BITS_IN_SLOT + __cur_bit) + phy_mem_base;
        printf("address %x is used, slot is %d, bit is %d\n", cur_addr, __cur_slot, __cur_bit);
    });

    return 0;
}

/* @NOTE: caller must hold mm lock */
int __add_page_mapping(uint32_t linear_addr, uint32_t phy_addr, pgd_t *pgd, bool user)
{
    uint32_t pgd_offset = 0;
    uint32_t pde_offset = 0;
    pde_t pde;  // pde represents 4M size memory
    pte_t pte;  // pte represents 4K size memory

    panic_on(linear_addr % PAGE_SIZE, "linear address should be page aligned 0x%x", linear_addr);

    pgd_offset = get_bits(linear_addr, 22, 31);
    pde_offset = get_bits(linear_addr, 12, 21);

    pde = (uint32_t)pgd[pgd_offset];
    if (!pde) {
        pde = (uint32_t)alloc_pgdir();
        pde |= (1 << PRESENT_BIT);
        pde |= (1 << RW_BIT);
        pde |= (user ? 1 << US_BIT : 0);
        pgd[pgd_offset] = (uint32_t)pde;
    } else if (user) {
        /* Just for test usage. We built user program into memory */
        pde |= (1 << US_BIT);
        pgd[pgd_offset] = (uint32_t)pde;
    }

    pde &= ~(PAGE_MASK);
    pte = ((uint32_t*)pde)[pde_offset];
    if (!pte) {
        pte = (uint32_t)(phy_addr & ~(PAGE_MASK));
        pte |= (1 << PRESENT_BIT);
        pte |= (1 << RW_BIT);
        pte |= (user ? 1 << US_BIT : 0);
        ((uint32_t*)pde)[pde_offset] = pte;
    } else if (user) {
        pte |= (1 << US_BIT);
        ((uint32_t*)pde)[pde_offset] = pte;
    }

    flush_tlb();

    return 0;
}

int kadd_page_mapping(uint32_t linear_addr, uint32_t phy_addr, pgd_t *pgd) {
    return __add_page_mapping(linear_addr, phy_addr, pgd, 0);
}


int uadd_page_mapping(uint32_t linear_addr, uint32_t phy_addr, pgd_t *pgd) {
    return __add_page_mapping(linear_addr, phy_addr, pgd, 1);
}

int page_table_init(pgd_t *pgd)
{
    /* A pgd_t pointer points to a page, which contains 1024 pde_t */
    // init_pgtbl_dir = alloc_pgdir();
    // memset(init_pgtbl_dir, 0, PAGE_SIZE);
    /*
     * We must ensure that
     * linear address 0x&__kenel_start map to phy addr 0x&_kernel_start
     *                0x(&__kernel_start + 4k) map to phy addr 0x(&__kernel_start + 4k)
     *                ...
     *                0x(&__kernel_end) map to phy addr 0x(&__kernel_end)
     */

    ITERATE_PAGES({}, {
       unsigned long cur_addr = PAGE_SIZE * (__cur_slot*BITS_IN_SLOT + __cur_bit) + phy_mem_base;
       if (cur_addr >= (unsigned long)&__kernel_start)
           kadd_page_mapping(cur_addr, cur_addr, pgd);
    });
    kadd_page_mapping(VIDEO_MEM , VIDEO_MEM, pgd);

    return 0;
}

/*
 * Check if the contious (1 << order) pages begining at addr is freed.
 * For example: order == 4, check if all contious 16 bit are 0
 *              There are 3 bytes: 001000[00 00000000 000000]10
 *              Check the bits in [...]
 */
static bool pages_is_free(unsigned long addr, uint8_t order)
{
    int cur_slot = 0;
    int cur_bit = 0;
    int nr_bits = 1 << order;

    page_bitmap_get_location(addr, &cur_slot, &cur_bit);
    if (cur_slot >= SLOTS) {
        panic("invalid slot %d\n", cur_slot);
        return false;
    }

    if (cur_bit != 0 && nr_bits > 0) {
        // 先处理那些非byte对齐的bit
        int remain_bits = 8 - cur_bit;
        int bits = remain_bits;

        if (nr_bits < remain_bits)
            bits = nr_bits;
        if (get_bits(mem_bitmap[cur_slot], cur_bit, cur_bit+bits-1) != 0) {
            goto out_used;
        }
        nr_bits -= bits;
        cur_slot++;
    }

    panic_on(nr_bits < 0, "invalid bits %d\n", nr_bits);
    // 再处理那些byte对齐的bits，直接作为uint8判断是否为0
    if (nr_bits >= (sizeof(uint8_t) * 8)) {
        int nr_slots = nr_bits/8;

        while (nr_slots--) {
            if (mem_bitmap[cur_slot] != 0)
                goto out_used;
            cur_slot++;
        }

        nr_bits %= 8;
    }

    // 最后处理那些在尾部byte不对齐的bits
    if (nr_bits > 0) {
        if (get_bits(mem_bitmap[cur_slot], 0, nr_bits-1) != 0) {
            goto out_used;
        }
    }

    return true;
out_used:
    if (order == 0)
        printf("addr %x is used, slot is %d, bit is %d\n", addr, cur_slot, cur_bit);
    return false;
}

static pfn_t find_buddy_pfn(pfn_t pfn, char order)
{
    return pfn ^ (1 << order);
}

static inline unsigned long pfn_to_page(pfn_t pfn)
{
    return (pfn * PAGE_SIZE) + phy_mem_base;
}

static inline pfn_t page_to_pfn(unsigned long addr)
{
    return (addr - phy_mem_base) / PAGE_SIZE;
}

/* @return: return the next address to be inited */
static unsigned long __init_free_pages_list(unsigned long addr)
{
    char order = 0;
    struct list* head = NULL;
    pfn_t pfn = page_to_pfn(addr);
    pfn_t bd_pfn = find_buddy_pfn(pfn, order);
    unsigned long bd_addr = pfn_to_page(bd_pfn);
    unsigned adr = addr;

    if (!pages_is_free(addr, order)) {
        return addr + PAGE_SIZE;
    }

    while (order < MAX_ORDER) {
        if (!pages_is_free(bd_addr , order) || order == _MAX_ORDER) {
            break;
        }
        if (addr != bd_addr && ((struct list*)bd_addr)->next) {
            list_del((struct list*)bd_addr);
            phy_mm_stcutre.nr_free_pages[order]--;
        }
        addr = addr < bd_addr ? addr : bd_addr;
        order++;
        pfn = page_to_pfn(addr);
        bd_pfn = find_buddy_pfn(pfn, order);
        bd_addr = pfn_to_page(bd_pfn);
    }

    phy_mm_stcutre.nr_free_pages[order]++;
    phy_mm_stcutre.all_free_pages += (1 << order);
    head = get_free_pages_head(order);
    INIT_LIST((struct list*)addr);
    list_add_tail(head , (struct list*)addr);
    adr += (PAGE_SIZE * (1 << order));

    return adr;
}

int init_free_pages_list()
{
    int i = 0;
    unsigned long cur_addr = phy_mem_base;

    memset(&phy_mm_stcutre, 0, sizeof(phy_mm_stcutre));
    for (i = 0; i < MAX_ORDER; ++i) {
        INIT_LIST(get_free_pages_head(i));
    }

    while (cur_addr < phy_mem_end) {
        cur_addr = __init_free_pages_list(cur_addr);
    }

    return 0;
}

void mm_show_statistics(uint32_t ret[MAX_ORDER])
{
    int i = 0;
    while (i < MAX_ORDER) {
        if (ret) {
            ret[i] = phy_mm_stcutre.nr_free_pages[i];
        }
        printf("order%d: %u\n", i, phy_mm_stcutre.nr_free_pages[i]);
        ++i;
    }

    printf("There are %u free pages\n", phy_mm_stcutre.all_free_pages);
}

int init_paging(unsigned long addr)
{
    int ret = 0;

    if ((ret = page_bitmap_init(addr))) {
        return ret;
    }
    clear();

    if ((ret = init_free_pages_list())) {
        return ret;
    }
    clear();
    mm_show_statistics(NULL);

    init_pgtbl_dir = alloc_pgdir();
    panic_on(!init_pgtbl_dir, "alloc pgtable failed\n");
    if ((ret = page_table_init(init_pgtbl_dir)))
        return ret;
    clear();
    mm_show_statistics(NULL);

    return ret;
}

void enable_paging()
{
    uint32_t regs[4] = {0};// rax rbx rcx rdx

    /*
    * As we said in the comments(NOTE2) at the beginning of this file, we use 32-bit paging mode
    * About the details of how to enable paging, see chapter 4.1.2(Paging-mode Enabling) intel manual volume 3.
    */
    /* load init_pgtbl_dir to CR3 register */
    asm volatile (  "movl %0, %%cr3;"
                    "movl %%cr0, %%eax;"
                    "orl $0x80000000, %%eax;"
                    "movl %%eax, %%cr0;"
                    :  /* no output */
                    :"r"(init_pgtbl_dir)  /* input pgtable dir */
                    : "eax");

    /* set CR0.PG = 1 and CR4.PAE(disable PAE) = 0, CR4.PSE = 0(disable reserved bits) */

    /* After enable paging, do some sanity check. Chapter 4.1.4 */
    cpuid(1, regs);

    /* test stack memory paging */
    int a = 10;
    a += 100;
    /* test video memory paging */
    printf("a is %d\n", a);
}

/*
 * For example: split 2 pages from list3 which contains 8 pages
 * Original state
 *          list1:
 *          list2:
 *          list3: ********
 * After step 1
 *          list1:
 *          list2:****
 *          list3:****
 * After step 2
 *          list1:**
 *          list2:****
 *          list3:**
 *
 */
static void split_free_pages_list(char cur_order, char ori_order)
{
    unsigned long addr = 0;
    unsigned long cur_addr = 0;

    addr = (unsigned long)(get_free_pages_head(cur_order)->next);

    while (cur_order-- > ori_order) {
        cur_addr = addr + ((1 << cur_order) * PAGE_SIZE);
        list_add_tail(get_free_pages_head(cur_order), (struct list*)cur_addr);
        phy_mm_stcutre.nr_free_pages[cur_order]++;
    }
}

/* Get (1 << order) pages from buddy system */
void* alloc_pages(char order)
{
    struct list *head = NULL;
    char cur_order = order;
    panic_on(order < 0 || order >= MAX_ORDER, "invalid request order %d\n", order);
    int flags;

    cli_and_save(flags);
    while (cur_order >= 0 && cur_order < MAX_ORDER)  {
        head = get_free_pages_head(cur_order);
        if (list_empty(head)) {
            cur_order++;
            continue;
        }
        /* Found a free pages list */
        head = head->next;
        page_bitmap_set_busy(head, order);
        if (cur_order != order)
            split_free_pages_list(cur_order, order);
        list_del(head);
        phy_mm_stcutre.nr_free_pages[cur_order]--;
        phy_mm_stcutre.all_free_pages -= (1 << order);

        panic_on(((unsigned long)head & PAGE_MASK), "invalid page address 0x%x\n", head);
        return head;
    }
    sti_and_restore(flags);

    return NULL;
}

static void try_to_merge(pfn_t pfn, char order)
{
    pfn_t buddy_pfn = find_buddy_pfn(pfn, order);
    unsigned long page = pfn * PAGE_SIZE + phy_mem_base;
    unsigned long buddy_page = buddy_pfn * PAGE_SIZE + phy_mem_base;
    struct list *head = NULL;

    while (pages_is_free(buddy_page, order)) {
        list_del((void*)page);
        list_del((void*)buddy_page);
        phy_mm_stcutre.nr_free_pages[order] -= 2;
        order++;

        phy_mm_stcutre.nr_free_pages[order]++;
        page = page < buddy_page ? page : buddy_page;
        head = get_free_pages_head(order);
        list_add_tail(head, (void*)page);

        pfn = (page - phy_mem_base) / PAGE_SIZE;
        buddy_pfn = find_buddy_pfn(pfn, order);
        buddy_page = buddy_pfn * PAGE_SIZE + phy_mem_base;
    }
}

/* Return (1 << order) pages to buddy system */
void free_pages(void *addr, char order)
{
    int flags;
    cli_and_save(flags);
    pfn_t pfn = (unsigned long)(addr - phy_mem_base)/PAGE_SIZE;
    struct list *head = NULL;
    INIT_LIST(addr);

    panic_on(order < 0 || order > MAX_ORDER, "invalid order %d\n", order);
    phy_mm_stcutre.all_free_pages += (1 << order);
    phy_mm_stcutre.nr_free_pages[order]++;
    head = get_free_pages_head(order);
    list_add_tail(head, addr);
    page_bitmap_set_free(addr, order);
    try_to_merge(pfn, order);
    sti_and_restore(flags);
}

void* alloc_page()
{
    void *p = alloc_pages(0);

    memset(p, 0, PAGE_SIZE);
    return p;
}

void free_page(void *addr)
{
    free_pages(addr, 0);
}

/*
 * page fault, with error code
 * errno format: bit0: present bit1: read/write bit2: kernel/user access
 */
void page_fault_handler(unsigned long addr, unsigned long errno)
{
    bool page_present = !(errno & (1 << 0));
    bool op_write = errno & (1 << 1);
    bool from_user = errno & (1 << 2);

    KERN_INFO("page fault occured addr: 0x%x\n", addr);
    if (!from_user) {
        kadd_page_mapping(addr, addr, init_pgtbl_dir);
    } else {
        struct task_struct *cur = current();
        pgd_t *pgd = cur->mm.pgdir;
        panic_on(!pgd, "task is 0x%x:%s\n", cur, cur->comm);
        // void *page = alloc_page();

        uadd_page_mapping(addr, addr, pgd);
    }
}

void intr0xE_handler(unsigned long errno)
{
    unsigned long addr = 0;

    asm volatile ("movl %%cr2, %0":"=r"(addr)::);
    addr &= ~PAGE_MASK;

    return page_fault_handler(addr, errno);
}


void liballoc_lock(unsigned long *flags)
{
    cli_and_save(*flags);
}

void liballoc_unlock(unsigned long flags)
{
    sti_and_restore(flags);
}

void* liballoc_alloc(size_t order)
{
    return alloc_pages(order);
}

void liballoc_free(void *addr, size_t order)
{
    // free_pages(addr, order);
}

void restore_cr3()
{
    extern int intr_num;
    struct task_struct *cur = current();
    pgd_t *pgd = cur->mm.pgdir ? cur->mm.pgdir : init_pgtbl_dir;

    panic_on(!pgd, "unexpected pgdir intr is 0x%x\n", (int)intr_num);
    asm volatile ("movl %0, %%cr3" ::"r"(pgd));
}