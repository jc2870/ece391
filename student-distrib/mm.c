#include "mm.h"
#include "lib.h"
#include "errno.h"
#include "multiboot.h"
#include "tasks.h"
#include "types.h"
#include "vga.h"
#include "list.h"
#include "x86_desc.h"

extern const int __text_start;
extern const int __text_end;
extern const int __data_start;
extern const int __data_end;
extern const int __bss_start;
extern const int __bss_end;
extern const int __kernel_start;
extern const int __kernel_end;

struct page *mem_map = (struct page*)0xC0800000;

struct kmap {
    u32 vaddr_start;
    u32 paddr_start;
    u32 paddr_end;
    u32 perm;
} kmap[] = {
    // [0] = {
    //     .vaddr_start = (u32)&__text_start,
    //     .paddr_start = vdr2pdr((usl_t)&__text_start),
    //     .paddr_end   = vdr2pdr((usl_t)&__text_end),
    //     .perm        = (PERM_KN|PERM_P|PERM_RO),
    // },
    [1] = {
        .vaddr_start = (u32)&__data_start,
        .paddr_start = vdr2pdr((usl_t)&__data_start),
        .paddr_end   = vdr2pdr((usl_t)&__data_end),
        .perm        = (PERM_KN|PERM_P|PERM_RW),
    },
    [2] = {
        .vaddr_start = (u32)&__bss_start,
        .paddr_start = vdr2pdr((usl_t)&__bss_start),
        .paddr_end   = vdr2pdr((usl_t)&__bss_end),
        .perm        = (PERM_KN|PERM_P|PERM_RW),
    },
    [3] = {
        .vaddr_start = (u32)VIDEO_MEM,
        .paddr_start = vdr2pdr(VIDEO_MEM),
        .paddr_end   = vdr2pdr(VIDEO_MEM_END),
        .perm        = (PERM_KN|PERM_P|PERM_RW),
    }
};

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
uint8_t mem_refcnt[SLOTS*8];    // index is pfn
#define BITS_IN_SLOT (sizeof(mem_bitmap[0])*8)
uint64_t phy_mem_base;
uint64_t phy_mem_len;
uint64_t phy_mem_end;
pgd_t *init_pgtbl_dir;
static bool volatile enable_bootbitmap;

int tmp_test = 0;

static pfn_t buddy_pfn(pfn_t pfn, char order);

static inline usl_t pfn_to_pdr(pfn_t pfn);
static inline pfn_t pdr_to_pfn(unsigned long addr);

static inline struct page* pfn_page(pfn_t pfn);
static inline pfn_t page_pfn(struct page *page);
static inline usl_t page_pdr(struct page *page);
static inline struct page* vdr_page(usl_t addr);
static inline struct page* pdr_page(usl_t addr);

static struct page* alloc_pages(char order);
static void free_pages(struct page*, char order);
static struct page* alloc_page();
static void free_page(struct page *page);
static bool addr_is_free(usl_t addr, uint8_t order);
static void setup_kvm(pgd_t *pgd);
static usl_t boot_bitmap_alloc();
static void mm_assert();

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
    asm volatile ("movl %0, %%cr3"::"r"(current()->mm.pgdir));
}

/* @NOTE: caller must hold mm lock */
#define ITERATE_PAGES(free_statements, used_statements)     do {        \
    int __cur_slot, __cur_bit;                                          \
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
} while (0)


/* only alloc 4k size memory, used for alloc page table */
void* alloc_pgdir()
{
    usl_t page = NULL;
    if (enable_bootbitmap) {
        /* Here get physical address */
        page = boot_bitmap_alloc();
    } else {
        struct page *page = NULL;

        page = get_free_page();
        return (void*)page_vdr(page);
    }

    return (void*)pdr2vdr(page);
}

u32 get_page_ref(void *page)
{
    int flags;
    pfn_t pfn;
    u8 ret;

    cli_and_save(flags);
    pfn = pdr_to_pfn((usl_t)page);
    ret = mem_refcnt[pfn];
    sti_and_restore(flags);
    return ret;
}

void get_page(struct page* page)
{
    int flags;
    pfn_t pfn;

    panic_on(page_vdr(page)%PAGE_SIZE, "invalid page address 0x0x\n", page_vdr(page));
    cli_and_save(flags);
    pfn = page_pfn(page);
    mem_refcnt[pfn]++;
    sti_and_restore(flags);
}

void put_page(struct page* page)
{
    int flags;
    pfn_t pfn;

    panic_on(page_vdr(page)%PAGE_SIZE, "invalid page address 0x0x\n", page_vdr(page));
    cli_and_save(flags);
    pfn = page_pfn(page);
    panic_on(mem_refcnt[pfn] == 0, "mm bug, invalid page refcnt\n");
    mem_refcnt[pfn]--;
    if (mem_refcnt[pfn] == 0) {
        free_page(page);
    }
    sti_and_restore(flags);
}

void get_pages(struct page* page, char order)
{
    int i = 0;

    for (; i < (1 << order); ++i) {
        get_page(page);
        page += PAGE_SIZE;
    }
}

struct page* get_free_pages(char order)
{
    struct page* pages = alloc_pages(order);
    get_pages(pages, order);

    return pages;
}

void put_pages(struct page *pages, char order)
{
    int i = 0;

    for (; i < (1 << order); ++i) {
        put_page(pages);
        pages++;
    }
}

struct page* get_free_page()
{
    struct page* page = alloc_page();
    get_page(page);

    return page;
}

/* Get the slot and bit which addr belongs to */
void page_bitmap_get_location(unsigned long addr, int *ret_slot, int *ret_bit)
{
    *ret_slot = addr/PAGE_SIZE/BITS_IN_SLOT;
    *ret_bit = (addr/PAGE_SIZE)%BITS_IN_SLOT;
}

static inline void __page_bitmap_set(unsigned long addr, int slot, int bit)
{
    mem_bitmap[slot] |= (1 << bit);
}

static inline void __page_bitmap_clear(unsigned long addr, int slot, int bit)
{
    mem_bitmap[slot] &= ~(1 << bit);
}

void page_bitmap_set(usl_t phy_addr, char order, char v)
{
    int slot, bit, i;
    unsigned long adr = phy_addr;

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

void page_bitmap_set_busy(usl_t phy_addr, char order)
{
    page_bitmap_set(phy_addr, order, 1);
}

void page_bitmap_set_free(usl_t phy_addr, char order)
{
    page_bitmap_set(phy_addr, order, 0);
}

int page_bitmap_init(multiboot_info_t *mbi)
{
    uint32_t nr_pages = 0;
    uint32_t nr_slots = 0;
    uint32_t i = 0, j = 0;
    if (CHECK_FLAG(mbi->flags, 6)) {
        memory_map_t *mmap;
        // printf("phy memory:\n");
        mmap = (memory_map_t *)mbi->mmap_addr;
        for (mmap = (memory_map_t*)pdr2vdr((u32)mmap);
                (unsigned long)mmap < pdr2vdr(mbi->mmap_addr) + mbi->mmap_length;
                mmap = (memory_map_t *)((unsigned long)mmap + mmap->size + sizeof (mmap->size))) {
            if (mmap->type != 1)
                continue;
            if (!mmap->base_addr_high && !mmap->base_addr_low)
                continue;
            printf("\tbase_addr = 0x%#x%#x, length = 0x%#x%#x\n",
                    (unsigned)mmap->base_addr_high,
                    (unsigned)mmap->base_addr_low,
                    (unsigned)mmap->length_high,
                    (unsigned)mmap->length_low);
            phy_mem_base = (((unsigned long long)mmap->base_addr_high) << 32) | (unsigned)mmap->base_addr_low;
            phy_mem_len = (((unsigned long long)mmap->length_high) << 32) | (unsigned)mmap->length_low;
            phy_mem_end = phy_mem_base + phy_mem_len;
            break;  // asume no more availble memory
        }
    }

    if (!phy_mem_len) {
        panic("ERROR: no usable memory\n");
    }
    /* make memory size aligned to page_size*/
    phy_mem_len &= ~PAGE_MASK;
    /* mark all memory as used */
    asm volatile ("cld; rep; stosl; "::"D"(mem_bitmap), "a"(0xffffffff), "c"(sizeof(mem_bitmap)/4) : "cc", "memory");
    asm volatile ("cld; rep; stosl; "::"D"(mem_refcnt), "a"(0x0l), "c"(sizeof(mem_refcnt)/4) : "cc", "memory");

    nr_pages = phy_mem_len / PAGE_SIZE;
    nr_slots = (nr_pages+BITS_IN_SLOT)/BITS_IN_SLOT;
    printf("Memory base is %llx, size is %llx, there are %u pages, used %u slots\n",
           phy_mem_base, phy_mem_len, nr_pages, nr_slots);
    printf("bss start is %lx, bss end is %lx\n", (unsigned long)&__bss_start, (unsigned long)&__bss_end);
    printf("kernel start is %lx, kernel end is %lx\n", (unsigned long)&__kernel_start, (unsigned long)&__kernel_end);
    printf("data start is %lx, data end is %lx\n", (unsigned long)&__data_start, (unsigned long)&__data_end);

    if (nr_slots >= SLOTS) {
        /*
         * qemu -m $memory is too large, or SLOTS was defined too small
         * Ajust one of them, otherwise will happen unexpected memory overwritten.
         */
        printf("BUG: error memory. BITS_IN_SLOT is %d, nr_slots is %d, SLOTS is %d\n", BITS_IN_SLOT, nr_slots, SLOTS);
        return -EINVAL;
    }

    /* every uint8 in mem_bitmap array */
    for (i = 0; i < nr_slots; ++i) {
        /* every bit in uint8 */
        for (j = 0; j < BITS_IN_SLOT; ++j) {
            unsigned long cur_addr = PAGE_SIZE * (i*BITS_IN_SLOT + j);

            if (cur_addr >= VIDEO_MEM && cur_addr < VIDEO_MEM_END) {
                // get_page(cur_addr);
                continue;
            }

            if (cur_addr < phy_mem_base || cur_addr >= phy_mem_end) {
                continue;
            }

            /* mark kernel memory as used and set ref count to max */
            if (cur_addr >= vdr2pdr((usl_t)&__kernel_start) && cur_addr < vdr2pdr((usl_t)&__kernel_end)) {
                // get_page(cur_addr);
                continue;
            }
            /* mark kernel stack as used and set ref count to max */
            if (cur_addr >= KSTACK_TOP && cur_addr < KSTACK_BOTTOM) {
                // get_page(cur_addr);
                continue;
            }

            /* Mark page as free */
            mem_bitmap[i] &= ~(1 << j);
        }
    }

    if (CHECK_FLAG(mbi->flags, 3)) {
        int mod_count = 0;
        module_t* mod = (module_t*)pdr2vdr(mbi->mods_addr);
        while (mod_count < mbi->mods_count) {
            for (usl_t cur_addr = mod->mod_start; cur_addr < mod->mod_end; cur_addr += PAGE_SIZE) {
                page_bitmap_set_busy(cur_addr, 0);
                // get_page(cur_addr);
            }
            mod_count++;
            mod++;
        }
    }

#ifdef DEBUG_MM
    ITERATE_PAGES({}, {
        unsigned long cur_addr = PAGE_SIZE * (__cur_slot*BITS_IN_SLOT + __cur_bit);
        printf("address %x is used, slot is %d, bit is %d\n", cur_addr, __cur_slot, __cur_bit);
    });
#endif

    return 0;
}

static pte_t *get_pte(uint32_t vaddr, pgd_t *pgd)
{
    uint32_t pgd_offset = 0;
    uint32_t pde_offset = 0;
    pde_t pde;  // pde represents 4M size memory
    pte_t pte;  // pte represents 4K size memory
    pte_t *ret = NULL;

    panic_on(vaddr % PAGE_SIZE, "linear address should be page aligned 0x%x", vaddr);

    pgd_offset = get_bits(vaddr, 22, 31);
    pde_offset = get_bits(vaddr, 12, 21);

    pde = (uint32_t)pgd[pgd_offset];
    panic_on(!pde, "should never happed\n");

    pde &= ~(PAGE_MASK);
    pte = ((uint32_t*)pde)[pde_offset];
    panic_on(!pte, "should never happed\n");

    ret = &((uint32_t*)pde)[pde_offset];

    return ret;
}

static pte_t __do_cow_page(u32 vaddr, struct page *page, pgd_t *pgd)
{
    pte_t pte;

    pte = page_pdr(page);
    pte |= (1 << PRESENT_BIT);
    pte |= (1 << RW_BIT);
    pte |= (1 << US_BIT);
    *get_pte(vaddr, pgd) = pte;

    flush_tlb();

    return pte;
}

/* @NOTE: caller must hold mm lock */
int __add_page_mapping(uint32_t vaddr, uint32_t paddr, pgd_t *pgd, u32 perm)
{
    uint32_t pgd_offset = 0;
    uint32_t pde_offset = 0;
    pde_t pde;  // pde represents 4M size memory
    pte_t pte;  // pte represents 4K size memory

    panic_on(vaddr % PAGE_SIZE, "linear address should be page aligned 0x%x", vaddr);

    pgd_offset = get_bits(vaddr, 22, 31);
    pde_offset = get_bits(vaddr, 12, 21);

    pde = (uint32_t)pgd[pgd_offset];
    if (!pde) {
        pde = (uint32_t)alloc_pgdir();
        __add_page_mapping(pde, vdr2pdr(pde), current()->mm.pgdir, perm);
        pde = vdr2pdr(pde);
    }
    pde |= perm;
    pgd[pgd_offset] = (uint32_t)pde;
    pde = pdr2vdr(pde);

    pde &= ~(PAGE_MASK);
    pte = ((uint32_t*)pde)[pde_offset];
    if (!pte) {
        pte = paddr;
    }
    pte |= perm;
    ((uint32_t*)pde)[pde_offset] = pte;

    return 0;
}

void page_table_init(pgd_t *pgd, bool user)
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
    setup_kvm(pgd);
}

static void setup_kvm(pgd_t *pgd)
{
    u64 vaddr = pdr2vdr(0);
    u32 nr_phy_pages = phy_mem_len / PAGE_SIZE;
    u32 memmap_pages = (nr_phy_pages * sizeof(struct page) + PAGE_SIZE-1)/ PAGE_SIZE;
    int i = 0;
    int perm = PERM_P|PERM_KN|PERM_RW;

    while (vaddr < 0xC0800000) {
        __add_page_mapping(vaddr, vdr2pdr(vaddr), pgd, perm);
        vaddr += PAGE_SIZE;
    }

    vaddr = (u32)mem_map;
    for (i = 0; i < memmap_pages; ++i) {
        __add_page_mapping(vaddr, vdr2pdr(vaddr), pgd, perm);
        vaddr += PAGE_SIZE;
    }
}

void kpgtbl_init(pgd_t *pgd)
{
    setup_kvm(pgd);
}

void upgtbl_init(struct task_struct *task)
{
    pgd_t *pgd = task->mm.pgdir;
    char *stack = (char*)task;
    int size = 0;
    for (; size < STACK_SIZE; size += PAGE_SIZE, stack += PAGE_SIZE) {
        __add_page_mapping((usl_t)stack, vdr2pdr((usl_t)stack), pgd, PERM_KN|PERM_P|PERM_RW);
    }

    /* @fixme: bug here.  */
    page_table_init(pgd, 1);
}

/*
 * Check if the contious (1 << order) pages begining at addr is freed.
 * For example: order == 4, check if all contious 16 bit are 0
 *              There are 3 bytes: 001000[00 00000000 000000]10
 *              Check the bits in [...]
 */
static bool addr_is_free(usl_t addr, uint8_t order)
{
    int cur_slot = 0;
    int cur_bit = 0;
    int nr_bits = 1 << order;
    usl_t adr = 0;

    page_bitmap_get_location(addr, &cur_slot, &cur_bit);
    adr = PAGE_SIZE * (cur_slot*BITS_IN_SLOT + cur_bit);
    panic_on(adr != addr, "error\n");
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
    return false;
}

static pfn_t buddy_pfn(pfn_t pfn, char order)
{
    return pfn ^ (1 << order);
}

static struct page *buddy_page(struct page *page, char order)
{
    pfn_t bd_pfn = buddy_pfn(page_pfn(page), order);

    return pfn_page(bd_pfn);
}

static inline usl_t pfn_to_pdr(pfn_t pfn)
{
    return (pfn * PAGE_SIZE);
}

static inline pfn_t pdr_to_pfn(unsigned long addr)
{
    return addr / PAGE_SIZE;
}

static inline struct page* pfn_page(pfn_t pfn){
    return &mem_map[pfn];
}

static inline pfn_t page_pfn(struct page *page)
{
    return ((usl_t)page - (usl_t)mem_map) / sizeof(struct page);
}

static inline usl_t page_pdr(struct page *page)
{
    pfn_t pfn = page_pfn(page);
    return pfn_to_pdr(pfn);
}

inline usl_t page_vdr(struct page *page)
{
    return pdr2vdr(page_pdr(page));
}

static inline struct page * pdr_page(usl_t paddr)
{
    pfn_t pfn = pdr_to_pfn(paddr);
    return pfn_page(pfn);
}

static inline struct page* vdr_page(usl_t vaddr)
{
    return pdr_page(vdr2pdr(vaddr));
}

static void mm_assert()
{
    char order = 0;
    struct list *head;

    for(; order < MAX_ORDER; ++order) {
        head = get_free_pages_head(order);
        struct page *page;
        usl_t padr;

        list_for_each_entry(page, head, bd_list) {
            padr = page_pdr(page);
            if (!addr_is_free(padr, order)) {
                panic("mm bug, order %d, page 0x%x, addr 0x%x\n",
                    order, page, padr);
            }
        }
    }
}

/* @return: return the next address to be inited */
static unsigned long __init_free_pages_list()
{
    usl_t paddr = 0;
    struct list* head = get_free_pages_head(0);
    char order = 0;

    while (paddr < phy_mem_end) {
        struct page *page = pdr_page(paddr);

        if (!addr_is_free(paddr, 0)) {
            paddr += PAGE_SIZE;
            continue;
        }

        list_add_tail(head, &page->bd_list);
        phy_mm_stcutre.nr_free_pages[0]++;
        phy_mm_stcutre.all_free_pages++;
        paddr += PAGE_SIZE;
    }

    for (order = 0; order < _MAX_ORDER; ++order) {
        head = get_free_pages_head(order);
        struct page *page;
        struct page* bd_page;
        struct list tmpl;
        INIT_LIST(&tmpl);

        list_for_each_entry_safe_from_head(page, head, bd_list) {
            bd_page = buddy_page(page, order);
            if (page_is_free(page, order) && page_is_free(bd_page, order)) {
                list_del(&page->bd_list);
                list_del(&bd_page->bd_list);
                INIT_LIST(&bd_page->bd_list);
                page = min(page, bd_page);
                list_add_tail(get_free_pages_head(order+1), &page->bd_list);
            } else {
                list_del(&page->bd_list);
                list_add_tail(&tmpl, &page->bd_list);
            }
        }

        list_splice(&tmpl, head);
    }
}

int init_free_pages_list()
{
    int i = 0;

    memset(&phy_mm_stcutre, 0, sizeof(phy_mm_stcutre));
    for (i = 0; i < MAX_ORDER; ++i) {
        INIT_LIST(get_free_pages_head(i));
    }

    __init_free_pages_list();

    return 0;
}

void mm_show_statistics(uint32_t ret[MAX_ORDER])
{
    int i = 0;
    while (i < MAX_ORDER) {
        if (ret) {
            ret[i] = phy_mm_stcutre.nr_free_pages[i];
        }
#ifdef DEBUG_MM
        printf("order%d: %u\n", i, phy_mm_stcutre.nr_free_pages[i]);
#endif
        ++i;
    }

#ifdef DEBUG_MM
    printf("There are %u free pages\n", phy_mm_stcutre.all_free_pages);
#endif
}

/* Only support allocation of single page */
static usl_t boot_bitmap_alloc()
{
    usl_t page = 0;
    ITERATE_PAGES({
        page = PAGE_SIZE * (__cur_slot*BITS_IN_SLOT + __cur_bit);
        page_bitmap_set_busy(page, 0);
        return page;
    }, );

    panic("oom\n");
    return 0;
}

static void struct_page_init(struct page *page)
{
    INIT_LIST(&page->bd_list);
}

static void memmap_init()
{
    u32 nr_phy_pages = (phy_mem_len + phy_mem_base) / PAGE_SIZE;
    u32 memmap_pages = (nr_phy_pages * sizeof(struct page) + PAGE_SIZE-1)/ PAGE_SIZE;
    int i = 0;
    u32 vaddr = (u32)mem_map;

    for (i = 0; i < memmap_pages; ++i) {
        __add_page_mapping(vaddr, vdr2pdr(vaddr), &kpgd, 0x3);
        page_bitmap_set_busy(vdr2pdr(vaddr), 0);
        vaddr += PAGE_SIZE;
    }

    for (i = 0; i < nr_phy_pages; ++i) {
        struct_page_init(&mem_map[i]);
    }
}

void mm_init(unsigned long addr)
{
    int ret = 0;
    tmp_test = 0;

    multiboot_info_t *mbi = (multiboot_info_t*)addr;
    memset(mem_refcnt, 0, sizeof(mem_refcnt)/4);
    if ((ret = page_bitmap_init(mbi))) {
        panic("init kpage table failed\n");
    }
    clear();
    enable_bootbitmap = true;
    memmap_init();

    if ((ret = init_free_pages_list())) {
        panic("init kpage table failed\n");
    }
    clear();
    mm_show_statistics(NULL);
    enable_bootbitmap = false;
    init_pgtbl_dir = &kpgd;
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
    struct list *head = NULL;
    struct page *page = NULL;
    struct page *bd_page;

    head = get_free_pages_head(cur_order);
    page = list_first_entry(head, struct page, bd_list);

    while (cur_order-- > ori_order) {
        bd_page = buddy_page(page, cur_order);
        list_del(&bd_page->bd_list);
        list_add_tail(get_free_pages_head(cur_order), &bd_page->bd_list);
        phy_mm_stcutre.nr_free_pages[cur_order+1]--;
        phy_mm_stcutre.nr_free_pages[cur_order]++;
    }
}

/* Get (1 << order) pages from buddy system */
struct page* alloc_pages(char order)
{
    struct list *head = NULL;
    char cur_order = order;
    panic_on(order < 0 || order >= MAX_ORDER, "invalid request order %d\n", order);
    int flags;
    struct page *page = NULL;

    cli_and_save(flags);
    while (cur_order >= 0 && cur_order < MAX_ORDER)  {
        head = get_free_pages_head(cur_order);
        if (list_empty(head)) {
            cur_order++;
            continue;
        }
        /* Found a free pages list */
        page = list_first_entry(head, struct page, bd_list);
        if (!addr_is_free(page_pdr(page), order)) {
            printf("mm bug, try to alloc a busy page\n");
            panic("addr: 0x%x page:0x%x pfn:0x%x order:%d\n",
                page_pdr(page), page, page_pfn(page), order);
        }
        page_bitmap_set_busy(page_pdr(page), order);
        if (cur_order != order)
            split_free_pages_list(cur_order, order);
        list_del(&page->bd_list);
        phy_mm_stcutre.nr_free_pages[cur_order]--;
        phy_mm_stcutre.all_free_pages -= (1 << order);

        panic_on((page_pdr(page) & PAGE_MASK), "invalid page address 0x%x\n", head);
        goto out;
    }

    page = NULL;
out:
    sti_and_restore(flags);
    mm_assert();

    return page;
}

static void try_to_merge(pfn_t pfn, char order)
{
    pfn_t bd_pfn = buddy_pfn(pfn, order);
    usl_t addr = pfn_to_pdr(pfn);
    usl_t bd_addr = pfn_to_pdr(bd_pfn);
    struct page *page = pfn_page(pfn);
    struct page *bd_page = pfn_page(bd_pfn);
    struct list *head = NULL;

    while (addr_is_free(bd_addr, order) && addr_is_free(addr, order)) {
        panic_on(page->bd_list.next == NULL || page->bd_list.prev == NULL,
            "mm bug\n");
        list_del(&page->bd_list);
        list_del(&bd_page->bd_list);
        INIT_LIST(&page->bd_list);
        INIT_LIST(&bd_page->bd_list);
        phy_mm_stcutre.nr_free_pages[order] -= 2;
        order++;

        phy_mm_stcutre.nr_free_pages[order]++;
        addr = addr < bd_addr ? addr : bd_addr;
        page = pdr_page(addr);
        head = get_free_pages_head(order);
        list_add_tail(head, &page->bd_list);

        pfn     = pdr_to_pfn(addr);
        bd_pfn  = buddy_pfn(pfn, order);
        bd_addr = pfn_to_pdr(bd_pfn);
        page    = pfn_page(pfn);
        bd_page = pfn_page(bd_pfn);
    }
}

/* Return (1 << order) pages to buddy system */
void free_pages(struct page* page, char order)
{
    int flags;
    pfn_t pfn = page_pfn(page);
    struct list *head = NULL;

    cli_and_save(flags);
    INIT_LIST(&page->bd_list);

    panic_on(order < 0 || order > MAX_ORDER, "invalid order %d\n", order);
    phy_mm_stcutre.all_free_pages += (1 << order);
    phy_mm_stcutre.nr_free_pages[order]++;
    head = get_free_pages_head(order);
    list_add_tail(head, &page->bd_list);
    page_bitmap_set_free(page_pdr(page), order);
    try_to_merge(pfn, order);

    sti_and_restore(flags);

    mm_assert();
}

struct page* alloc_page()
{
    struct page* page = alloc_pages(0);

    memset((void*)pdr2vdr(page_pdr(page)), 0, PAGE_SIZE);
    return page;
}

void free_page(struct page *page)
{
    free_pages(page, 0);
}

/*
 * page fault, with error code
 * errno format: bit0: present bit1: read/write bit2: kernel/user access
 */
void page_fault_handler(unsigned long addr, unsigned long errno)
{
    bool page_absent = get_bit(errno, 0) == 0;
    bool op_write = get_bit(errno, 1) == 1;
    bool from_user = get_bit(errno, 2) == 1;
    pgd_t *pgd = current()->mm.pgdir;
    panic_on(!addr, "null ptr referenced occured");
    if (!from_user) {
        __add_page_mapping(addr, vdr2pdr(addr), pgd, PERM_KN|PERM_P|PERM_RW);
    } else {
        if (!op_write) {
            __add_page_mapping(addr, vdr2pdr(addr), pgd, PERM_P|PERM_US|PERM_RW);
        } else {
            struct page *page = get_free_page();
            struct page *src_page = NULL;
            pte_t dst_pte = 0;
            pte_t src_pte = 0;

            dst_pte = __do_cow_page(addr, page, pgd);
            src_pte = *get_pte(addr, pgd);
            src_pte &= ~PAGE_MASK;
            dst_pte &= ~PAGE_MASK;
            src_page = pfn_page(pdr_to_pfn(src_pte));
            put_page(src_page);
            memcpy((void*)page_vdr(page), (void*)page_vdr(src_page), PAGE_SIZE);
        }
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
    return (void*)page_vdr(get_free_pages(order));
}

void liballoc_free(void *addr, size_t order)
{
    struct page *page = vdr_page((usl_t)addr);
    put_pages(page, order);
}

u32 shell_stack = 0;
void init_task_mm(struct task_struct *task, Elf32_Ehdr *header)
{
    Elf32_Phdr *pheader = (Elf32_Phdr *)((char *)header + header->e_phoff);
    u32 psize = header->e_phentsize;
    int i = 0;
    void *stack = NULL;

    stack = (void*)page_vdr(get_free_page());
    shell_stack = (u32)stack;
    panic_on(!stack, "alloc stack failed\n");
    __add_page_mapping(task->cpu_state.esp - PAGE_SIZE, (void*)vdr2pdr(stack), task->mm.pgdir, PERM_US|PERM_P|PERM_RW);

    for (i = 0; i < header->e_phnum; ++i) {
        int msize = pheader->p_memsz;
        // printf("vaddr: 0x%x paddr: 0x%x: flag:0x%x\n",
        //     pheader->p_vaddr, pheader->p_paddr, pheader->p_flags);

        while (msize > 0) {
            u32 paddr = (u32)((u8*)header + pheader->p_offset);
            paddr &= ~PAGE_MASK;
            __add_page_mapping(pheader->p_vaddr & ~PAGE_MASK,
                vdr2pdr(paddr), task->mm.pgdir, PERM_RW|PERM_US|PERM_P);
            msize -= PAGE_SIZE;
        }
        pheader = (Elf32_Phdr*)((char*)pheader + psize);
    }
}
extern u32 shell_stack;
void copy_task_mm(struct task_struct *dst, struct task_struct *src)
{
    pgd_t *dst_pgd = dst->mm.pgdir;
    pgd_t *src_pgd = src->mm.pgdir;
    pde_t src_pde;
    pte_t src_pte;
    pte_t dst_pte;
    int i = 0;
    int j = 0;

    for (i = 0; i < MAX_PDE_ENTRY; ++i) {
        u32 new_pde = NULL;
        src_pde = (uint32_t)src_pgd[i];
        if (!src_pde) {
            continue;
        }

        /* alloc new pde */
        new_pde = page_pdr(get_free_page());
        new_pde |= (1 << PRESENT_BIT);
        new_pde |= (1 << RW_BIT);
        new_pde |= (1 << US_BIT);
        dst_pgd[i] = new_pde;

        src_pde = pdr2vdr(src_pde);
        new_pde = pdr2vdr(new_pde);
        src_pde &= ~(PAGE_MASK);
        new_pde &= ~(PAGE_MASK);
        for (j = 0; j < MAX_PTE_ENTRY; ++j) {
            src_pte = ((uint32_t*)src_pde)[j];
            if (!src_pte) {
                continue;
            }

            /* Set pte to readonly */
            dst_pte = src_pte & ~(1 << RW_BIT);
            // if (src_pte > shell_stack && src_pte < shell_stack + PAGE_SIZE) {
            //     printf("set 0x%x to readonly, shell_stack is 0x%x\n", src_pte & ~PAGE_MASK, shell_stack);
            // }
            ((u32*)new_pde)[j] = dst_pte;
            dst_pte &= ~PAGE_MASK;
            get_page(pdr_page(dst_pte));
        }
    }
}

void free_mm(pgd_t *pgd)
{
    pde_t pde;
    pte_t pte;
    int i = 0;
    int j = 0;

    for (i = 0; i < MAX_PDE_ENTRY; ++i) {
        pde = (uint32_t)pgd[i];
        if (!pde) {
            continue;
        }

        pde &= ~(PAGE_MASK);
        pde = pdr2vdr(pde);
        for (j = 0; j < MAX_PTE_ENTRY; ++j) {
            pte = ((uint32_t*)pde)[j];
            if (!pte) {
                continue;
            }

            pte &= ~PAGE_MASK;

            put_page(pdr_page(pte));
        }
        put_page(vdr_page(pde));
    }

    put_page(pdr_page((usl_t)pgd));
}