/* lib.h - Defines for useful library functions
 * vim:ts=4 noexpandtab
 */

#ifndef _LIB_H
#define _LIB_H

#include "types.h"

/* Macros. */
/* Check if the bit BIT in FLAGS is set. */
#define CHECK_FLAG(flags, bit)   ((flags) & (1 << (bit)))
#define __unused                __attribute__((unused))
#define __always_inline         __attribute__((always_inline))
#define __patchable_func_entry  __attribute__((patchable_function_entry(5)))
#define __section(name)         __attribute__((section(name)))
#define __weak(name)            __attribute__((weak))

int32_t printf(int8_t *format, ...);
uint32_t mprintf(char *fmt, ...);
void putc(uint8_t c);
int32_t puts(int8_t *s);
int8_t itoa(uint32_t value, int8_t* buf, int32_t radix);
int8_t itollu(uint64_t value, int8_t* buf, int32_t radix);
int8_t *strrev(int8_t* s);
uint32_t strlen(const int8_t* s);
void clear(void);
extern void set_screen(int x, int y);


int set_bits(int num, int n, int m);
int clear_bits(int num, int n, int m);
uint32_t get_bits(uint32_t num, int n, int m);
bool get_bit(uint32_t num, int m);
void __panic(int8_t *format, ...);

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define KERN_INFO(format, args...)                      \
do {                                                    \
    printf("func: %s file: %s line: %d " format,        \
           __func__, __FILE__, __LINE__, ## args);      \
} while(0)

#define panic(fmt, args...) \
do {                        \
    printf("############  PANIC  ############\n");  \
    printf("    ");                                 \
    KERN_INFO("\n");   \
    __panic(fmt, ## args);                  \
} while(0)

#define panic_on(cond, fmt, args...)\
do {                                \
    if (unlikely(cond))             \
        panic(fmt, ## args);        \
} while(0)

#define ARRAY_SIZE(p) (sizeof(p)/sizeof(p[0]))
#define min(a, b) ((a) < (b) ? (a) : (b))

void* memset(void* s, int32_t c, uint32_t n);
void* memset_word(void* s, int32_t c, uint32_t n);
void* memset_dword(void* s, int32_t c, uint32_t n);
void* memcpy(void* dest, const void* src, uint32_t n);
void* memmove(void* dest, const void* src, uint32_t n);
int memcmp(const void *s1, const void *s2, size_t n);
int32_t strncmp(const int8_t* s1, const int8_t* s2, uint32_t n);
int8_t* strcpy(int8_t* dest, const int8_t*src);
int8_t* strncpy(int8_t* dest, const int8_t*src, uint32_t n);
char *kstrdup(const char *src);

/* Userspace address-check functions */
int32_t bad_userspace_addr(const void* addr, int32_t len);
int32_t safe_strncpy(int8_t* dest, const int8_t* src, int32_t n);

/* Port read functions */
/* Inb reads a byte and returns its value as a zero-extended 32-bit
 * unsigned int */
static inline uint32_t inb(uint16_t port) {
    uint32_t val;
    asm volatile ("             \n\
            xorl %0, %0         \n\
            inb  (%w1), %b0     \n\
            "
            : "=a"(val)
            : "d"(port)
            : "memory"
    );
    return val;
}

/* Reads two bytes from two consecutive ports, starting at "port",
 * concatenates them little-endian style, and returns them zero-extended
 * */
static inline uint32_t inw(uint16_t port) {
    uint32_t val;
    asm volatile ("             \n\
            xorl %0, %0         \n\
            inw  (%w1), %w0     \n\
            "
            : "=a"(val)
            : "d"(port)
            : "memory"
    );
    return val;
}

static inline void
insl(int port, void *addr, int cnt)
{
  asm volatile("cld; rep insl" :
               "=D" (addr), "=c" (cnt) :
               "d" (port), "0" (addr), "1" (cnt) :
               "memory", "cc");
}

static inline void
outsl(int port, const void *addr, int cnt)
{
  asm volatile("cld; rep outsl" :
               "=S" (addr), "=c" (cnt) :
               "d" (port), "0" (addr), "1" (cnt) :
               "cc");
}

/* Reads four bytes from four consecutive ports, starting at "port",
 * concatenates them little-endian style, and returns them */
static inline uint32_t inl(uint16_t port) {
    uint32_t val;
    asm volatile ("inl (%w1), %0"
            : "=a"(val)
            : "d"(port)
            : "memory"
    );
    return val;
}

/*
 * Sends a 8-bit value on a I/O location.
 * The a modifier enforces val to be placed in the eax register before the asm command is issued
 * and Nd allows for one-byte constant values to be assembled as constants,
 * freeing the edx register for other cases.
 */
#define outb(data, port)                \
do {                                    \
    asm volatile ("outb %b1, (%w0)"     \
            :                           \
            : "d"(port), "a"(data)      \
            : "memory", "cc"            \
    );                                  \
} while (0)

/* Writes two bytes to two consecutive ports */
#define outw(data, port)                \
do {                                    \
    asm volatile ("outw %w1, (%w0)"     \
            :                           \
            : "d"(port), "a"(data)      \
            : "memory", "cc"            \
    );                                  \
} while (0)

/* Writes four bytes to four consecutive ports */
#define outl(data, port)                \
do {                                    \
    asm volatile ("outl %l1, (%w0)"     \
            :                           \
            : "d"(port), "a"(data)      \
            : "memory", "cc"            \
    );                                  \
} while (0)

/* Clear interrupt flag - disables interrupts on this processor */
#define cli()                           \
do {                                    \
    asm volatile ("cli"                 \
            :                           \
            :                           \
            : "memory", "cc"            \
    );                                  \
} while (0)

/* Save flags and then clear interrupt flag
 * Saves the EFLAGS register into the variable "flags", and then
 * disables interrupts on this processor */
#define cli_and_save(flags)             \
do {                                    \
    asm volatile ("                   \n\
            pushfl                    \n\
            popl %0                   \n\
            cli                       \n\
            "                           \
            : "=r"(flags)               \
            :                           \
            : "memory", "cc"            \
    );                                  \
} while (0)

/* Set interrupt flag - enable interrupts on this processor */
#define sti()                           \
do {                                    \
    asm volatile ("sti"                 \
            :                           \
            :                           \
            : "memory", "cc"            \
    );                                  \
} while (0)

#define sti_and_restore(flags)          \
do {                                    \
    asm volatile ("sti\n"               \
                  "pushl %0\n"          \
                  "popfl\n"             \
                  ::"r"(flags):"memory", "cc");       \
} while(0)

/* Restore flags
 * Puts the value in "flags" into the EFLAGS register.  Most often used
 * after a cli_and_save_flags(flags) */
#define restore_flags(flags)            \
do {                                    \
    asm volatile ("                   \n\
            pushl %0                  \n\
            popfl                     \n\
            "                           \
            :                           \
            : "r"(flags)                \
            : "memory", "cc"            \
    );                                  \
} while (0)

static inline void cpuid(uint32_t op, uint32_t regs[4])
{
	asm volatile("cpuid"
	    : "=a" (regs[0]),				// output
	      "=b" (regs[1]),
	      "=c" (regs[2]),
	      "=d" (regs[3])
	    : "a" (op), "c" (0)	// input
	    : "memory");
}

static inline void barrier()
{
    __asm__ __volatile__("": : :"memory");
}

/*
 * Wait a very small amount of time (1 to 4 microseconds, generally).
 * Useful for implementing a small delay for PIC remapping on old hardware or generally as a simple but imprecise wait.
 * You can do an IO operation on any unused port: the Linux kernel by default uses port 0x80,
 * which is often used during POST to log information on the motherboard's hex display but almost always unused after boot.
 */
static inline void io_delay(void)
{
    outb(0, 0x80);
}

static int find_first_set_bit(u32 n)
{
    int ret = 0;
    if (n == 0) {
        return 0xff;
    }
    asm volatile ("bsf %0, %1":"=r"(ret) :"r"(n));
    return ret;
}

static int find_last_set_bit(u32 n)
{
    int ret = 0;
    if (n == 0) {
        return 0xff;
    }
    asm volatile ("bsr %0, %1":"=r"(ret) :"r"(n));
    return ret;
}

static __unused int find_first_free_bit(u32 n)
{
    return find_first_set_bit(~n);
}

static __unused int find_last_free_bit(u32 n)
{
    return find_last_set_bit(~n);
}

static __unused void set_bit(int *num, int n)
{
    *num |= (1 << n);
}

static __unused void clear_bit(int *num, int n)
{
    *num &= ~(1 << n);
}

static inline void __unused outb_d(uint8_t val, uint16_t port)
{
    outb(val, port);
    io_delay();
}

extern void str_trim(char *str);

#endif /* _LIB_H */
