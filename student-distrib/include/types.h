/* types.h - Defines to use the familiar explicitly-sized types in this
 * OS (uint32_t, int8_t, etc.).  This is necessary because we don't want
 * to include <stdint.h> when building this OS
 * vim:ts=4 noexpandtab
 */

#ifndef _TYPES_H
#define _TYPES_H

#define NULL 0
#define bool char
#define false 0
#define true 1

#ifndef ASM


/* Types defined here just like in <stdint.h> */
typedef long long int64_t;
typedef unsigned long long uint64_t;

typedef int int32_t;
typedef unsigned int uint32_t;

typedef short int16_t;
typedef unsigned short uint16_t;

typedef char int8_t;
typedef unsigned char uint8_t;

typedef uint16_t u16;
typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int16_t s16;
typedef int8_t  s8;
typedef int32_t s32;
typedef int64_t s64;

typedef long ssize_t;
typedef unsigned long size_t;

typedef unsigned long usl_t;

#define __user __attribute__((noderef, address_space(1)))

#endif /* ASM */

#endif /* _TYPES_H */
