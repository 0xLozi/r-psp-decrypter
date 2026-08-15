#include <stdint.h>
#pragma once

typedef uint8_t u8;
typedef uint32_t u32;

int decompress_kle(u8 *outBuf, int outSize, u8 *inBuf, void **end, int isKl4e);
