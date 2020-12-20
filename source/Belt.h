#ifndef BELT_H
#define BELT_H

#include <inttypes.h>
#include "libakrypt.h"

#define BELT_KS 32
#define BELT_BLOCK_LEN 16

void belt_init(ak_uint8* k, int kLen, ak_uint8* ks);
void belt_encrypt(ak_uint8* ks, ak_uint8* inBlock, ak_uint8* outBlock);

#endif
