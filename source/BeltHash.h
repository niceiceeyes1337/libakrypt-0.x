#ifndef BELT_HASH_H
#define BELT_HASH_H

#include <inttypes.h>
#include "libakrypt.h"

#define BELT_HASH_SIZE 32
#define BELT_HASH_BLOCK_LEN 32

typedef struct
{
    ak_uint8 len_state[BELT_HASH_SIZE];
    ak_uint8* state_ptr;
    ak_uint8* len_ptr;
    ak_uint8 accumulator[BELT_HASH_BLOCK_LEN];
    ak_uint32 acc_occupied;
    ak_uint8 h[BELT_HASH_BLOCK_LEN];
} belt_hash_state;

void belt_hash_init(belt_hash_state ctx[1]);
void belt_hash(const ak_uint8 data[], ak_uint64 len, belt_hash_state ctx[1]);
void belt_end(ak_uint8 hval[], belt_hash_state ctx[1]);

#endif //BELT_HASH_H
