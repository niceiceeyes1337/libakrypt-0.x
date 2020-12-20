#ifndef BELT_HASH_H
#define BELT_HASH_H

#include <inttypes.h>
#include "libakrypt.h"

#define BELT_HASH_SIZE 32
#define BELT_HASH_BLOCK_LEN 32

// describes hash algorithm state
typedef struct
{
    // 128 bit len and 128 bit state s
    ak_uint8 len_state[BELT_HASH_SIZE];
    // ptr to state inside the len_state array
    ak_uint8* state_ptr;
    // ptr to len inside the len_state array
    ak_uint8* len_ptr;
    // tmp buffer for blocks len != 256 bits
    ak_uint8 accumulator[BELT_HASH_BLOCK_LEN];
    // how many bytes of accumulator are in use
    ak_uint32 acc_occupied;
    // h variable
    ak_uint8 h[BELT_HASH_BLOCK_LEN];
} belt_hash_state;

void belt_hash_init(belt_hash_state ctx[1]);
void belt_hash(const ak_uint8 data[], ak_uint64 len, belt_hash_state ctx[1]);
void belt_end(ak_uint8 hval[], belt_hash_state ctx[1]);
void belt_calculate(const ak_uint8* data, ak_uint64 len, ak_uint8 hval[]);


#endif //BELT_HASH_H
