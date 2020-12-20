#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "BeltHash.h"

// word for hash 1
const uint8_t x1[] = {
    0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B,
    0x36, 0x6D, 0x00, 0x8E, 0x58
};

// expected result of hash x1
const uint8_t r1[] = {
    0xAB, 0xEF, 0x97, 0x25, 0xD4, 0xC5, 0xA8, 0x35,
    0x97, 0xA3, 0x67, 0xD1, 0x44, 0x94, 0xCC, 0x25,
    0x42, 0xF2, 0x0F, 0x65, 0x9D, 0xDF, 0xEC, 0xC9,
    0x61, 0xA3, 0xEC, 0x55, 0x0C, 0xBA, 0x8C, 0x75
};

// word for hash 2
const ak_uint8 x2[] = {
    0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B,
    0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
    0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC,
    0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D
};

// expected result of hash x2
const uint8_t r2[] = {
    0x74, 0x9E, 0x4C, 0x36, 0x53, 0xAE, 0xCE, 0x5E,
    0x48, 0xDB, 0x47, 0x61, 0x22, 0x77, 0x42, 0xEB,
    0x6D, 0xBE, 0x13, 0xF4, 0xA8, 0x0F, 0x7B, 0xEF,
    0xF1, 0xA9, 0xCF, 0x8D, 0x10, 0xEE, 0x77, 0x86
};

// word for hash 3
const uint8_t x3[] = {
    0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B,
    0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
    0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC,
    0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D,
    0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81,
    0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B
};

// expected result of hash x3
const uint8_t r3[] = {
    0x9D, 0x02, 0xEE, 0x44, 0x6F, 0xB6, 0xA2, 0x9F,
    0xE5, 0xC9, 0x82, 0xD4, 0xB1, 0x3A, 0xF9, 0xD3,
    0xE9, 0x08, 0x61, 0xBC, 0x4C, 0xEF, 0x27, 0xCF,
    0x30, 0x6B, 0xFB, 0x0B, 0x17, 0x4A, 0x15, 0x4A
};

ak_uint32 test_belt_hash(const ak_uint8* enter, ak_uint32 enter_len, const ak_uint8* result, ak_uint32 result_len){
    belt_hash_state state;
    ak_uint8 belt_result[BELT_HASH_SIZE];

    if(result_len != BELT_HASH_BLOCK_LEN)
        return 0;

    belt_hash_init(&state);
    belt_hash(enter, enter_len, &state);
    belt_end(belt_result, &state);

    return (memcmp(belt_result, result, BELT_HASH_SIZE) == 0);
}


int main(int argc, const char * argv[]) {

    printf("\tTest X1...");

    if(test_belt_hash(x1, sizeof(x1), r1, sizeof(r1))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");

    printf("\tTest X2...");

    if(test_belt_hash(x2, sizeof(x2), r2, sizeof(r2))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");

    printf("\tTest X3...");
    if(test_belt_hash(x3, sizeof(x3), r3, sizeof(r3))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");
}
