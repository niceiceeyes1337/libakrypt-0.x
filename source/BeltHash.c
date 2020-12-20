#include <string.h>     /* for memcpy() etc.        */

#include "BeltHash.h"
#include "Belt.h"

static void sigma1_xor(ak_uint8* x, ak_uint8* h, ak_uint8* state)
{
    ak_uint8 u3u4[BELT_BLOCK_LEN];
    ak_uint8 tmp[BELT_BLOCK_LEN];

    ((ak_uint64*)u3u4)[0] = ((ak_uint64*)h)[0] ^ ((ak_uint64*)h)[2];
    ((ak_uint64*)u3u4)[1] = ((ak_uint64*)h)[1] ^ ((ak_uint64*)h)[3];

    belt_encrypt(x, u3u4, tmp);

    ((ak_uint64*)state)[0] ^= (((ak_uint64*)tmp)[0] ^ ((ak_uint64*)u3u4)[0]);
    ((ak_uint64*)state)[1] ^= (((ak_uint64*)tmp)[1] ^ ((ak_uint64*)u3u4)[1]);
}

static void sigma1(ak_uint8* u12, ak_uint8* u34, ak_uint8* result)
{
    ak_uint8 u3u4[BELT_BLOCK_LEN];

    ((ak_uint64*)u3u4)[0] = ((ak_uint64*)u34)[0] ^ ((ak_uint64*)u34)[2];
    ((ak_uint64*)u3u4)[1] = ((ak_uint64*)u34)[1] ^ ((ak_uint64*)u34)[3];

    belt_encrypt(u12, u3u4, result);

    ((ak_uint64*)result)[0] ^= ((ak_uint64*)u3u4)[0];
    ((ak_uint64*)result)[1] ^= ((ak_uint64*)u3u4)[1];
}

// it's safe to put h here into result
// x = u1 || u2, h = u3 || u4
// len(x) = 256 bit, len(h) = 256 bit
static void sigma2(ak_uint8* x, ak_uint8* h, ak_uint8* result)
{
    ak_uint8 teta[BELT_KS];
    ak_uint64 h0 = ((ak_uint64*)h)[0];
    ak_uint64 h1 = ((ak_uint64*)h)[1];

    // teta1 = sigma1(u) || u4
    sigma1(x, h, teta);
    ((ak_uint64*)teta)[2] = ((ak_uint64*)h)[2];
    ((ak_uint64*)teta)[3] = ((ak_uint64*)h)[3];

    // F_{teta1}(u1) xor u1
    belt_encrypt(teta, x, result);

    ((ak_uint64*)result)[0] ^= ((ak_uint64*)x)[0];
    ((ak_uint64*)result)[1] ^= ((ak_uint64*)x)[1];

    // (sigma1(u) xor 0xff..ff) || u3
    // invert first part of teta1
    ((ak_uint64*)teta)[0] ^= 0xffffffffffffffffull;
    ((ak_uint64*)teta)[1] ^= 0xffffffffffffffffull;

    // if result == h at this moment original h[0] and h[1] are lost
    ((ak_uint64*)teta)[2] = h0;
    ((ak_uint64*)teta)[3] = h1;

    belt_encrypt(teta, x + BELT_BLOCK_LEN, result + BELT_BLOCK_LEN);

    ((ak_uint64*)result)[2] ^= ((ak_uint64*)x)[2];
    ((ak_uint64*)result)[3] ^= ((ak_uint64*)x)[3];
}

static void iteration(ak_uint8* x, ak_uint8* h, ak_uint8* s)
{
    // update state: s <- s xor sigma1(x_i || h)
    sigma1_xor(x, h, s);
    // update h: h <- sigma2(x_i || h)
    sigma2(x, h, h);
}

static void finalize(belt_hash_state ctx[1], ak_uint8* result)
{
    sigma2(ctx->len_state, ctx->h, result);
}

static void increment_len_block(belt_hash_state ctx[1])
{
    ((ak_uint64*) ctx->len_ptr)[0] += (BELT_HASH_BLOCK_LEN << 3);
    if(((ak_uint64*) ctx->len_ptr)[0] < (BELT_HASH_BLOCK_LEN << 3)){
        ((ak_uint64*) ctx->len_ptr)[1] += 1;
    }
}

static void increment_len_bytes(belt_hash_state ctx[1], ak_uint8 bytes)
{
    ((ak_uint64*) ctx->len_ptr)[0] += (bytes << 3);
    if(((ak_uint64*) ctx->len_ptr)[0] < (bytes << 3)){
        ((ak_uint64*) ctx->len_ptr)[1] += 1;
    }
}

void belt_hash_init(belt_hash_state ctx[1])
{
    ctx->len_ptr = (ak_uint8*)ctx->len_state;
    ctx->state_ptr = (ak_uint8*)ctx->len_state + 16;
    ((ak_uint64*)ctx->len_state)[0] = 0;
    ((ak_uint64*)ctx->len_state)[1] = 0;
    ((ak_uint64*)ctx->len_state)[2] = 0;
    ((ak_uint64*)ctx->len_state)[3] = 0;
    ((ak_uint64*)ctx->accumulator)[0] = 0;
    ((ak_uint64*)ctx->accumulator)[1] = 0;
    ((ak_uint64*)ctx->accumulator)[2] = 0;
    ((ak_uint64*)ctx->accumulator)[3] = 0;
    ((ak_uint64*)ctx->h)[0] = 0x3bf5080ac8ba94b1ull; //0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B,
    ((ak_uint64*)ctx->h)[1] = 0xe45d4a588e006d36ull; //0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
    ((ak_uint64*)ctx->h)[2] = 0xacc7b61b9dfa0485ull; //0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC,
    ((ak_uint64*)ctx->h)[3] = 0x0dcefd02c2722e25ull; //0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D
    ctx->acc_occupied = 0;
}

void belt_hash(const ak_uint8* data, ak_uint64 len, belt_hash_state ctx[1])
{
    if(ctx->acc_occupied > 0){
        if(ctx->acc_occupied + len < BELT_HASH_BLOCK_LEN){
            memcpy(ctx->accumulator + ctx->acc_occupied, data, len);
            ctx->acc_occupied += len;
            return;
        }
        else
        {
            memcpy(ctx->accumulator + ctx->acc_occupied, data, BELT_HASH_BLOCK_LEN - ctx->acc_occupied);
            data += (BELT_HASH_BLOCK_LEN - ctx->acc_occupied);
            len -= (BELT_HASH_BLOCK_LEN - ctx->acc_occupied);

            increment_len_block(ctx);
            iteration(ctx->accumulator, ctx->h, ctx->state_ptr);

            ctx->acc_occupied = 0;
        }
    }

    ctx->acc_occupied = len & (BELT_HASH_BLOCK_LEN - 1);

    while (len > ctx->acc_occupied) {
        increment_len_block(ctx);
        iteration((ak_uint8*)data, ctx->h, ctx->state_ptr);
        data += BELT_HASH_BLOCK_LEN;
        len -= BELT_HASH_BLOCK_LEN;
    }

    if(ctx->acc_occupied > 0)
        memcpy(ctx->accumulator, data, ctx->acc_occupied);
}

void belt_end(ak_uint8 hval[], belt_hash_state ctx[1])
{
    ak_uint32 i;
    if(ctx->acc_occupied > 0)
    {
        for (i = 0; i < BELT_HASH_BLOCK_LEN - ctx->acc_occupied; i += 1) {
            ctx->accumulator[ctx->acc_occupied + i] = 0;
        }
        iteration(ctx->accumulator, ctx->h, ctx->state_ptr);
        increment_len_bytes(ctx, ctx->acc_occupied);
    }
    finalize(ctx, hval);
}

void belt_calculate(const ak_uint8* data, ak_uint64 len, ak_uint8 hval[])
{
    belt_hash_state ctx;
    belt_hash_init(&ctx);

    ctx.acc_occupied = len & (BELT_HASH_BLOCK_LEN - 1);
    while(len > ctx.acc_occupied)
    {
        increment_len_block(&ctx);
        iteration((ak_uint8*)data, ctx.h, ctx.state_ptr);
        data += BELT_HASH_BLOCK_LEN;
        len -= BELT_HASH_BLOCK_LEN;
    }

    if(ctx.acc_occupied > 0)
    {
        memcpy(ctx.accumulator, data, ctx.acc_occupied);
        iteration(ctx.accumulator, ctx.h, ctx.state_ptr);
        increment_len_bytes(&ctx, ctx.acc_occupied);
    }

    finalize(&ctx, hval);
}
