#include <stdio.h>
#include <stdlib.h>

#include <log/log.h>

#include "typedef.h"
#include "basic_op.h"
#include "oper_32b.h"
#include "math_op.h"
#include "cnst.h"
#include "acelp.h"
#include "cod_main.h"
#include "bits.h"
#include "main.h"
#include "voAMRWB.h"
#include "mem_align.h"
#include "cmnMemory.h"


#define NUM_INPUTS 32

Word16 input[64] = {
    0,     0,    0,     0,     0,     0,     0,     0,     0,     0,     0,
    0,     0,    0,     0,     -4,    8,     -4,    -20,   76,    -176,  330,
    -550,  848,  -1238, 1742,  -2414, 3398,  -5200, 11070, 28057, -4314, 1636,
    -675,  299,  -245,  424,   -789,  1328,  -2069, 3140,  -5032, 10906, 28124,
    -4316, 1565, -498,  -32,   307,   -431,  461,   -423,  330,   -190,  6,
    217,   -487, 821,   -1248, 1812,  -2606, 3802,  -5948, 12262};

Word16 code[64] = {
    512, 0,   -1536, 1024, -512, 1536, -1024, -512, -1024, -512, 0, 1024, 0,
    0,   0,   0,     -512, 0,    -512, 0,     0,    -512,  0,    0, 0,    -512,
    0,   512, 0,     0,    0,    0,    -512,  0,    0,     0,    0, 0,    0,
    0,   0,   0,     0,    0,    0,    0,     0,    0,     0,    0, 0,    0,
    0,   0,   0,     0,    0,    0,    0,     0,    0,     0,    0, 0};
Word16 reference[64] = {
    8,  0,  -24, 16, -8, 24,  -16, -8,  -16, -8,  0,   16,  0,   0,   0,   0,
    -8, 0,  -8,  1,  -2, -4,  -7,  11,  -15, 14,  -30, 50,  -65, 138, 349, -54,
    12, -8, 4,   -3, 5,  -10, 17,  -26, 39,  -63, 136, 350, -54, 19,  -6,  0,
    4,  -5, 6,   -5, 4,  -2,  0,   3,   -6,  10,  -16, 23,  -32, 47,  -74, 153};
Word16 actual[64] = {
    0,     0,     -24,   32767, -8,    32767, -16,   -8,    -16,   -8,    0,
    32767, 0,     0,     0,     -1,    -7,    -1,    -9,    32767, -2,    -4,
    -7,    32767, -15,   32767, -31,   32767, -64,   32767, 32767, -54,   0,
    -9,    32767, -4,    0,     -10,   32767, -26,   0,     -63,   32767, 32767,
    -53,   32767, -7,    -1,    0,     -6,    32767, -6,    0,     -3,    32767,
    32767, -6,    32767, -16,   32767, -32,   32767, -75,   32767};
Word16 gain_code = 8, gain_pit = 204;

void loop_correct(Word16 exc[], Word16 code[L_SUBFR], Word16 gain_code, Word16 gain_pit, Word32 i_subfr);
void loop_incorrect(Word16 exc[], Word16 code[L_SUBFR], Word16 gain_code, Word16 gain_pit, Word32 i_subfr);

int main() {

    Word16 *exc;

    exc = &input[0];
    Word32 i_subfr = 0, i;

    short exc_orig[L_SUBFR + L_FRAME];
    short exc_copy[L_SUBFR + L_FRAME];
    int different = false;

    for (i = 0; i < L_SUBFR; i++)
    {
        exc_orig[i + i_subfr] = exc[i + i_subfr];
        exc_copy[i + i_subfr] = exc[i + i_subfr];
    }

    // Using either loop_correct or loop_incorrect produces the same result as
    // the non-vectorized loop below
    loop_incorrect(exc, code, gain_code, gain_pit, i_subfr);
    // loop_correct(exc, code, gain_code, gain_pit, i_subfr);

    #pragma clang loop vectorize(disable)
    for (i = 0; i < L_SUBFR; i++)
    {
        Word32 tmp, L_tmp;
        /* code in Q9, gain_pit in Q14 */
        L_tmp = (gain_code * code[i])<<1;
        L_tmp = (L_tmp << 5);
        tmp = L_mult(exc_copy[i + i_subfr], gain_pit); // (exc[i + i_subfr] * gain_pit)<<1
        L_tmp = L_add(L_tmp, tmp);
        L_tmp = L_shl2(L_tmp, 1);
        exc_copy[i + i_subfr] = extract_h(L_add(L_tmp, 0x8000));
    }

    for (int i = 0; i < L_SUBFR; i++) {
        if (exc[i + i_subfr] != exc_copy[i + i_subfr]) {
            ALOGI("MEDIA-BUG different @ %d: %d vs %d", i, exc[i + i_subfr], exc_copy[i + i_subfr]);
            different = true;

            break;
        }
    }
    if (!different) {
        ALOGI("MEDIA-BUG Output is the same");
    }
    return 0;
}
