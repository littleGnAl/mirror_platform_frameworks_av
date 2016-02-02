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

__attribute__((no_sanitize("integer")))
void loop_correct(Word16 *exc, Word16 *code, Word16 gain_code, Word16 gain_pit, Word32 i_subfr) {
    Word32 i, L_tmp;
    for (i = 0; i < L_SUBFR; i++)
    {
        Word32 tmp;
        L_tmp = (gain_code * code[i])<<1;
        L_tmp = (L_tmp << 5);
        //ALOGI("fix1");
        tmp = L_mult(exc[i + i_subfr], gain_pit); // (exc[i + i_subfr] * gain_pit)<<1
        L_tmp = L_add(L_tmp, tmp);
        L_tmp = L_shl2(L_tmp, 1);
        exc[i + i_subfr] = extract_h(L_add(L_tmp, 0x8000));
    }
}
