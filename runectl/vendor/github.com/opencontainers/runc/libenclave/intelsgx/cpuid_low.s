#include "textflag.h"

// func cpuid_low(leaf, subLeaf uint32) (eax, ebx, ecx, edx uint32)
TEXT ·cpuid_low(SB),NOSPLIT,$0-24
    MOVL    arg1+0(FP), AX
    MOVL    arg2+4(FP), CX
    CPUID
    MOVL AX, eax+8(FP)
    MOVL BX, ebx+12(FP)
    MOVL CX, ecx+16(FP)
    MOVL DX, edx+20(FP)
    RET
