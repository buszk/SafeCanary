#include <stdio.h>
#include <stdlib.h>

#include "pin.H"
#include "branch_pred.h"
#include "libdft_api.h"
#include "xed-iclass-enum.h"
#include "string.h"
#include "assert.h"
#include "tagmap.h"

// Counters
static ADDRINT lastWriteINS = 0;
static ADDRINT lastWriteAddr = 0;
static UINT32 lastWriteSize = 0;

/* thread context */
extern REG thread_ctx_ptr;

/* Record current write */
static VOID CanaryMemWrite(ADDRINT inst_addr, VOID * addr, INT32 size) {
    lastWriteINS = (ADDRINT)inst_addr;
    lastWriteAddr = (ADDRINT)addr;
    lastWriteSize = size;
}

/* test: assert the reg as tainted */
static VOID PIN_FAST_ANALYSIS_CALL
assert_reg32_tainted(thread_ctx_t *thread_ctx, uint32_t reg) {
    assert(thread_ctx->vcpu.gpr[reg]);
    // printf("Tainted: %s\n", thread_ctx->vcpu.gpr[reg]? "yes": "no");
}
static VOID CanaryMemWriteAfter(ADDRINT inst_addr) {
    /* Mark the Write location tainted */
    if (lastWriteINS == inst_addr) {
        if (lastWriteSize == 4) {
            tagmap_setl(lastWriteAddr);
        }
        else if (lastWriteSize == 2) {
            tagmap_setw(lastWriteAddr);
        }
        else if (lastWriteSize == 1) {
            tagmap_setb(lastWriteAddr);
        }
        else {
            assert (0);
        }
        assert(tagmap_getb(lastWriteAddr) );
    }
    else {
        assert (0);
    }
    printf("%x: %x, %d\n", inst_addr, lastWriteAddr, lastWriteSize);
}
static void ins_inspect (INS ins, VOID *v) {

	/* find all mov instruction */

	if (INS_IsMov(ins)) {
        /* find all canary setup */
        INS next = INS_Next(ins);
        if (INS_RegRContain(ins, REG_SEG_GS) && INS_IsMemoryRead(ins) && INS_IsStackWrite(INS_Next(ins))) {
            // possible canary
            // TODO: optimize with bit op
            if (INS_Disassemble(ins).find("gs:[0x14]") != std::string::npos) {
                // canary
			    printf("%x: %s\n", INS_Address(ins), INS_Disassemble(ins).c_str());
                printf("%x: %s\n", INS_Address(next), INS_Disassemble(next).c_str());
                printf("%d\n", INS_OperandReg(ins, (UINT32) 0));
                /*
                 * Add callbacks to taint the stack memory
                 * The first insert call checks for address and size to write
                 * The second insert call that verifies the Mem write succeed
                 *     and taint the memory range.
                 */
                INS_InsertCall(
                        INS_Next(ins), IPOINT_BEFORE, (AFUNPTR)CanaryMemWrite,
                        IARG_INST_PTR,
                        IARG_MEMORYWRITE_PTR,
                        IARG_MEMORYWRITE_SIZE,
                        IARG_END);

                INS_InsertCall(
                        INS_Next(ins), IPOINT_AFTER, (AFUNPTR)CanaryMemWriteAfter,
                        IARG_INST_PTR,
                        IARG_END); 
            }
            return;
        }
    }        


    /* Check at canary check time that the canary is actually tainted  */
    if ((xed_iclass_enum_t)INS_Opcode(ins) == XED_ICLASS_XOR) {
        if (INS_RegRContain(ins, REG_SEG_GS) && INS_IsMemoryRead(ins)) {
            // TODO: make this bit op
            if (INS_Disassemble(ins).find("gs:[0x14]") != std::string::npos) {
                INS prev = INS_Prev(ins);
                printf("%x: %s\n", INS_Address(prev), INS_Disassemble(prev).c_str());
                printf("%x: %s\n", INS_Address(ins), INS_Disassemble(ins).c_str());
                printf("%d\n", INS_OperandReg(prev, (UINT32) 0));
                REG reg_dst = INS_OperandReg(prev, (UINT32) 0);
                assert (INS_OperandReg(prev, 0) == INS_OperandReg(ins, 0));
                INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)assert_reg32_tainted,
                        IARG_REG_VALUE, thread_ctx_ptr,
                        IARG_UINT32, REG32_INDX(reg_dst),
                        IARG_END);
            }
        }	
    }
}


/*
 * Safe Canary
 * 
 * Use libdft to protect canary from leaking
 *
 */
int main (int argc, char **argv) {
	
	/* initialize symbol processing */
	PIN_InitSymbols();

	/* initialize PIN */
	if (unlikely(PIN_Init(argc, argv)))
		goto err;
	
	/* initialize libdft */
	if (unlikely(libdft_init() != 0))
		goto err;

	/* add canary create check */
	INS_AddInstrumentFunction(ins_inspect, NULL);

    /*
     * Install taint check at print syscall
     */


	/* start PIN */
	PIN_StartProgram();

	/* typically not reached; make the compiler happy */
	return EXIT_SUCCESS;

err:
	
    /* detach from teh process */
    libdft_die();

    /* return */
	return EXIT_FAILURE;
}


