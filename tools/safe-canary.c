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

static VOID CanaryMemWrite(ADDRINT inst_addr, VOID * addr, INT32 size) {
    printf("%x: %x, %d\n", inst_addr, addr, size);
    lastWriteINS = (ADDRINT)inst_addr;
    lastWriteAddr = (ADDRINT)addr;
    lastWriteSize = size;

}
static VOID CanaryMemWriteAfter(ADDRINT inst_addr) {
    printf("%x: %x, %d\n", inst_addr, lastWriteAddr, lastWriteSize);
    // Mark the Write location tainted
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
    }
    else {
        assert (0);
    }
   
}
static void ins_inspect (INS ins, VOID *v) {

	/* find all mov instruction */

	if (INS_IsMov(ins)) {
        /* find all canary setup */
        if (INS_RegRContain(ins, REG_SEG_GS) && INS_IsMemoryRead(ins) && INS_IsStackWrite(INS_Next(ins))) {
            // possible canary
            if (INS_Disassemble(ins).find("gs:[0x14]") != std::string::npos) {
                // canary
			    printf("%x: %s\n", INS_Address(ins), INS_Disassemble(ins).c_str());
                printf("%x: %s\n", INS_NextAddress(ins), INS_Disassemble(INS_Next(ins)).c_str());
                
                // Add callback to taint the stack memory
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
        }
        
/*
        // find all instructions disassembly with gs in it 
		if (INS_Disassemble(ins).find("gs:[0x14]") != std::string::npos) {
			printf("Has gs\n");
            printf("Is memory read: %s\n", INS_IsMemoryRead(ins) ? "true": "false");
			// printf("GS for read : %s\n", INS_RegRContain(ins, REG_SEG_GS) ? "true": "false");
			// printf("GS for write: %s\n", INS_RegWContain(ins, REG_SEG_GS) ? "true": "false");
            printf("Is next INS stack write: %s\n", INS_IsStackWrite(INS_Next(ins)) ? "true": "false");
		}      
*/
	}
/*

	// use XED to decode the instruction and extract its opcode
	xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

	switch (ins_indx) {
		case XED_ICLASS_MOV:
			break;
		default:
			break;
	
    }
 */    
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


