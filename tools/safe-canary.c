#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdarg.h>

#include "pin.H"
#include "libdft_api.h"
#include "xed-iclass-enum.h"
#include "assert.h"
#include "tagmap.h"
#include "syscall_desc.h"
#include "branch_pred.h"
#include "libdft_core.h"

static int debug = 0;
static int log = 0;
// Counters
static ADDRINT lastWriteINS = 0;
static ADDRINT lastWriteAddr = 0;
static UINT32 lastWriteSize = 0;

/* thread context */
extern REG thread_ctx_ptr;

/* ins descriptors */
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];



static int sc_printf(const char* format, ...) {
    va_list arg;
    int done;
    if (log) {
        va_start(arg, format);
        done = vfprintf(stdout,format, arg);
        va_end(arg);
        return done;
    }
    return 0;
}

/* Record current write */
static VOID CanaryMemWrite(ADDRINT inst_addr, VOID * addr, INT32 size) {
    lastWriteINS = (ADDRINT)inst_addr;
    lastWriteAddr = (ADDRINT)addr;
    lastWriteSize = size;
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
    sc_printf("%x: %x, %u\n", inst_addr, lastWriteAddr, lastWriteSize);
}

/* Record current read */
static VOID MemRead(ADDRINT inst_addr, VOID * addr, INT32 size) {
    // check taint map
    if (tagmap_issetn((ADDRINT)addr, size)) {
       dprintf(2, "=====Anomaly Detected=====\nADDR: %p, Loc: %p, size, %d\n", (void *)inst_addr, addr, size); 
       exit(1);
    }
}
/* test: assert the reg as tainted */
static VOID PIN_FAST_ANALYSIS_CALL
assert_reg32_tainted(thread_ctx_t *thread_ctx, uint32_t reg) {
    assert(thread_ctx->vcpu.gpr[reg]);
}
static void ins_inspect (INS ins, VOID *v) {

    INS next = INS_Next(ins);
	/* find all mov instruction */

	if (INS_IsMov(ins)) {
        /* find all canary setup */
        if (INS_RegRContain(ins, REG_SEG_GS) && INS_IsMemoryRead(ins) && INS_IsStackWrite(INS_Next(ins))) {
            // possible canary
            // TODO: optimize with bit op
            if (INS_Disassemble(ins).find("gs:[0x14]") != std::string::npos) {
                // canary
			    if (debug) {
                    sc_printf("%x: %s\n", INS_Address(ins), INS_Disassemble(ins).c_str());
                    sc_printf("%x: %s\n", INS_Address(next), INS_Disassemble(next).c_str());
                    sc_printf("%d\n", INS_OperandReg(ins, (UINT32) 0));
                }
                /*
                 * Add callbacks to taint the stack memory
                 * The first insert call checks for address and size to write
                 * The second insert call that verifies the Mem write succeed
                 *     and taint the memory range.
                 */
                INS_InsertPredicatedCall(
                        INS_Next(ins), IPOINT_BEFORE, (AFUNPTR)CanaryMemWrite,
                        IARG_INST_PTR,
                        IARG_MEMORYWRITE_PTR,
                        IARG_MEMORYWRITE_SIZE,
                        IARG_END);
            }
            return;
        }
        
    }

    if (INS_IsMemoryRead(ins) && 
            !(INS_IsMov(ins) && (xed_iclass_enum_t)INS_Opcode(next) == XED_ICLASS_XOR && INS_RegRContain(next, REG_SEG_GS)) ){
        INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)MemRead,
                IARG_INST_PTR,
                IARG_MEMORYREAD_PTR,
                IARG_MEMORYREAD_SIZE,
                IARG_END
                );
    }

    if (!debug) return;

    /* Check at canary check time that the canary is actually tainted  */
    if ((xed_iclass_enum_t)INS_Opcode(ins) == XED_ICLASS_XOR) {
        if (INS_RegRContain(ins, REG_SEG_GS) && INS_IsMemoryRead(ins)) {
            // TODO: make this bit op
            if (INS_Disassemble(ins).find("gs:[0x14]") != std::string::npos) {
                INS prev = INS_Prev(ins);
                if (debug) {
                    sc_printf("%x: %s\n", INS_Address(prev), INS_Disassemble(prev).c_str());
                    sc_printf("%x: %s\n", INS_Address(ins), INS_Disassemble(ins).c_str());
                    sc_printf("%d\n", INS_OperandReg(prev, (UINT32) 0));
                }
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

static void 
pre_write_hook(syscall_ctx_t *ctx) {
    /* 
     * ctx->arg[SYSCALL_ARG1]: print buffer 
     * ctx->arg[SYSCALL_ARG2]: num byte to print
     */
    if (tagmap_issetn(ctx->arg[SYSCALL_ARG2], ctx->arg[SYSCALL_ARG2])) {
        sc_printf("=====pre data leak detected=====\n");
        exit(1);
    }
}

static void
pre_writev_hook(syscall_ctx_t *ctx) {
    int i;
    struct iovec *iov;
    /* Check each iovec */
    for (i = 0; i < (int)ctx->arg[SYSCALL_ARG2]; i++) {
        iov = ((struct iovec *)ctx->arg[SYSCALL_ARG1]) + i;

        if(tagmap_issetn((size_t)iov->iov_base, iov->iov_len)) {
            sc_printf("=====pre writev leak detected=====\n");
            exit(1);
        }
    }
}
static void 
pre_socketcall_hook(syscall_ctx_t *ctx) {
    uint32_t i;
    struct msghdr *msg;
    struct iovec *iov;
    /* args to the actual function is kept as the arg1 of socketcall syscall*/
    unsigned long *args = (unsigned long *)ctx->arg[SYSCALL_ARG1];
    switch ((int)ctx->arg[SYSCALL_ARG0]) {
        case SYS_SEND:
        case SYS_SENDTO:
            if (tagmap_issetn(args[SYSCALL_ARG2], args[SYSCALL_ARG2])) {
                sc_printf("=====pre socket send leak detected=====\n");
                exit(1);
            }
            break;

        case SYS_SENDMSG:
            msg = (struct msghdr *)args[SYSCALL_ARG1];
            /* Check each iovec */
            for (i = 0; i < msg->msg_iovlen; i++) {
                iov = &msg->msg_iov[i];

                if (tagmap_issetn((size_t)iov->iov_base, (size_t)iov->iov_len)) {
                    sc_printf("=====pre socket sendmsg leak detected=====\n");
                    exit(1);
                }
            }
            break;

        default:
            break;
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

    /* write(2) */
    (void)syscall_set_pre(&syscall_desc[__NR_write], pre_write_hook);

    /* writev(2) */
    (void)syscall_set_pre(&syscall_desc[__NR_writev], pre_writev_hook);
    
    /* socketcall */
    (void)syscall_set_pre(&syscall_desc[__NR_socketcall], pre_socketcall_hook);
	
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


