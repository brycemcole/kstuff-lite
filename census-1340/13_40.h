/* PS5 13.40 kernel offsets — TF-oracle verified entries.
 * Verification method: execution-only oracle (EPT XOM blocks all data reads
 * of kernel text; no dumps possible). Verified = the instruction(s) executed
 * in kernel context on a live 13.40 console with observed architectural
 * effects (TF #DB frame: post-instruction RIP, RSP, RFLAGS).
 * Everything else is 0 = UNPROVEN. Do not use unproven entries in a handoff.
 * RVAs are from kernel text base (KASLR per boot; kdata = text + 0xCB0000). */

#ifndef OFFSETS_13_40_H
#define OFFSETS_13_40_H

/* --- verified by TF-oracle (2026-10-19, console CFI-1215A fw 13.400.002) --- */
/* `add rsp,0xE8; iretq` — gate trampoline; both halves executed (iretq popped
 * a planted 5-qword frame and resumed user mode). Proven via int179 IST6. */
#define OFF_1340_ADD_RSP_IRET   0x257B36
/* bare `iretq` — proven: fall-through from ADD_RSP_IRET executed it. */
#define OFF_1340_DORETI_IRET    0x257B3D
/* executes 1+ bytes then `ret` (consumed a scratch qword, trapped at target).
 * Exact first-instruction width not isolated (TF suppresses 1st boundary). */
#define OFF_1340_NOP_RET        0x255036
/* `add rsp,0x28` — VERIFIED: 4 bytes wide, sets PF/SF, pops 5 qwords.
 * This is cpu_switch−0x22. */
#define OFF_1340_PIVOT          0x25213E

/* --- IDT/TSS layout (live-census verified, 13.40) --- */
#define OFF_1340_IDT            0x2EE4300  /* kdata RVA */
#define OFF_1340_TSS_ARRAY      0x2EE6FE0  /* kdata RVA, stride 0x68, 16 cpus */
#define OFF_1340_TSS_IST4       0x3C       /* slot offset in TSS row */
#define OFF_1340_TSS_IST6       0x4C
#define OFF_1340_IDT1_NATIVE    0x268dc0   /* rva, ist0, type 0x8e */
#define OFF_1340_IDT179_NATIVE  0x268ef0   /* reserved-vector stub, ist0 */

/* --- live-census verified, not oracle-executed --- */
#define OFF_1340_CPU_SWITCH     0x252160   /* = PIVOT+0x22, boundary implied */
#define OFF_1340_KERNEL_PMAP    0x3B28FF8  /* kdata; pm_pml4@+0x20, pm_cr3@+0x28 */
#define OFF_1340_DATA_CAVE      0x2D29000  /* text RVA; 2MiB NX writable zeros */

/* --- unproven (from r0gdb-era guesses; zeros until oracle-verified) --- */
#define OFF_1340_DBREG_RESUME   0
#define OFF_1340_COPYIN         0
#define OFF_1340_HV_MP_STARTUP  0
#define OFF_1340_MP_STARTUP_VEC 0

#endif
