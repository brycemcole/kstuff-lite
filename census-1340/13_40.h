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

/* --- oracle6-8 verdicts (2026-10-19/22; see census-1340-live.txt) --- */
#define OFF_1340_WRMSR_RET      0x255034   /* oracle6 PASS */
#define OFF_1340_POP_RAX        0x2912A1   /* oracle7 PASS */
#define OFF_1340_POP_RCX        0x2918B2   /* oracle7b PASS */
#define OFF_1340_POP_RDI        0x28CE6D   /* oracle7 PASS */

/* --- live-census verified, not oracle-executed --- */
#define OFF_1340_CPU_SWITCH     0x252160   /* = PIVOT+0x22, boundary implied */
#define OFF_1340_KERNEL_PMAP    0x3B28FF8  /* text RVA (= kdata+0x2E78FF8); pm_pml4@+0x20, pm_cr3@+0x28 */
#define OFF_1340_DATA_CAVE      0x2D29000  /* text RVA; 2MiB NX writable zeros */

/* --- upstream-confirmed (EchoStretch/Byepervisor-Reborn 768e8a1, 2026-10-17):
 * their landed 13.40 table matches this header's TF-oracle values 6-for-6:
 * PIVOT 0x25213E, IRETQ 0x257B3D, PMAP_STORE 0x3B28FF8, DATA_CAVE 0x2D29000,
 * HV_MP_STARTUP_CALL 0xC0A620, IDT/TSS layout (their RVAs are text-relative:
 * IDT 0x3B94300 / TSS 0x3B96FE0 = ours kdata-relative +0xCB0000). Their full
 * gadget map then field-proven end-to-end on this console (build needed the
 * kdlsym.c include fix; rest-mode resume -> hypervisor compromised, kernel
 * .text dumped, .text write verified). Pop gadgets: they ship 0x291291 /
 * 0x2918A2 / 0x676252 vs our oracle-proven 0x2912A1 / 0x2918B2 / 0x28CE6D
 * (distinct sites, both sets fire). */
#define OFF_1340_HV_MP_STARTUP  0xC0A620   /* upstream-confirmed; malloc 0xBFC290 + 0xE390 delta */
#define OFF_1340_MP_STARTUP_VEC 0x268D08   /* upstream value (= 13.60; not independently tested) */

/* --- REFUTED on 13.40 (oracle7 series / oracle8b-c console kills) --- */
/* 0x2912A2 (byte after pop rax: control transfer, not ret), 0x2A0F7B,
 * 0x291C42, 0x252142 (NOT a ret: nonsense landing), 0x34CB91 (harmless
 * 5-byte non-gadget), and the r0gdb-table DR gadgets dr2gpr 0x25234D /
 * gpr2dr_1 0x252466 / gpr2dr_2 0x252559 (killed the console at DR2GPR
 * even with full register shields — transplanted RVAs, invalid here). */

/* --- unproven (zeros until verified) --- */
#define OFF_1340_DBREG_RESUME   0x2529D8   /* = cpu_switch+0x878; upstream ships same */
#define OFF_1340_COPYIN         0

#endif
