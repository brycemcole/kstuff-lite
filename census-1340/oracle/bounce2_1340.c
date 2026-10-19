/* 13.40 int3 bounce v2 — self-provisioned IST7 + minimal IDT[3] window.
 *
 * Census (this boot): IDT[3] native {rva 0x268db8, ist0, DPL3, 0xEE};
 * TSS ist6/ist7 slots zero. Native kernel never uses IST7, so pointing all
 * 16 TSS rows at a DATA_CAVE stack and parking frames there is inert until
 * IDT[3] is briefly repointed at add_rsp_iret (ist=7).
 *
 * Chain: int3 -> hw frame at ist7c-0x28 -> add rsp,0xE8 -> ist7c+0xC0 ->
 * iret pops 5-qword user frame -> userland. Zero net swapgs.
 */
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define CAVE_RVA 0x2D29000ULL
#define IST7C_RVA (CAVE_RVA + 0x40000ULL)
#define NATIVE3_RVA 0x268db8ULL

static uint64_t g_tss_rows[16], g_ist7_save[16], g_ist6_save[16];
static uint8_t g_gate3[16];
static volatile int g_returned;

static int
readn(uint64_t a, void *b, size_t n) {
  return kernel_copyout((intptr_t)a, b, n);
}

static int
writen(uint64_t a, const void *b, size_t n) {
  return kernel_copyin(b, (intptr_t)a, n);
}

int
main(void) {
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t tss = data + 0x2ee6fe0ULL;
  uint64_t idt = data + 0x2ee4300ULL;
  uint64_t add_rsp_iret = text + 0x257B36ULL;
  uint64_t ist7c = text + IST7C_RVA;
  uint64_t f_user[5], user_rsp, frame[5];
  uint8_t gate3[16];
  int fd = open("/data/bounce2_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd < 0)
    fd = open("/mnt/usb0/bounce2_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("bounce v2; fw=%#x text=%#" PRIx64 "\n", kernel_get_fw_version(),
         text);
  fsync(STDOUT_FILENO);
  if((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  if(readn(idt + 3 * 16, gate3, 16))
    return 2;
  {
    uint16_t lo = 0, mid = 0;
    uint32_t hi = 0;
    memcpy(&lo, gate3, 2);
    memcpy(&mid, gate3 + 6, 2);
    memcpy(&hi, gate3 + 8, 4);
    uint64_t off = ((uint64_t)hi << 32) | ((uint64_t)mid << 16) | lo;
    printf("idt[3] rva=%#" PRIx64 " ist=%u dpl=%u type=%#02x\n",
           off > text ? off - text : 0, gate3[4] & 7, (gate3[5] >> 5) & 3,
           gate3[5]);
    if(off != text + NATIVE3_RVA || ((gate3[5] >> 5) & 3) != 3) {
      printf("ABORT idt[3] not native\n");
      return 3;
    }
    memcpy(g_gate3, gate3, 16);
  }
  fsync(STDOUT_FILENO);

  for(int cpu = 0; cpu < 16; cpu++) {
    g_tss_rows[cpu] = tss + (uint64_t)cpu * 0x68ULL;
    if(readn(g_tss_rows[cpu] + 0x54, &g_ist7_save[cpu], 8) ||
       readn(g_tss_rows[cpu] + 0x4c, &g_ist6_save[cpu], 8)) {
      printf("tss read fail cpu=%d\n", cpu);
      return 4;
    }
    if(writen(g_tss_rows[cpu] + 0x54, &ist7c, 8)) {
      printf("tss ist7 arm fail cpu=%d\n", cpu);
      goto undo_tss;
    }
  }
  printf("tss ist7 -> cave %#" PRIx64 " x16\n", ist7c);
  fsync(STDOUT_FILENO);

  __asm__ volatile("mov %%rsp, %0" : "=r"(user_rsp));
  f_user[0] = (uint64_t)&&returned_here;
  f_user[1] = 0x43;
  f_user[2] = 0x202;
  f_user[3] = user_rsp;
  f_user[4] = 0x3b;
  if(writen(ist7c + 0xC0, f_user, sizeof f_user)) {
    printf("frame plant fail\n");
    goto undo_tss;
  }

  gate3[4] = (gate3[4] & ~7) | 7;
  {
    uint16_t lo = (uint16_t)add_rsp_iret, mid = (uint16_t)(add_rsp_iret >> 16);
    uint32_t hi = (uint32_t)(add_rsp_iret >> 32);
    memcpy(gate3, &lo, 2);
    memcpy(gate3 + 6, &mid, 2);
    memcpy(gate3 + 8, &hi, 4);
  }

  printf("window open\n");
  fsync(STDOUT_FILENO);
  if(writen(idt + 3 * 16, gate3, 16)) {
    printf("idt[3] patch fail\n");
    goto undo_tss;
  }
  __asm__ volatile("int3" ::: "memory");
  writen(idt + 3 * 16, g_gate3, 16);
  printf("fell through\n");
  goto undo_tss;

returned_here:
  g_returned = 1;
  writen(idt + 3 * 16, g_gate3, 16);
  if(readn(ist7c - 0x28, frame, sizeof frame))
    memset(frame, 0, sizeof frame);
  printf("hw frame rip=%#" PRIx64 " cs=%#" PRIx64 " rflags=%#" PRIx64
         " rsp=%#" PRIx64 " ss=%#" PRIx64 "\n",
         frame[0], frame[1], frame[2], frame[3], frame[4]);

undo_tss:
  for(int cpu = 0; cpu < 16; cpu++) {
    writen(g_tss_rows[cpu] + 0x54, &g_ist7_save[cpu], 8);
    writen(g_tss_rows[cpu] + 0x4c, &g_ist6_save[cpu], 8);
  }
  printf("returned=%d\n", g_returned);
  if(g_returned)
    printf("BOUNCE_OK\n");
  fsync(STDOUT_FILENO);
  return g_returned ? 0 : 6;
}
