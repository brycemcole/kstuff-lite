#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ps5/kernel.h>

static uint64_t g_save[16][8];
static uint64_t g_ist7[16];
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
  uint64_t tss = data + 0x2ee6fe0;
  uint64_t frame[5];
  uint64_t user_rsp;
  int fd = open("/data/census_1340_int3.log",
                O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("13.40 int3-to-user trampoline test (all CPUs)\n");
  printf("fw=%#x\n", kernel_get_fw_version());
  if ((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  for (int cpu = 0; cpu < 16; cpu++) {
    uint64_t row = tss + (uint64_t)cpu * 0x68;
    if (readn(row + 0x54, &g_ist7[cpu], 8) ||
        readn(g_ist7[cpu] + 0xc0, g_save[cpu], sizeof g_save[cpu])) {
      printf("save fail cpu=%d\n", cpu);
      return 3;
    }
    printf("cpu%02d ist7=%#" PRIx64 " rip0=%#" PRIx64 "\n",
           cpu, g_ist7[cpu], g_save[cpu][0]);
  }
  printf("arming\n");
  fsync(STDOUT_FILENO);

  __asm__ volatile("mov %%rsp, %0" : "=r"(user_rsp));
  frame[0] = (uint64_t)&&returned_here;
  frame[1] = 0x43;
  frame[2] = 0x202;
  frame[3] = user_rsp;
  frame[4] = 0x3b;
  for (int cpu = 0; cpu < 16; cpu++) {
    if (writen(g_ist7[cpu] + 0xc0, frame, sizeof frame)) {
      printf("write fail cpu=%d\n", cpu);
      goto restore;
    }
  }
  __asm__ volatile("int3" ::: "memory");
  printf("fell through\n");
  goto restore;

returned_here:
  g_returned = 1;

restore:
  for (int cpu = 0; cpu < 16; cpu++) {
    if (g_ist7[cpu] && writen(g_ist7[cpu] + 0xc0, g_save[cpu], sizeof g_save[cpu]))
      printf("restore fail cpu=%d\n", cpu);
  }
  printf("returned=%d\n", g_returned);
  if (g_returned)
    printf("INT3_RETURN_OK\n");
  fsync(STDOUT_FILENO);
  return g_returned ? 0 : 6;
}
