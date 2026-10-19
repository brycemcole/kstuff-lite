/* Recovery: restore IDT[1]/IDT[179] to native targets after oracle3
 * died with gates armed. IST=0 (handler runs on current stack; ist4
 * native stack value unknown, slot goes unreferenced). TSS ist4/ist6
 * slots zeroed (ist6 native is zero; ist4 slot dead with gate ist=0). */
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ps5/kernel.h>

static int
writen(uint64_t a, const void *b, size_t n) {
  return kernel_copyin(b, (intptr_t)a, n);
}
static int
readn(uint64_t a, void *b, size_t n) {
  return kernel_copyout((intptr_t)a, b, n);
}

static void
mkgate(uint8_t *g, uint64_t target, uint8_t ist, uint8_t type) {
  uint16_t lo = (uint16_t)target, mid = (uint16_t)(target >> 16);
  uint32_t hi = (uint32_t)(target >> 32);
  memset(g, 0, 16);
  memcpy(g, &lo, 2);
  g[2] = 0x20;
  g[4] = ist;
  g[5] = type;
  memcpy(g + 6, &mid, 2);
  memcpy(g + 8, &hi, 4);
}

int
main(void) {
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t tss = data + 0x2ee6fe0ULL;
  uint64_t idt = data + 0x2ee4300ULL;
  uint8_t g[16], cur[16];
  int fd = open("/data/recover_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("recover; fw=%#x text=%#" PRIx64 "\n", kernel_get_fw_version(), text);
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  readn(idt + 16, cur, 16);
  printf("idt[1]  now off=%#" PRIx64 " ist=%u\n",
         ((uint64_t)*(uint32_t *)(cur + 8) << 32) |
             ((uint64_t)*(uint16_t *)(cur + 6) << 16) | *(uint16_t *)cur,
         cur[4]);
  mkgate(g, text + 0x268dc0ULL, 0, 0x8e);
  printf("idt[1]  restore rc=%d\n", writen(idt + 16, g, 16));

  readn(idt + 179 * 16, cur, 16);
  printf("idt[179] now off=%#" PRIx64 " ist=%u\n",
         ((uint64_t)*(uint32_t *)(cur + 8) << 32) |
             ((uint64_t)*(uint16_t *)(cur + 6) << 16) | *(uint16_t *)cur,
         cur[4]);
  mkgate(g, text + 0x268ef0ULL, 0, 0x8e);
  printf("idt[179] restore rc=%d\n", writen(idt + 179 * 16, g, 16));

  for(int cpu = 0; cpu < 16; cpu++) {
    uint64_t row = tss + (uint64_t)cpu * 0x68ULL;
    writen(row + 0x3c, &(uint64_t){0}, 8);
    writen(row + 0x4c, &(uint64_t){0}, 8);
  }
  printf("tss ist4/ist6 zeroed x16\nRECOVER_DONE\n");
  fsync(STDOUT_FILENO);
  return 0;
}
