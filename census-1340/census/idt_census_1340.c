/* Read-only 13.40 IDT/TSS census. Pure kernel_copyout, no writes, no int3. */
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ps5/kernel.h>

static int
readn(uint64_t a, void *b, size_t n) {
  return kernel_copyout((intptr_t)a, b, n);
}

int
main(void) {
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t tss = data + 0x2ee6fe0ULL;
  uint64_t idt = data + 0x2ee4300ULL;
  int fd = open("/data/idt_census_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd < 0)
    fd = open("/mnt/usb0/idt_census_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("idt census; fw=%#x text=%#" PRIx64 " doreti_iret_rva=%#" PRIx64
         " add_rsp_rva=%#" PRIx64 "\n",
         kernel_get_fw_version(), text, (uint64_t)0x257B3dULL,
         (uint64_t)0x257B36ULL);
  if((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  for(int v = 0; v < 32; v++) {
    uint8_t g[16];
    if(readn(idt + (uint64_t)v * 16, g, 16)) {
      printf("idt read fail v=%d\n", v);
      return 2;
    }
    uint16_t lo = 0, mid = 0;
    uint32_t hi = 0;
    memcpy(&lo, g, 2);
    memcpy(&mid, g + 6, 2);
    memcpy(&hi, g + 8, 4);
    uint64_t off = ((uint64_t)hi << 32) | ((uint64_t)mid << 16) | lo;
    printf("idt[%2d] rva=%#06llx ist=%u dpl=%u type=%#02x raw=",
           v, off > text ? (unsigned long long)(off - text) : 0xffffULL,
           g[4] & 7, (g[5] >> 5) & 3, g[5]);
    for(int i = 0; i < 16; i++)
      printf("%02x", g[i]);
    printf("\n");
  }
  fsync(STDOUT_FILENO);

  for(int cpu = 0; cpu < 16; cpu++) {
    uint64_t row = tss + (uint64_t)cpu * 0x68ULL;
    uint64_t ist4 = 0, ist5 = 0, ist6 = 0, ist7 = 0;
    if(readn(row + 0x40, &ist4, 8) || readn(row + 0x48, &ist5, 8) ||
       readn(row + 0x4c, &ist6, 8) || readn(row + 0x54, &ist7, 8)) {
      printf("tss read fail cpu=%d\n", cpu);
      return 3;
    }
    printf("cpu%02d tss_row=%#" PRIx64 " ist4=%#" PRIx64 " ist5=%#" PRIx64
           " ist6=%#" PRIx64 " ist7=%#" PRIx64 "\n",
           cpu, row, ist4, ist5, ist6, ist7);
  }
  printf("IDT_CENSUS_OK\n");
  fsync(STDOUT_FILENO);
  return 0;
}
