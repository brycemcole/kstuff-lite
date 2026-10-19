/* Read-only timeline: sample idt[1], idt[179], TSS ist4/ist6 slots
 * every 100ms for ~20s. Detects concurrent re-arming writers (kstuff). */
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

static uint64_t
goff(const uint8_t *g) {
  uint16_t lo = 0, mid = 0;
  uint32_t hi = 0;
  memcpy(&lo, g, 2);
  memcpy(&mid, g + 6, 2);
  memcpy(&hi, g + 8, 4);
  return ((uint64_t)hi << 32) | ((uint64_t)mid << 16) | lo;
}

int
main(void) {
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t tss = data + 0x2ee6fe0ULL;
  uint64_t idt = data + 0x2ee4300ULL;
  int fd = open("/data/timeline_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("timeline; fw=%#x text=%#" PRIx64 "\n", kernel_get_fw_version(),
         text);
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  uint64_t last1 = 0, last179 = 0, last4 = 0, last6 = 0;
  int changes = 0;
  for(int t = 0; t < 200; t++) {
    uint8_t g1[16], g179[16];
    uint64_t i4 = 0, i6 = 0;
    if(readn(idt + 16, g1, 16) || readn(idt + 179 * 16, g179, 16) ||
       readn(tss + 0x3c, &i4, 8) || readn(tss + 0x4c, &i6, 8)) {
      printf("t=%d read fail\n", t);
      break;
    }
    uint64_t o1 = goff(g1), o179 = goff(g179);
    uint64_t s1 = o1 | ((uint64_t)g1[4] << 48), s179 = o179 | ((uint64_t)g179[4] << 48);
    if(t == 0 || s1 != last1 || s179 != last179 || i4 != last4 || i6 != last6) {
      printf("t=%d idt1=%#" PRIx64 " (rva %#llx ist %u) idt179=%#" PRIx64
             " (rva %#llx ist %u) ist4=%#" PRIx64 " ist6=%#" PRIx64 "\n",
             t, o1, (unsigned long long)(o1 - text), g1[4], o179,
             (unsigned long long)(o179 - text), g179[4], i4, i6);
      last1 = s1;
      last179 = s179;
      last4 = i4;
      last6 = i6;
      changes++;
    }
    usleep(100000);
  }
  printf("TIMELINE_DONE changes=%d\n", changes);
  fsync(STDOUT_FILENO);
  return 0;
}
