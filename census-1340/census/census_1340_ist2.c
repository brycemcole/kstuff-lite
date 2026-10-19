#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ps5/kernel.h>

static int
readn(uint64_t address, void *buf, size_t n) {
  return kernel_copyout((intptr_t)address, buf, n);
}

static void
dumpq(const char *name, uint64_t va, int n) {
  uint64_t buf[12];
  memset(buf, 0, sizeof buf);
  if (readn(va, buf, (size_t)n * 8)) {
    printf("%s FAIL va=%#" PRIx64 "\n", name, va);
    return;
  }
  printf("%s va=%#" PRIx64 "\n", name, va);
  for (int i = 0; i < n; i++)
    printf("  +%02x %#" PRIx64 "\n", i * 8, buf[i]);
}

int
main(void) {
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t tss = data + 0x2ee6fe0;
  int fd = open("/data/census_1340_ist2.log",
                O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("fw=%#x text=%#" PRIx64 "\n", kernel_get_fw_version(), text);
  uint64_t ist3=0, ist4=0, ist6=0, ist7=0;
  readn(tss + 0x34, &ist3, 8);
  readn(tss + 0x3c, &ist4, 8);
  readn(tss + 0x4c, &ist6, 8);
  readn(tss + 0x54, &ist7, 8);
  printf("ist3=%#" PRIx64 " ist4=%#" PRIx64 " ist6=%#" PRIx64 " ist7=%#" PRIx64 "\n",
         ist3, ist4, ist6, ist7);
  printf("iret=%#" PRIx64 " add_rsp=%#" PRIx64 " nop_ret=%#" PRIx64 "\n",
         text + 0x257B3D, text + 0x257B36, text + 0x255036);
  dumpq("IST3+0xc0", ist3 + 0xc0, 8);
  dumpq("IST3+0x00", ist3, 8);
  dumpq("IST3-0xe8", ist3 - 0xe8, 8);
  dumpq("IST4+0xc0", ist4 + 0xc0, 8);
  dumpq("IST4+0x00", ist4, 8);
  dumpq("IST7+0xc0", ist7 + 0xc0, 8);
  dumpq("IST7+0x00", ist7, 8);
  dumpq("IST7-0xe8", ist7 - 0xe8, 8);
  printf("done\n");
  fsync(STDOUT_FILENO);
  return 0;
}
