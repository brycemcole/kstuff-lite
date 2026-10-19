#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ps5/kernel.h>

static int
readn(uint64_t address, void *buf, size_t n) {
  errno = 0;
  int r = kernel_copyout((intptr_t)address, buf, n);
  if (r)
    printf("read FAIL va=%#" PRIx64 " n=%zu errno=%d r=%d\n",
           address, n, errno, r);
  return r;
}

static void
dump_gate(int vec, const uint8_t *g) {
  uint16_t off_lo = 0, sel = 0, off_mid = 0;
  uint32_t off_hi = 0;
  memcpy(&off_lo, g + 0, 2);
  memcpy(&sel, g + 2, 2);
  memcpy(&off_mid, g + 6, 2);
  memcpy(&off_hi, g + 8, 4);
  uint64_t off = ((uint64_t)off_hi << 32) | ((uint64_t)off_mid << 16) | off_lo;
  uint8_t ist = g[4] & 7;
  uint8_t type = g[5];
  printf("idt[%03d] off=%#" PRIx64 " sel=%#x ist=%u type=%#02x dpl=%u\n",
         vec, off, sel, ist, type, (type >> 5) & 3);
}

static void
dumpq(const char *name, uint64_t va, int n) {
  uint64_t buf[16];
  if (n > 16)
    n = 16;
  memset(buf, 0, sizeof buf);
  if (readn(va, buf, (size_t)n * 8))
    return;
  printf("%s va=%#" PRIx64 "\n", name, va);
  for (int i = 0; i < n; i++)
    printf("  +%02x %#" PRIx64 "\n", i * 8, buf[i]);
}

int
main(void) {
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t idt = data + 0x2ee4300;
  uint64_t tss = data + 0x2ee6fe0;
  uint8_t gate[16];
  int fd = open("/data/census_1340_ist.log",
                O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("13.40 IST/IDT inspector; read-only\n");
  printf("fw=%#x text=%#" PRIx64 " data=%#" PRIx64 "\n",
         kernel_get_fw_version(), text, data);
  if ((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;

  int vecs[] = {1, 3, 6, 8, 9, 13, 179};
  for (size_t i = 0; i < sizeof vecs / sizeof vecs[0]; i++) {
    if (readn(idt + (uint64_t)vecs[i] * 16, gate, 16))
      return 2;
    dump_gate(vecs[i], gate);
  }

  printf("CPU0 TSS IST1-7 and rsp0:\n");
  uint64_t rsp0 = 0, ist[8] = {0};
  if (readn(tss + 0x04, &rsp0, 8))
    return 3;
  printf("rsp0=%#" PRIx64 "\n", rsp0);
  for (int i = 1; i <= 7; i++) {
    if (readn(tss + 0x24 + (uint64_t)(i - 1) * 8, &ist[i], 8))
      return 4;
    printf("ist%d=%#" PRIx64 "\n", i, ist[i]);
  }

  if (ist[3])
    dumpq("IST3-0x28", ist[3] - 0x28, 8);
  if (ist[4])
    dumpq("IST4-0x28", ist[4] - 0x28, 8);
  if (ist[6])
    dumpq("IST6-0x28", ist[6] - 0x28, 8);
  if (ist[7])
    dumpq("IST7-0x28", ist[7] - 0x28, 8);

  uint64_t add_rsp = text + 0x257B36;
  uint64_t iret = text + 0x257B3D;
  printf("expected add_rsp_iret=%#" PRIx64 " iretq=%#" PRIx64 "\n",
         add_rsp, iret);
  printf("done\n");
  fsync(STDOUT_FILENO);
  return 0;
}
