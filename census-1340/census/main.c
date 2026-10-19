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
  int result = kernel_copyout((intptr_t)address, buf, n);
  if(result)
    printf("read FAIL at %#" PRIx64 " n=%zu errno=%d\n", address, n, errno);
  return result;
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
  printf("idt[%03d] off=%#" PRIx64 " sel=%#x ist=%u type=%#02x\n",
         vec, off, sel, ist, type);
}

static void
scan_cave(const char *name, uint64_t addr, size_t n) {
  uint8_t buf[0x1000];
  size_t zeros = 0, fail = 0, first_nz = n;
  for(size_t off = 0; off < n; off += sizeof(buf)) {
    size_t chunk = n - off;
    if(chunk > sizeof(buf))
      chunk = sizeof(buf);
    memset(buf, 0xaa, sizeof(buf));
    if(readn(addr + off, buf, chunk)) {
      fail++;
      continue;
    }
    for(size_t i = 0; i < chunk; i++) {
      if(buf[i] == 0)
        zeros++;
      else if(first_nz == n)
        first_nz = off + i;
    }
  }
  printf("cave %s va=%#" PRIx64 " size=%#zx zeros=%zu first_nz=%#zx fail=%zu\n",
         name, addr, n, zeros, first_nz, fail);
}

int
main(void) {
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t idt = data + 0x2ee4300;
  uint64_t tss = data + 0x2ee6fe0;
  uint64_t pcpu = data + 0x2ef8f00;
  uint8_t gate[16];
  int fd = open("/data/census_1340_idt_tss.log",
                O_WRONLY | O_CREAT | O_TRUNC, 0644);

  if(fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("13.40 IDT/TSS/cave census; read-only\n");
  printf("fw=%#x text=%#" PRIx64 " data=%#" PRIx64 " gap=%#" PRIx64 "\n",
         kernel_get_fw_version(), text, data, data - text);
  fsync(STDOUT_FILENO);
  if((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;

  printf("idt=%#" PRIx64 " tss=%#" PRIx64 " pcpu=%#" PRIx64 "\n", idt, tss, pcpu);
  for(int vec = 0; vec <= 20; vec++) {
    if(readn(idt + (uint64_t)vec * 16, gate, sizeof(gate)))
      return 2;
    dump_gate(vec, gate);
  }

  printf("TSS IST6 (hook slot) and IST1 per core:\n");
  for(int core = 0; core < 16; core++) {
    uint64_t row = tss + (uint64_t)core * 0x68;
    uint64_t ist1 = 0, ist6 = 0, rsp0 = 0;
    if(readn(row + 0x04, &rsp0, 8) || readn(row + 0x24, &ist1, 8) ||
       readn(row + 0x4c, &ist6, 8))
      return 3;
    printf("core %02d tss=%#" PRIx64 " rsp0=%#" PRIx64 " ist1=%#" PRIx64
           " ist6=%#" PRIx64 "\n", core, row, rsp0, ist1, ist6);
  }

  uint64_t pcpu0 = 0;
  if(!readn(pcpu, &pcpu0, 8))
    printf("pcpu[0]=%#" PRIx64 "\n", pcpu0);

  scan_cave("1320", text + 0x2D29000ULL, 0x4000);
  scan_cave("1340delta", text + 0x2D2D000ULL, 0x4000);
  scan_cave("1360", text + 0x2D39000ULL, 0x4000);
  printf("census complete\n");
  fsync(STDOUT_FILENO);
  return 0;
}
