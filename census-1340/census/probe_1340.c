/* Probe which kdata VAs copyout serves. Read-only. */
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ps5/kernel.h>

static uint64_t data;

static int
readn(uint64_t a, void *b, size_t n) {
  memset(b, 0xcc, n);
  return kernel_copyout((intptr_t)a, b, n);
}

static void
hex(const char *tag, uint64_t va, const uint8_t *b, size_t n) {
  printf("%s %#" PRIx64 ":", tag, va);
  for(size_t i = 0; i < n; i++)
    printf(" %02x", b[i]);
  printf("\n");
}

int
main(void) {
  uint8_t b[64];
  uint64_t v[4];
  int fd = open("/data/probe_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  printf("probe; fw=%#x text=%#" PRIx64 " data=%#" PRIx64 "\n",
         kernel_get_fw_version(), text, data);
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  int rc = readn(data + 0x2ee4300ULL, b, 16);
  printf("idt0 rc=%d\n", rc);
  hex("idt0", data + 0x2ee4300ULL, b, 16);

  rc = readn(data + 0x28c9e80ULL, v, 8);
  printf("allproc rc=%d val=%#" PRIx64 "\n", rc, v[0]);

  rc = readn(data + 0x682ff8ULL, v, 8);
  printf("pml4page[511] rc=%d val=%#" PRIx64 "\n", rc, v[0]);

  rc = readn(data + 0x682000ULL, b, 32);
  printf("kdata+0x682000 rc=%d\n", rc);
  hex("kdata+0x682000", data + 0x682000ULL, b, 32);

  rc = readn(data + 0x680000ULL, b, 32);
  printf("kdata+0x680000 rc=%d\n", rc);
  hex("kdata+0x680000", data + 0x680000ULL, b, 32);

  rc = readn(data + 0x690000ULL, b, 32);
  printf("kdata+0x690000 rc=%d\n", rc);
  hex("kdata+0x690000", data + 0x690000ULL, b, 32);

  /* pm_pml4 page as VA from its own value: 0xffffffff81972000-ish */
  uint64_t pml4v = 0;
  readn(text + 0x3b28ff8ULL, &pml4v, 8);
  uint64_t page = pml4v & 0x000ffffffffff000ULL;
  rc = readn(page, b, 32);
  printf("pml4page va=%#" PRIx64 " rc=%d\n", page, rc);
  hex("pml4page", page, b, 32);
  printf("PROBE_DONE\n");
  fsync(STDOUT_FILENO);
  return 0;
}
