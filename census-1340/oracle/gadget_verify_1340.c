/* Read-only: verify add_rsp_iret gadget bytes at ktext+0x257B36 via
 * pmap walk + DMAP read. No kernel writes, no traps. */
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define DMAP_BASE 0xFFFFFFA000000000ULL
#define PMAP_STORE_RVA 0x3B28FF8ULL
#define GADGET_RVA 0x257B36ULL
#define PTE_PS 0x80ULL
#define PTE_PA 0x000FFFFFFFFFF000ULL

static int
readn(uint64_t a, void *b, size_t n) {
  return kernel_copyout((intptr_t)a, b, n);
}

static uint64_t g_dmap;

static int
walk(uint64_t pml4_pte, uint64_t va, uint64_t *pa, uint64_t *pte_out) {
  uint64_t idx[4], e, table;
  int sh[4] = {39, 30, 21, 12};
  table = g_dmap | (pml4_pte & PTE_PA);
  for(int i = 0; i < 4; i++) {
    idx[i] = (va >> sh[i]) & 0x1ffULL;
    if(readn(table + idx[i] * 8, &e, 8))
      return 1;
    if(i == 0)
      printf("pml4e=%#" PRIx64 "\n", e);
    if(!(e & 1))
      return 2;
    if(e & PTE_PS) {
      *pa = (e & PTE_PA) | (va & ((1ULL << sh[i]) - 1));
      *pte_out = e;
      return 0;
    }
    table = g_dmap | (e & PTE_PA);
  }
  *pa = (e & PTE_PA) | (va & 0xfffULL);
  *pte_out = e;
  return 0;
}

int
main(void) {
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t pmap = text + PMAP_STORE_RVA;
  uint64_t pml4 = 0, pa = 0, pte = 0, va;
  uint8_t bytes[32];
  int fd = open("/data/gadget_verify_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd < 0)
    fd = open("/mnt/usb0/gadget_verify_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("gadget verify; fw=%#x text=%#" PRIx64 "\n", kernel_get_fw_version(),
         text);
  if((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  if(readn(pmap, &pml4, 8) || !pml4) {
    printf("pmap_store read fail (%#" PRIx64 ")\n", pml4);
    return 2;
  }
  printf("pm_pml4=%#" PRIx64 "\n", pml4);

  static const uint64_t bases[] = {
      0xFFFFFFA000000000ULL, /* DMPML4I=500 (NKPML4E=4) */
      0xFFFFFFFC00000000ULL, /* DMPML4I=496 (NKPML4E=1) */
      0xFFFFFF8000000000ULL, /* DMPML4I=0 */
      0xFFFFFFE000000000ULL, /* DMPML4I=504 */
      0xFFFFFFFE00000000ULL, /* DMPML4I=508 */
  };
  va = text + GADGET_RVA;
  int done = 0;
  for(size_t b = 0; b < sizeof bases / sizeof bases[0] && !done; b++) {
    g_dmap = bases[b];
    if(walk(pml4, va, &pa, &pte)) {
      printf("dmap=%#" PRIx64 " walk fail\n", g_dmap);
      continue;
    }
    if(readn(g_dmap | pa, bytes, sizeof bytes)) {
      printf("dmap=%#" PRIx64 " leaf read fail\n", g_dmap);
      continue;
    }
    printf("dmap=%#" PRIx64 " pa=%#" PRIx64 " pte=%#" PRIx64 " bytes:", g_dmap,
           pa, pte);
    for(size_t i = 0; i < sizeof bytes; i++)
      printf(" %02x", bytes[i]);
    printf("\n");
    done = 1;
  }
  if(!done) {
    printf("no dmap candidate worked\n");
    return 4;
  }
  fsync(STDOUT_FILENO);

  int ok = (bytes[8] == 0x48 && bytes[9] == 0x81 && bytes[10] == 0xc4 &&
            bytes[11] == 0xe8 && bytes[12] == 0 && bytes[13] == 0 &&
            bytes[14] == 0 && bytes[15] == 0x48 && bytes[16] == 0xcf);
  printf("GADGET_%s\n", ok ? "VERIFIED" : "MISMATCH");
  fsync(STDOUT_FILENO);
  return ok ? 0 : 5;
}
