#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ps5/kernel.h>

#define SCAN_END 0x2800000ULL
#define PAGE 0x1000U
#define MAX_UNIQUE 768

static int
readn(uint64_t address, void *buf, size_t n) {
  errno = 0;
  return kernel_copyout((intptr_t)address, buf, n);
}

int
main(void) {
  uint64_t data = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint8_t page[PAGE];
  uint64_t unique[MAX_UNIQUE];
  uint32_t counts[MAX_UNIQUE];
  uint64_t first[MAX_UNIQUE];
  size_t nunique = 0;
  uint64_t mp_ptrs = 0, fail = 0, scanned = 0;
  const uint64_t exact[] = {
    0x25213E, 0x252160, 0x25234D, 0x2529D8, 0x255036, 0x257B36, 0x257B3D,
    0x259280, 0x25D027, 0x268EA8, 0x269238, 0x269FB8, 0x26A798,
    0x39006C, 0x3909B0, 0x3913B0,
    0xBFC290, 0xC0A110, 0xC0A310, 0xC0A620, 0xC0D620, 0xC0E27A, 0xC12822,
    0xC16EE0
  };
  int fd = open("/data/census_1340_mpvec.log",
                O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);

  printf("13.40 MP-vector unique scan; read-only\n");
  printf("fw=%#x text=%#" PRIx64 " data=%#" PRIx64 " gap=%#" PRIx64 "\n",
         kernel_get_fw_version(), text, data, data - text);
  if ((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;

  for (uint64_t off = 0; off < SCAN_END; off += PAGE) {
    if ((off & 0xfffff) == 0) {
      printf("progress data+%#" PRIx64 " unique=%zu mp_ptrs=%" PRIu64
             " fail=%" PRIu64 "\n",
             off, nunique, mp_ptrs, fail);
      fsync(STDOUT_FILENO);
    }
    if (readn(data + off, page, PAGE)) {
      fail++;
      continue;
    }
    scanned++;
    for (size_t i = 0; i + 8 <= PAGE; i += 8) {
      uint64_t val = 0;
      memcpy(&val, page + i, 8);
      if (val < text || val >= data)
        continue;
      uint64_t koff = val - text;
      for (size_t e = 0; e < sizeof(exact) / sizeof(exact[0]); e++) {
        if (koff == exact[e])
          printf("exact data+%#" PRIx64 " -> ktext+%#" PRIx64 "\n",
                 off + i, koff);
      }
      if (koff < 0x268000 || koff >= 0x26C000)
        continue;
      mp_ptrs++;
      size_t slot = nunique;
      for (size_t u = 0; u < nunique; u++) {
        if (unique[u] == koff) {
          slot = u;
          break;
        }
      }
      if (slot == nunique) {
        if (nunique == MAX_UNIQUE)
          continue;
        unique[nunique] = koff;
        counts[nunique] = 0;
        first[nunique] = off + i;
        slot = nunique++;
      }
      counts[slot]++;
    }
  }

  for (size_t a = 0; a < nunique; a++) {
    for (size_t b = a + 1; b < nunique; b++) {
      if (unique[b] < unique[a]) {
        uint64_t tu = unique[a], tf = first[a];
        uint32_t tc = counts[a];
        unique[a] = unique[b];
        first[a] = first[b];
        counts[a] = counts[b];
        unique[b] = tu;
        first[b] = tf;
        counts[b] = tc;
      }
    }
  }

  printf("unique MP-band targets %zu (cap %d) mp_ptrs=%" PRIu64 "\n",
         nunique, MAX_UNIQUE, mp_ptrs);
  for (size_t u = 0; u < nunique; u++) {
    printf("mp ktext+%#" PRIx64 " count=%u first=data+%#" PRIx64 "\n",
           unique[u], counts[u], first[u]);
  }
  printf("done scanned_pages=%" PRIu64 " fail=%" PRIu64 "\n", scanned, fail);
  fsync(STDOUT_FILENO);
  return 0;
}
