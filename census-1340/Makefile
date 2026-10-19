PS5_PAYLOAD_SDK ?= /tmp/ps5-payload-sdk-v044/ps5-payload-sdk
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
CFLAGS += -Wall -Wextra -Werror -g
ELF := census_1340_idt_tss.elf
vpath %.c oracle census

all: $(ELF)
$(ELF): main.c
	$(CC) $(CFLAGS) -o $@ $<
.PHONY: all

tforacle_bounce.elf: tforacle_1340.c
	$(CC) $(CFLAGS) -o $@ $<
tforacle_valid.elf: tforacle_1340.c
	$(CC) $(CFLAGS) -DSTAGE2 -o $@ $<
tforacle_pivot.elf: tforacle_1340.c
	$(CC) $(CFLAGS) -DSTAGE2 -DCANDIDATE_RVA=0x25213EULL -o $@ $<
idt_census_1340.elf: idt_census_1340.c
	$(CC) $(CFLAGS) -o $@ $<
gadget_verify_1340.elf: gadget_verify_1340.c
	$(CC) $(CFLAGS) -o $@ $<
bounce2_1340.elf: bounce2_1340.c
	$(CC) $(CFLAGS) -o $@ $<
text_read_1340.elf: text_read_1340.c
	$(CC) $(CFLAGS) -o $@ $<
probe_1340.elf: probe_1340.c
	$(CC) $(CFLAGS) -o $@ $<
oracle3_1340.elf: oracle3_1340.c
	$(CC) $(CFLAGS) -o $@ $<
recover_1340.elf: recover_1340.c
	$(CC) $(CFLAGS) -o $@ $<

timeline_1340.elf: timeline_1340.c
	$(CC) $(CFLAGS) -o $@ $<

oracle4_1340.elf: oracle4_1340.c
	$(CC) $(CFLAGS) -o $@ $<

oracle5a_1340.elf: oracle5_1340.c
	$(CC) $(CFLAGS) -DCAND_RVA=0x255036ULL -o $@ $<
oracle5b_1340.elf: oracle5_1340.c
	$(CC) $(CFLAGS) -DCAND_RVA=0x25213EULL -o $@ $<
