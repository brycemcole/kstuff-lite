# census-1340 — 13.40 kernel-text gadget verification

Firmware 13.400.002 maps kernel text EPT execute-only: every data read faults,
so text cannot be dumped and gadget offsets cannot be taken from a dump. This
suite verifies them instead by *executing* each candidate gadget in kernel
context and reading the trap-flag #DB frame it leaves behind.

- `oracle/` — TF one-instruction oracle (`oracle3`–`oracle5`), the earlier
  `tforacle`/`gadget_verify`/`bounce2` iterations, `timeline` (IDT-writer
  watch), and `recover` (gate/TSS disarm + restore).
- `census/` — IDT/TSS layout census payloads (vector geometry, IST slots,
  mpvec, swapgs) plus `probe`/`text_read` diagnostics.
- `13_40.h` — verified-vs-unproven offsets. Oracle-verified: `ADD_RSP_IRET`
  0x257B36, `DORETI_IRET` 0x257B3D, `NOP_RET` 0x255036, `PIVOT` 0x25213E.
  These confirm the r0gdb-era entries in `prosper0gdb/offsets/13_40.h`
  rebased from the 0xCB0000 kdata delta.
- `census-1340-live.txt` — live-console run log (2026-10-19, CFI-1215A).

Build against the [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk)
(toolchain default can be overridden with `PS5_PAYLOAD_SDK=...`); run the
resulting ELFs via elfldr. Gates are armed on IDT[1]/IDT[179] only; `recover`
restores both on exit.
