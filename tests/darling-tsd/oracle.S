// Hand-assembled expectations for the instruction encoders of dyld3/DarlingTSDIslands.cpp. The assembler
// derives every word, so the tests do not repeat the encoder's own bit arithmetic.
        .text
        .balign 4
        .globl oracle_mrs_x9
oracle_mrs_x9:      mrs x9, TPIDRRO_EL0
        .globl oracle_mrs_xzr
oracle_mrs_xzr:     mrs xzr, TPIDRRO_EL0
        .globl oracle_lsr_x9
oracle_lsr_x9:      lsr x9, x9, #12
        .globl oracle_mov_x9
oracle_mov_x9:      mov x9, xzr
        .globl oracle_nop
oracle_nop:         nop
        .globl oracle_trap_x9
oracle_trap_x9:     udf #0xda09
        .globl oracle_veneer
oracle_veneer:
        mrs x9, TPIDR_EL0
        ldr x9, [x9, #0x170]
        cbnz x9, 1f
        udf #0xda09
1:      b oracle_return
        .globl oracle_veneer_x30
oracle_veneer_x30:
        mrs x30, TPIDR_EL0
        ldr x30, [x30, #0x7ff8]
        cbnz x30, 1f
        udf #0xda1e
1:      b oracle_return
        .skip 0x1000
        .globl oracle_return
oracle_return:      nop
        .globl oracle_branch_forward
oracle_branch_forward: b oracle_return

// Code that the native test copies into a mapping that stands in for cache text.
        .balign 4
        .globl tsd_code_begin
tsd_code_begin:
        .globl tsd_read
tsd_read:
        .globl tsd_read_site
tsd_read_site:      mrs x0, TPIDRRO_EL0
        ret
// x0 = int[2]: records the Z and C flags that were set before the read
        .globl tsd_flags
tsd_flags:
        mov x1, x0
        cmp x1, x1
        .globl tsd_flags_site
tsd_flags_site:     mrs x0, TPIDRRO_EL0
        cset w2, eq
        cset w3, cs
        stp w2, w3, [x1]
        ret
// x0 = &started (byte), x1 = &stop (word): runs next to the sites until stop is set, returns the iteration count
        .globl tsd_spinner
tsd_spinner:
        mov w2, #1
        strb w2, [x0]
        mov x0, xzr
1:      add x0, x0, #1
        ldr w2, [x1]
        cbz w2, 1b
        ret
        .globl tsd_code_end
tsd_code_end:

// The on-disk image rewrite: inputs and what the assembler says they become (slot offset 0x170).
        .balign 4
        .globl oracle_disk_in
oracle_disk_in:
        mrs x9, TPIDRRO_EL0
        and x9, x9, #0xfffffffffffffff8
        ret
        .globl oracle_disk_out
oracle_disk_out:
        mrs x9, TPIDR_EL0
        ldr x9, [x9, #0x170]
        ret
        .globl oracle_disk_lone_in
oracle_disk_lone_in:
        mrs x9, TPIDRRO_EL0
        ret
        .globl oracle_disk_lone_out
oracle_disk_lone_out:
        mrs x9, TPIDR_EL0
        ret
// mrs into x9 followed by an and on another register, then a 32-bit and, then an mrs as the last word
        .globl oracle_disk_miss_in
oracle_disk_miss_in:
        mrs x9, TPIDRRO_EL0
        and x10, x10, #0xfffffffffffffff8
        mrs x9, TPIDRRO_EL0
        and w9, w9, #0xfffffff8
        mrs x9, TPIDRRO_EL0
        .globl oracle_disk_miss_out
oracle_disk_miss_out:
        mrs x9, TPIDR_EL0
        and x10, x10, #0xfffffffffffffff8
        mrs x9, TPIDR_EL0
        and w9, w9, #0xfffffff8
        mrs x9, TPIDR_EL0
        .globl oracle_disk_end
oracle_disk_end:
