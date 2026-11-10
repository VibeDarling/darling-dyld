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
