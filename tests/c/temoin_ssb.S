/* Témoins du détecteur tests/gadget_ssb.py (test_c_gadget_ssb).
 * temoin_ssb_gadget : l'emplacement -0x10(%rbp) reçoit un pointeur, puis une donnée (XOR de deux registres), puis de
 *                     nouveau le pointeur, relu et déréférencé : le motif du 18 novembre 2026 ; doit être signalé.
 * temoin_ssb_sain   : le même calcul, la donnée dans un autre emplacement (-0x18) ; ne doit pas être signalé.
 * uint64_t f(const uint64_t *table, const uint64_t *x, uint64_t k) */
    .text
    .globl temoin_ssb_gadget
    .type temoin_ssb_gadget, @function
temoin_ssb_gadget:
    push %rbp
    mov %rsp, %rbp
    sub $64, %rsp
    mov %rdi, -0x10(%rbp)
    mov (%rsi), %rax
    xor %rdx, %rax
    mov %rax, -0x10(%rbp)
    mov -0x10(%rbp), %rcx
    mov %rdi, -0x10(%rbp)
    mov -0x10(%rbp), %r8
    xor 0x18(%r8), %rcx
    mov %rcx, %rax
    leave
    ret
    .size temoin_ssb_gadget, .-temoin_ssb_gadget

    .globl temoin_ssb_sain
    .type temoin_ssb_sain, @function
temoin_ssb_sain:
    push %rbp
    mov %rsp, %rbp
    sub $64, %rsp
    mov %rdi, -0x10(%rbp)
    mov (%rsi), %rax
    xor %rdx, %rax
    mov %rax, -0x18(%rbp)
    mov -0x18(%rbp), %rcx
    mov %rdi, -0x10(%rbp)
    mov -0x10(%rbp), %r8
    xor 0x18(%r8), %rcx
    mov %rcx, %rax
    leave
    ret
    .size temoin_ssb_sain, .-temoin_ssb_sain
    .section .note.GNU-stack,"",@progbits
