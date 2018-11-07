all:
	# craft netcat shellcode
	nasm -felf32 -o netcat.o netcat.asm
	# ld -m elf_i386 -o netcat netcat.o

	# craft decoder
	nasm -felf32 -o decode_sub.o decode_sub.asm

	# encode netcat shellcode
	gcc encode_sub.c -o encode_sub

	# test polymorphic shellcode
	gcc test_polymorphic.c -o test_polymorphic

clean:
	rm -f netcat.o netcat decode_sub.o encode_sub test_polymorphic
