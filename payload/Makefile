all:
	# craft payload shellcode
	nasm -felf32 -o payload.o payload.s
	ld -m elf_i386 -o payload payload.o

	# craft decoder
	nasm -felf32 -o decode_sub.o decode_sub.s

	# encode payload shellcode
	gcc encode_sub.c -o encode_sub

	# test polymorphic shellcode
	gcc test_polymorphic.c -o test_polymorphic

clean:
	rm -f payload.o payload decode_sub.o encode_sub test_polymorphic
