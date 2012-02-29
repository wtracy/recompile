recompile: recompile.c
	cc recompile.c -o recompile

test.o: test.asm
	nasm -f elf test.asm

test: test.o
	ld -s -o test test.o

