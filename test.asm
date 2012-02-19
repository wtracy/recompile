SECTION .TEXT
	GLOBAL _start 

_start:
	; Terminate program
	mov eax,1            ; 'exit' system call
	mov ebx,0            ; exit with error code 0
	int 80h              ; call the kernel
