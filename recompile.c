#include <stdlib.h>
#include <stdio.h>
#include <elf.h>

Elf32_Off code_offset;
Elf32_Word code_size;

int check_header(Elf32_Ehdr header) {
	if (header.e_ident[0] == ELFMAG0
		&& header.e_ident[1] == ELFMAG1
		&& header.e_ident[2] == ELFMAG2
		&& header.e_ident[3] == ELFMAG3) {
		// successful match
	} else {
		fprintf(stderr, "Input is not an ELF file.\n");
		return -1;
	}
	if (header.e_type != ET_EXEC) {
		fprintf(stderr, "Input is not an executable file.\n");
		return -1;
	}
	if (header.e_machine != EM_386) {
		fprintf(stderr, "Input is not an x86 file.\n");
		return -1;
	}
	if (header.e_version != EV_CURRENT) {
		fprintf(stderr, "Input is not a known version of the ELF specification.\n");
		return -1;
	}

	return 0;
}

int do_read(void* buffer, ssize_t size, FILE* input) {
	ssize_t result;

	result = fread(buffer, size, 1, input);
	if (result == 1) {
		return 0;
	} else if (feof(input)) {
		fprintf(stderr, "File ends unexpectedly.\n");
		exit(-1);
	} else {
		fprintf(stderr, "Read error: %d\n", ferror(input));
		exit(-1);
	}
	return -1; // should never happen
}

int load_chunk(ssize_t skip_amount, FILE* input, char print) {
	char* temp;

	if (skip_amount < 0){
		return -1;
	}

	temp = malloc(skip_amount);
	do_read(temp, skip_amount, input);

	if (print) {
		ssize_t i;
		for (i = 0; i < skip_amount; ++i) {
			if (i % 8 == 7) {
				printf("0x%02hhx\n", temp[i]);
			} else {
				printf("0x%02hhx ", temp[i]);
			}
		}
		printf("\n");
	}
	free(temp);

	return 0;
}

int skip(ssize_t skip_amount, FILE* input) {
	fprintf(stderr,"Skipping by 0x%x\n", skip_amount);
	return load_chunk(skip_amount, input, 0);
}

int dump(ssize_t dump_amount, FILE* input) {
	fprintf(stderr,"Dumping 0x%x\n", dump_amount);
	return load_chunk(dump_amount, input, 1);
}

int read_program_header(FILE* input) {
	Elf32_Phdr program_header;

	do_read(&program_header, sizeof(program_header), input);
	if (program_header.p_type == PT_LOAD) {
		fprintf(stderr, "Loadable segment.\n");
		/* Yeah, this is hacky. We assume that the location of the
		 * machine code is at the offset given in the last LOAD
		 * segment in the program headers. So, keep a global variable
		 * and update it every time we see another LOAD segment.
		 * I am aware of all the myriad ways in which this could go
		 * wrong. We're still in the proof of concept stage, okay?
		 */
		code_offset = program_header.p_offset;
		code_size = program_header.p_filesz;
	} else if (program_header.p_type == PT_NULL) {
		fprintf(stderr, "Null segment.\n");
	} else if (program_header.p_type == PT_DYNAMIC) {
		fprintf(stderr, "Dynamic segment.\n");
	} else if (program_header.p_type == PT_INTERP) {
		fprintf(stderr, "Interpreter segment.\n");
	} else if (program_header.p_type == PT_NOTE) {
		fprintf(stderr, "Auxiliary information segment.\n");
	} else if (program_header.p_type == PT_SHLIB) {
		fprintf(stderr, "Reserved type segment.\n");
	} else if (program_header.p_type == PT_PHDR) {
		fprintf(stderr, "Header table segment.\n");
	} else {
		fprintf(stderr, "Unknown or platform-specific segment type: 0x%x\n", program_header.p_type);
	}

	fprintf(stderr, "\tSegment file offset: 0x%08x\n", program_header.p_offset);

	return 0;
}

int parse(FILE* input) {
	Elf32_Ehdr header;
	long int result;
	size_t amount_read = 0;
	int i;
	
	result = do_read(&header, sizeof(header), input);

	if (check_header(header) != 0) {
		return -1;
	}
	amount_read = sizeof(header);
	fprintf(stderr, "Program header offset: 0x%08x\n", header.e_phoff);
	fprintf(stderr, "Section header offset: 0x%08x\n", header.e_shoff);
	fprintf(stderr, "Number of headers: %d\n", header.e_phnum);

	for (i = 0; i < header.e_phnum; ++i) {
		read_program_header(input);
		amount_read += header.e_phentsize;
	}

	fprintf(stderr, "Current file offset: 0x%04x\n", amount_read);
	fprintf(stderr, "Machine code offset: 0x%04x\n", code_offset);
	fprintf(stderr, "Machine code size:   0x%04x\n", code_size);

	result = skip(code_offset - amount_read, input);
	if (result < 0) {
		fprintf(stderr,"Error skipping to code offset.\n");
		return result;
	} 
	result = dump(code_size, input);
	if (result < 0){
		fprintf(stderr, "Error loading code chunk.\n");
	       	return result;
	}

	return 0;
}

int main(int argc, char** argv) {
	int result;

	result = parse(stdin);
	if (result != 0)
		fprintf(stderr, "Aborting.\n");
	return result;
}
