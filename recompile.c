#include <stdlib.h>
#include <stdio.h>
#include <elf.h>

typedef struct {
	Elf32_Addr p_address;
	Elf32_Addr v_address;
	Elf32_Off offset;
	Elf32_Word size;
	void* data;
} program_segment;

typedef struct {
	ssize_t array_size;
	ssize_t data_size;
	program_segment* content;
} program_segment_array;

void dump_program_segment_array(program_segment_array this) {
	ssize_t i; 
	for (i = 0; i < this.data_size; ++i) {
		fprintf(stderr, "LOAD Segment %d:\n", i);
		fprintf(
			stderr, 
			"\tMachine code offset:           0x%08x\n", 
			this.content[i].offset);
		fprintf(
			stderr, 
			"\tMachine code virtual address:  0x%08x\n",
			this.content[i].v_address);
		fprintf(
			stderr, 
			"\tMachine code physical address: 0x%08x\n",
			this.content[i].p_address);
		fprintf(
			stderr, 
			"\tMachine code size:             0x%08x\n",
			this.content[i].size);
	}
}

void init_program_segment_array(program_segment_array* this) {
	this->array_size = 1;
	this->data_size = 0;
	this->content = malloc(sizeof(program_segment));
}

void free_program_segment_array(program_segment_array* this) {
	free(this->content);
}

program_segment* append_program_segment(program_segment_array* this) {
	if (this->array_size <= this->data_size) {
		++(this->array_size);
		this->content = realloc(
				this->content, 
				this->data_size * sizeof(program_segment));
	}
	++(this->data_size);
	return &(this->content[this->data_size - 1]);
}

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

int read_program_header(FILE* input, program_segment_array* segments) {
	Elf32_Phdr program_header;

	do_read(&program_header, sizeof(program_header), input);
	if (program_header.p_type == PT_LOAD) {
		program_segment* segment;
		fprintf(stderr, "Loadable segment.\n");
		fprintf(stderr, "\tSize in file: 0x%x\n", program_header.p_filesz);
		fprintf(stderr, "\tPhysical address: 0x%x\n", program_header.p_paddr);
		fprintf(stderr, "\tVirtual address: 0x%x\n", program_header.p_vaddr);
		segment = append_program_segment(segments);
		segment->size        = program_header.p_filesz;
		segment->v_address   = program_header.p_vaddr;
		segment->p_address   = program_header.p_paddr;
		segment->offset      = program_header.p_offset;
		segment->data        = NULL;
		//dump_program_segment_array(*segments);
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
		fprintf(
			stderr, 
			"Unknown or platform-specific segment type: 0x%x\n", 
			program_header.p_type);
	}

	fprintf(
		stderr, 
		"\tSegment file offset: 0x%08x\n", program_header.p_offset);

	return 0;
}

int parse(FILE* input) {
	Elf32_Ehdr header;
	long int result;
	size_t amount_read = 0;
	int i;
	program_segment_array segment;
	
	result = do_read(&header, sizeof(header), input);

	if (check_header(header) != 0) {
		return -1;
	}
	amount_read = sizeof(header);
	fprintf(stderr, "Program header offset: 0x%08x\n", header.e_phoff);
	fprintf(stderr, "Section header offset: 0x%08x\n", header.e_shoff);
	fprintf(stderr, "Number of headers: %d\n", header.e_phnum);

	init_program_segment_array(&segment);
	for (i = 0; i < header.e_phnum; ++i) {
		read_program_header(input, &segment);
		amount_read += header.e_phentsize;
		fprintf(stderr, "\tloadable segments so far: %d\n", segment.data_size);
	}

	fprintf(stderr, "Current file offset: 0x%04x\n", amount_read);
	dump_program_segment_array(segment);
	
	/*fprintf(stderr, "Machine code offset: 0x%04x\n", code_offset);
	fprintf(stderr, "Machine code size:   0x%04x\n", code_size);*/

	/*result = skip(code_offset - amount_read, input);
	if (result < 0) {
		fprintf(stderr,"Error skipping to code offset.\n");
		return result;
	} 
	result = dump(code_size, input);
	if (result < 0){
		fprintf(stderr, "Error loading code chunk.\n");
	       	return result;
	}*/

	return 0;
}

int main(int argc, char** argv) {
	int result;

	result = parse(stdin);
	if (result != 0)
		fprintf(stderr, "Aborting.\n");
	return result;
}
