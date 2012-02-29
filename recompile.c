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
				this->array_size * sizeof(program_segment));
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

int skip(ssize_t skip_amount, FILE* input) {
	char* temp;

	/*if (skip_amount < 0){
		return -1;
	}*/

	//fprintf(stderr, "Allocating %d bytes\n", skip_amount);
	temp = malloc(skip_amount);
	//fprintf(stderr, "Pulling %d bytes\n", skip_amount);
	do_read(temp, skip_amount, input);

	//fprintf(stderr, "Freeing those bytes\n");
	free(temp);

	return 0;
}

int read_program_header(FILE* input, program_segment_array* segments) {
	Elf32_Phdr program_header;

	do_read(&program_header, sizeof(program_header), input);
	if (program_header.p_type == PT_LOAD) {
		program_segment* segment;
		/*fprintf(stderr, "Loadable segment.\n");
		fprintf(stderr, "\tSize in file: 0x%x\n", program_header.p_filesz);
		fprintf(stderr, "\tPhysical address: 0x%x\n", program_header.p_paddr);
		fprintf(stderr, "\tVirtual address: 0x%x\n", program_header.p_vaddr);*/
		segment = append_program_segment(segments);
		segment->size        = program_header.p_filesz;
		segment->v_address   = program_header.p_vaddr;
		segment->p_address   = program_header.p_paddr;
		segment->offset      = program_header.p_offset;
		segment->data        = NULL;
		//dump_program_segment_array(*segments);
	} else if (program_header.p_type == PT_NULL) {
		//fprintf(stderr, "Null segment.\n");
	} else if (program_header.p_type == PT_DYNAMIC) {
		//fprintf(stderr, "Dynamic segment.\n");
	} else if (program_header.p_type == PT_INTERP) {
		//fprintf(stderr, "Interpreter segment.\n");
	} else if (program_header.p_type == PT_NOTE) {
		//fprintf(stderr, "Auxiliary information segment.\n");
	} else if (program_header.p_type == PT_SHLIB) {
		//fprintf(stderr, "Reserved type segment.\n");
	} else if (program_header.p_type == PT_PHDR) {
		//fprintf(stderr, "Header table segment.\n");
	} else {
		fprintf(
			stderr, 
			"Unknown or platform-specific segment type: 0x%x\n", 
			program_header.p_type);
	}

	/*fprintf(
		stderr, 
		"\tSegment file offset: 0x%08x\n", program_header.p_offset);*/

	return 0;
}

int parse(FILE* input) {
	Elf32_Ehdr header;
	long int result;
	size_t amount_read = 0;
	int i;
	program_segment_array segment;
	program_segment_array section;
	
	result = do_read(&header, sizeof(header), input);

	if (check_header(header) != 0) {
		return -1;
	}
	amount_read = sizeof(header);
	fprintf(stderr, "Program header offset: 0x%08x\n", header.e_phoff);
	fprintf(stderr, "Section header offset: 0x%08x\n", header.e_shoff);
	fprintf(stderr, "Section string offset: 0x%08x\n", header.e_shstrndx);
	fprintf(stderr, "Number of headers: %d\n", header.e_phnum);

	/*init_program_segment_array(&section);
	for (i = 0; i < header.e_shnum; ++i) */

	init_program_segment_array(&segment);
	for (i = 0; i < header.e_phnum; ++i) {
		read_program_header(input, &segment);
		amount_read += header.e_phentsize;
		//fprintf(stderr, "\tloadable segments so far: %d\n", segment.data_size);
	}

	/*fprintf(stderr, "Current file offset: 0x%04x\n", amount_read);
	dump_program_segment_array(segment);*/

	for (i = 0; i < segment.data_size; ++i) {
		ssize_t offset = segment.content[i].offset;
		ssize_t size;
		void* ptr;
		if (offset > amount_read){
			ssize_t skip_by = offset - amount_read;
			//fprintf(stderr, "Skipping ahead by %d\n", skip_by);
			result = skip(skip_by, input);
			amount_read = offset;
		} else if (offset < amount_read) {
			/* Trim a bit off of the segment accordingly, since 
			 * we can't be bothered to go back to data we already 
			 * read. :-) */
			ssize_t stripped = amount_read - offset;
			//fprintf(stderr, "Stripping %d off the front of a segment\n", stripped);
			segment.content[i].size      -= stripped;
			segment.content[i].offset    += stripped;
			segment.content[i].v_address += stripped;
			segment.content[i].p_address += stripped;
		} // no compensation needed if we're already at the offset
		size = segment.content[i].size;
		ptr = malloc(size);
		do_read(ptr, size, input);
		segment.content[i].data = ptr;
	}
	//dump_program_segment_array(segment);


	
	for (i = 0; i < segment.data_size; ++i) {
		result = decode_segment(header.e_entry, segment.content[i]);
		if (result < 0)
			return result;
		if (result > 0)
			return 0;
	}

	free_program_segment_array(&segment);

	return 0;
}

int decode_segment(Elf32_Off entry_point, program_segment current) {
	if (entry_point < current.v_address) {
		fprintf(stderr, "Program entry point is illegal.\n");
		fprintf(stderr, "Entry point is 0x%08x but LOAD segment starts at 0x%08x\n", entry_point, current.v_address);
		return -1;
	} else if (entry_point >= current.v_address 
			&& entry_point < current.v_address + current.size) 
	{
		ssize_t i;
		unsigned char* data = current.data;

		//fprintf(stderr, "Found it!\n");
		//printf("0x%x\n", data);
		for (i = entry_point - current.v_address; 
				i < current.size; 
				++i) {
			/*if (i % 8 == 7) {
				printf("0x%02hhx\n", data[i]);
			} else {
				printf("0x%02hhx ", data[i]);
			}*/
			switch (data[i]) {
				/*case 0x04:
					printf("ADD 0x%02hhx 0x%02hhx 0x%02hhx 0x%02hhx\n", data[i+1], data[i+2], data[i+3], data[i+4]);
					i += 4;
					break;*/
				case 0x31:
					printf("XOR (0x%02hhx) 0x%02hhx\n", data[i+0], data[i+1]);
					i += 1;
					break;
				case 0x50:
				case 0x51:
				case 0x52:
				case 0x53:
				case 0x54:
				case 0x55:
				case 0x56:
				case 0x57:
					printf("PUSH (0x%02hhx)\n", data[i]);
					i += 0;
					break;
				case 0x58:
				case 0x59:
				case 0x5A:
				case 0x5B:
				case 0x5C:
				case 0x5D:
				case 0x5E:
				case 0x5F:
					printf("POP (0x%02hhx)\n", data[i]);
					break;
				case 0x68:
					printf("PUSH 0x%02hhx 0x%02hhx 0x%02hhx 0x%02hhx \n", data[i+1], data[i+2], data[i+3], data[i+4]);
					i += 4;
					break;
				case 0x83:
					printf("ADD (0x%02hhx) 0x%02hhx 0x%02hhx \n", data[i+0], data[i+1], data[i+2]);
					i += 2;
					break;
				case 0x89:
					printf("MOV (0x%02hhx) 0x%02hhx\n", data[i], data[i+1]);
					i += 1;
					break;
				case 0x90:
					printf("NOP (0x%02hhx)\n", data[i]);
					break;
				case 0xB8: 
				case 0xB9: 
				case 0xBA: 
				case 0xBB: 
				case 0xBC: 
				case 0xBD: 
				case 0xBE: 
				case 0xBF: 
					printf("MOV 0x%02hhx 0x%02hhx 0x%02hhx 0x%02hhx\n", data[i+1], data[i+2], data[i+3], data[i+4]);
					i += 4;
					break;
				case 0xCD: 
					printf("INIT 0x%02hhx \n", data[i+1]);
					i += 1;
					break;
				case 0xE8:
					printf("CALL (0x%02hhx) 0x%02hhx 0x%02hhx 0x%02hhx 0x%02hhx\n", data[i], data[i+1], data[i+2], data[i+3], data[i+4]);
					i += 4;
					break;
				case 0xF4:
					printf("HALT (0x%02hxx)\n", data[i]);
					break;
				default:
					printf("Mystery opcode 0x%02hhx\n", data[i]);
			}
		}
		printf("\n");

		return 1;
	} else {
		//fprintf(stderr, "Is it in the range 0x%08x--0x%08x?\n", current.v_address
		fprintf(stderr, "Nope, still looking.\n");
		return 0;
	}
}

int main(int argc, char** argv) {
	int result;

	result = parse(stdin);
	if (result != 0)
		fprintf(stderr, "Aborting.\n");
	return result;
}
