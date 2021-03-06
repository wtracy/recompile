#include <stdlib.h>
#include <stdio.h>
#include <elf.h>

typedef struct {
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

typedef struct {
	Elf32_Word name;
	Elf32_Addr address;
	Elf32_Word size;
} program_section;

typedef struct {
	ssize_t array_size;
	ssize_t data_size;
	program_section* content;
} program_section_array;

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
			"\tMachine code size:             0x%08x\n",
			this.content[i].size);
	}
}

void init_program_segment_array(program_segment_array* this) {
	this->array_size = 1;
	this->data_size = 0;
	this->content = malloc(sizeof(program_segment));
}

void init_program_section_array(program_section_array* this) {
	this->array_size = 1;
	this->data_size = 0;
	this->content = malloc(sizeof(program_section));
}

void free_program_segment_array(program_segment_array* this) {
	free(this->content);
}

void free_program_section_array(program_section_array* this) {
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

program_section* append_program_section(program_section_array* this) {
	if (this->array_size <= this->data_size) {
		++(this->array_size);
		this->content = realloc(
				this->content, 
				this->array_size * sizeof(program_section));
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
		fprintf(stderr, "Unknown ELF format.\n");
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
		fprintf(stderr, "fread returned %d\n", result);
		fprintf(stderr, "Read error: %d\n", ferror(input));
		exit(-1);
	}
	return -1; // should never happen
}

int read_program_header(
		FILE* input, program_segment_array* segments) {
	Elf32_Phdr program_header;

	do_read(&program_header, sizeof(program_header), input);
	if (program_header.p_type == PT_LOAD) {
		program_segment* segment;
		segment = append_program_segment(segments);
		segment->size        = program_header.p_filesz;
		segment->v_address   = program_header.p_vaddr;
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

	return 0;
}

int parse(FILE* input) {
	Elf32_Ehdr header;
	long int result;
	size_t amount_read = 0;
	int i;
	program_segment_array segment;
	program_section_array section;
	fpos_t pos;
	char* strings = NULL;
	size_t strings_size = 0;
	Elf32_Off strings_offset = 0;
	
	result = do_read(&header, sizeof(header), input);

	if (check_header(header) != 0) {
		return -1;
	}
	amount_read = sizeof(header);
	fprintf(stderr, "Current file offset: 0x%08x\n", amount_read);
	fprintf(stderr, "Program header offset: 0x%08x\n", header.e_phoff);
	fprintf(stderr, "Section header offset: 0x%08x\n", header.e_shoff);
	fprintf(stderr, "Section string offset: 0x%08x\n", header.e_shstrndx);
	fprintf(stderr, "Number of headers: %d\n", header.e_phnum);
	fprintf(stderr, "Number of section headers: %d\n", header.e_shnum);

	init_program_segment_array(&segment);
	for (i = 0; i < header.e_phnum; ++i) {
		read_program_header(input, &segment);
		amount_read += header.e_phentsize;
	}

	fprintf(stderr, "Current file offset: 0x%08x\n", amount_read);
	/*dump_program_segment_array(segment);*/

	for (i = 0; i < segment.data_size; ++i) {
		ssize_t offset = segment.content[i].offset;
		ssize_t size;
		void* ptr;

		fprintf(stderr, "Current file offset: 0x%08x\n", amount_read);
		if (offset > amount_read){
			result = fseek(input, offset, SEEK_SET);
			amount_read = offset;
			if (result != 0) {
				fprintf(stderr, "Fail finding segment.\n");
				exit(-1);
			}
		} else if (offset < amount_read) {
			/* Trim a bit off of the segment accordingly, since 
			 * we can't be bothered to go back to data we already 
			 * read. ;-) */
			ssize_t stripped = amount_read - offset;

			segment.content[i].size      -= stripped;
			segment.content[i].offset    += stripped;
			segment.content[i].v_address += stripped;
		} // no compensation needed if we're already at the offset
		fprintf(
				stderr, 
				"Reading segment at file offset: 0x%08x\n", 
				amount_read);
		size = segment.content[i].size;
		ptr = malloc(size);
		result = do_read(ptr, size, input);
		amount_read += size;
		segment.content[i].data = ptr;
		if (result != 0) {
			fprintf(stderr, "Failure reading segment!\n");
			exit(-1);
		}
		fprintf(
				stderr, 
				"File offset at end of segment: 0x%08x\n", 
				amount_read);
	}
	result = fseek(input, header.e_shoff, SEEK_SET);
	amount_read = header.e_shoff;
	if (result != 0) {
		fprintf(stderr, "Failure finding section header offset!\n");
		exit(-1);
	}
	fprintf(stderr, "Current file offset: 0x%08x\n", amount_read);

	for (i = 0; i < header.e_shnum; ++i) {
		Elf32_Shdr section_header;

		do_read(&section_header, sizeof(section_header), input);
		if (section_header.sh_type == SHT_STRTAB) {
			strings_offset = section_header.sh_offset;
			strings_size = section_header.sh_size;
		}
		amount_read += header.e_shentsize;
		fprintf(stderr, "Current file offset: 0x%08x\n", amount_read);
	}


	result = fseek(input, strings_offset, SEEK_SET);
	amount_read = strings_offset;
	if (result != 0) {
		fprintf(stderr, "Fail finding section.\n");
		exit(-1);
	}
	fprintf(
			stderr, 
			"Reading text at offset 0x%08x and size 0x%08x\n", 
			amount_read, 
			strings_size);
	
	strings = malloc(strings_size);
	result = do_read(strings, strings_size, input);
	if (result != 0) {
		fprintf(stderr, "Fail reading section.\n");
		exit(-1);
	} 
	amount_read += strings_size;
	fprintf(stderr, "Dumping strings!\n");
	for (i = 0; i < strings_size; ++i) {
		char c = strings[i];
		if(c == 0)
			fputc('\n', stderr);
		else
			fputc(c, stderr);
	}
	fprintf(stderr, "Done dumping strings!\n");
	fprintf(stderr, "Read section headers, done reading sections\n");


	/*for (i = 0; i < segment.data_size; ++i) {
		result = decode_segment(header.e_entry, segment.content[i]);
		if (result < 0)
			return result;
		if (result > 0)
			return 0;
	}*/

	free_program_segment_array(&segment);
	free(strings);

	return 0;
}

int decode_segment(Elf32_Off entry_point, program_segment current) {
	if (entry_point < current.v_address) {
		fprintf(stderr, "Illegal entry point. ");
		fprintf(
				stderr, 
				"Entry point is 0x%08x ",
				entry_point);
		fprintf(
				stderr,
				"but LOAD segment starts at 0x%08x.\n", 
				current.v_address);
		return -1;
	} else if (entry_point >= current.v_address 
			&& entry_point < current.v_address + current.size) 
	{
		ssize_t i;
		unsigned char* data = current.data;

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
