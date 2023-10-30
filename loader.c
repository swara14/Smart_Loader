#include "loader.h"
#include <signal.h>
Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
int fd, i, min_entrypoint;
Elf32_Addr entry_pt = 0;
void *virtual_mem = NULL;
size_t PAGE_SIZE = 4096;
void *entry_virtual;
Elf32_Addr offset;

void check_offset(off_t new_position)
{
	if (new_position == -1)
	{
		printf("Failed to seek offset\n");
		exit(1);
	}
}

size_t roundUpTo4KB(size_t size) {
    size_t pageSize = 4096;
    size_t mask = pageSize - 1;
    return (size + mask) & ~mask;
}

void Load_memory(){
	size_t rounded_up_size = roundUpTo4KB(phdr[i].p_memsz);
	size_t fragmentation = rounded_up_size - phdr[i].p_memsz;
	printf("fragmentation is %d\n", fragmentation);
	virtual_mem = mmap(NULL ,rounded_up_size , PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

	if (virtual_mem == MAP_FAILED)
	{
		printf("Failed to allocate virtual memory\n");
		exit(1);
	}

	check_offset(lseek(fd, 0, SEEK_SET));
	check_offset(lseek(fd, phdr[i].p_offset, SEEK_SET));

	read(fd, virtual_mem, phdr[i].p_memsz);
}

void free_space()
{
	free(ehdr);
	free(phdr);
}

void unmapping_virtual_memory()
{
	if (virtual_mem != NULL)
	{
		munmap(virtual_mem, phdr[i].p_memsz);
	}
	close(fd);
}

void check_file_read(const char *exe)
{
	int fd = open(exe, O_RDONLY);
	if (fd < 0)
	{
		printf("Error opening ELF file\n");
		exit(1);
	}
}

void load_phdr(size_t size_of_phdr)
{
	phdr = (Elf32_Phdr *)malloc(size_of_phdr * ehdr->e_phnum);

	if (phdr == NULL)
	{
		printf("Failed to allocate memory for program headers.\n");
		exit(1);
	}

	check_offset(lseek(fd, 0, SEEK_SET));
	check_offset(lseek(fd, ehdr->e_phoff, SEEK_SET));

	// Read program headers into memory
	if (read(fd, phdr, size_of_phdr * ehdr->e_phnum) != size_of_phdr * ehdr->e_phnum)
	{
		printf("Failed to load program headers properly\n");
		exit(1);
	}
	return;
}

void load_ehdr(size_t size_of_ehdr)
{
	ehdr = (Elf32_Ehdr *)malloc(size_of_ehdr);

	if (ehdr == NULL)
	{
		printf("Failed to allocate memory for ELF header.\n");
		exit(1);
	}

	check_offset(lseek(fd, 0, SEEK_SET));
	// Read ELF header into memory
	if (read(fd, ehdr, size_of_ehdr) != size_of_ehdr)
	{
		printf("Failed to load ELF header properly\n");
		exit(1);
	}
	// Check if the ELF file is 32-bit
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32)
	{
		printf("Not a 32-bit ELF file\n");
		exit(1);
	}
	return;
}

void find_entry_pt()
{
	i = 0;
	min_entrypoint = 0;
	int min = 0xFFFFFFFF;
	for (i = 0; i < ehdr->e_phnum; i++)
	{
		if (phdr[i].p_flags == 0x5)
		{
			if (min > ehdr->e_entry - phdr[i].p_vaddr)
			{
				min = ehdr->e_entry - phdr[i].p_vaddr;
				min_entrypoint = i;
			}
		}
	}
	i = min_entrypoint;
	entry_pt = phdr[i].p_vaddr;
}

void open_elf(char *exe)
{
	fd = open(exe, O_RDONLY);

	if (fd < 0)
	{
		printf("Failed to open ELF file\n");
		exit(1);
	}
}

void load_and_run_elf(char *exe)
{
	open_elf(exe);

	size_t size_of_phdr = sizeof(Elf32_Phdr), size_of_ehdr = sizeof(Elf32_Ehdr); // size of one program header

	load_ehdr(size_of_ehdr);
	load_phdr(size_of_phdr);

	find_entry_pt();

	// Load_memory();
	Elf32_Addr total_memsz = phdr[i].p_memsz;
	Elf32_Addr offset = ehdr->e_entry - entry_pt;

	offset = ehdr->e_entry - entry_pt;
	entry_virtual = virtual_mem + offset;
	int (*_start)() = (int (*)())entry_virtual;
	int result = _start();
	printf("User _start return value = %d\n", result);
}

int segfault_occured=0;
void signal_handler(int signum)
{
	if (signum == SIGSEGV){
		// if(segfault_occured){
		// 	exit(0);
		// }
		printf("GOT SIGSEV\n");
		Load_memory();

		Elf32_Addr offset = ehdr->e_entry - entry_pt;
		entry_virtual = virtual_mem + offset;
		int (*_start)() = (int (*)())entry_virtual;
		int result = _start();
		printf("User _start return value = %d\n", result);
		//segfault_occured++;
		// struct sigaction sh_sev;
        // memset(&sh_sev, 0, sizeof(sh_sev));
        // sh_sev.sa_handler = SIG_DFL;
        // sigaction(SIGSEGV, &sh_sev, NULL);
		free_space();
		unmapping_virtual_memory();
		return;
	}
}

void setup_signal_handler()
{
	struct sigaction sh_sev;
	memset(&sh_sev, 0, sizeof(sh_sev));
	sh_sev.sa_handler = signal_handler;
	if (sigaction(SIGSEGV, &sh_sev, NULL) == -1)
	{
		printf("Error in handling SIGSEV\n");
	}
	memset(&sh_sev, 0, sizeof(sh_sev));
}


int main(int argc, char **argv)
{
	if (argc != 2)
	{
		printf("Usage: %s <ELF Executable> \n", argv[0]);
		exit(1);
	}
	setup_signal_handler();
	// 1. Check the ELF file can be read
	check_file_read(argv[1]);

	// 2. Load and execute the ELF executable
	load_and_run_elf(argv[1]);

	// 3. Perform cleanup
	

	return 0;
}
