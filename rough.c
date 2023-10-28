#include "loader.h"
Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
int fd, i, min_entrypoint;
Elf32_Addr entry_pt = 0;
void *virtual_mem = NULL;
void *loaded_segments = NULL; // Keep track of loaded segments

// Global variables to keep track of page faults and allocations
int page_faults = 0;
int page_allocations = 0;
int internal_fragmentation = 0;

void free_space(){
    free(ehdr);
    free(phdr);
    if (virtual_mem != NULL) {
        free(loaded_segments);
        munmap(virtual_mem, phdr[i].p_memsz);
    }
    close(fd);
}


void handle_page_fault(Elf32_Addr fault_addr) {
    int segment_index = -1;
    for (i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD &&
            fault_addr >= phdr[i].p_vaddr &&
            fault_addr < phdr[i].p_vaddr + phdr[i].p_filesz) {
            segment_index = i;
            break;
        }
    }

    if (segment_index == -1) {
        printf("Invalid page fault address: 0x%08x\n", fault_addr);
        exit(1);
    }

    // Calculate the page start and end addresses for the fault
    Elf32_Addr page_start = phdr[segment_index].p_vaddr + (fault_addr - phdr[segment_index].p_vaddr) / PAGE_SIZE * PAGE_SIZE;
    Elf32_Addr page_end = page_start + PAGE_SIZE;

    // Allocate memory for the entire page
    void *page_ptr = mmap(page_start, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if (page_ptr == MAP_FAILED) {
        printf("Failed to allocate memory for page fault address: 0x%08x\n", fault_addr);
        exit(1);
    }

    // Load the segment content into the allocated memory
    check_offset(lseek(fd, 0, SEEK_SET));
    check_offset(lseek(fd, phdr[segment_index].p_offset, SEEK_SET));
    read(fd, page_ptr, phdr[segment_index].p_filesz);

    // Update the loaded_segments to keep track of allocated pages
    loaded_segments[segment_index] = page_ptr;
    page_allocations++;

    // Handle internal fragmentation
    int internal_frag = PAGE_SIZE - phdr[segment_index].p_filesz;
    if (internal_frag > 0) {
        internal_fragmentation += internal_frag;
    }
}

// Load and execute the ELF executable
void load_and_run_elf(char* exe) {
    open_elf(exe);

    size_t size_of_phdr = sizeof(Elf32_Phdr), size_of_ehdr = sizeof(Elf32_Ehdr);

    load_ehdr(size_of_ehdr);
    load_phdr(size_of_phdr);

    find_entry_pt();

    // Allocate memory for the entry point segment
    virtual_mem = mmap(NULL, phdr[i].p_memsz, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    loaded_segments = calloc(ehdr->e_phnum, sizeof(void*));

    if (virtual_mem == MAP_FAILED) {
        printf("Failed to allocate virtual memory\n");
        exit(1);
    }

    // Calculate the offset between entry point and segment starting address
    Elf32_Addr offset = ehdr->e_entry - entry_pt;
    // Get the actual memory address of the _start function
    void *entry_virtual = virtual_mem + offset;

    // Typecast the address to a function pointer for "_start" method
    int (*_start)() = (int(*)())entry_virtual;

    // Use sigaction to catch page faults and handle them
    struct sigaction sa;
    sa.sa_sigaction = (void (*)(int, siginfo_t *, void *))handle_page_fault;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);

    // Run the program
    int result = _start();

    // Cleanup and display results
    printf("User _start return value = %d\n", result);
    printf("Total Page Faults: %d\n", page_faults);
    printf("Total Page Allocations: %d\n", page_allocations);
    printf("Total Internal Fragmentation (KB): %d\n", internal_fragmentation);

    free_space();
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s <ELF Executable> \n", argv[0]);
        exit(1);
    }

    check_file_read(argv[1]);
    load_and_run_elf(argv[1);

    return 0;
}
