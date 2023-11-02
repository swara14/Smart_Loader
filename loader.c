#include "loader.h"
#include <signal.h>
Elf32_Ehdr *ehdr;
Elf32_Phdr *phdr;
int fd , i ,min_entrypoint;
Elf32_Addr entry_pt = 0 ;
void *virtual_mem = NULL;
int no_of_faults = 0;
size_t fragmentation = 0;

size_t roundUpTo4KB(size_t size) {
    size_t pageSize = 4096;
    size_t mask = pageSize - 1;
    return (size + mask) & ~mask;
}

void free_space(){
    free(ehdr);
    free(phdr);
}

void unmapping_virtual_memory(){
    if (virtual_mem != NULL) {
        munmap(virtual_mem, phdr[i].p_memsz);
    }
    close(fd);
}

void check_file_read(const char* exe){
  int fd = open(exe, O_RDONLY);
  if (fd < 0) {
    printf("Error opening ELF file\n");
    exit(1);
  }
}
void check_offset( off_t new_position ){
  if ( new_position == -1 )
  {
    printf("Failed to seek offset\n");
    exit(1);
  }
}

void load_phdr( size_t size_of_phdr ){
  phdr = ( Elf32_Phdr* )malloc( size_of_phdr * ehdr->e_phnum); 
  
  if (phdr == NULL) {
        printf("Failed to allocate memory for program headers.\n");
        exit(1);
  }
  
  check_offset(lseek(fd, 0, SEEK_SET));
  check_offset( lseek(fd , ehdr -> e_phoff , SEEK_SET ) );
  
  if ( read( fd , phdr , size_of_phdr * ehdr -> e_phnum) !=  size_of_phdr * ehdr -> e_phnum)
  {
    printf("Failed to load program headers properly\n");
    exit(1);
  }
  return;
}

void load_ehdr( size_t size_of_ehdr ){
  ehdr = ( Elf32_Ehdr* )malloc(size_of_ehdr);
  
  if (ehdr == NULL) {
        printf("Failed to allocate memory for ELF header.\n");
        exit(1);
  }

  check_offset( lseek(fd, 0, SEEK_SET) ); 
  if (read(fd, ehdr, size_of_ehdr) != size_of_ehdr)
  {
    printf("Failed to load ELF header properly\n");
    exit(1);
  }
  if (ehdr -> e_ident[EI_CLASS] != ELFCLASS32) {
    printf("Not a 32-bit ELF file\n");
    exit(1);
  }
  return;
}

void find_entry_pt(){
  i = 0  ;
  min_entrypoint = 0;
  int min = 0xFFFFFFFF;
  for ( i = 0; i < ehdr -> e_phnum ; i++)
  {
    if ( phdr[i].p_flags == 0x5 || phdr[i].p_flags == 0x6 )
    {
      if (min > ehdr->e_entry - phdr[i].p_vaddr )
      {
        min = ehdr->e_entry - phdr[i].p_vaddr;
        min_entrypoint = i;
      }
    }
  }
  i = min_entrypoint;
  entry_pt = phdr[i].p_vaddr;
}

void Load_memory(){
  virtual_mem = mmap(NULL, phdr[i].p_memsz, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE , 0, 0);  
  
  if (virtual_mem == MAP_FAILED) {
      printf("Failed to allocate virtual memory\n");
      exit(1);
  }
  
  check_offset(lseek(fd, 0, SEEK_SET));
  check_offset( lseek( fd , phdr[i].p_offset ,SEEK_SET ) );

  read(fd , virtual_mem ,phdr[i].p_memsz) ;
}

void open_elf( char* exe ){
  fd = open(exe, O_RDONLY);
  
  if (fd < 0) {
    printf("Failed to open ELF file\n");
    exit(1);
  }
}

void segfault_handler(int signum, siginfo_t *info, void *context) {
  if (signum == SIGSEGV)
  {
    no_of_faults++;
    off_t offset = 0;
    size_t size_to_be_allocated = 0;

    for (int i = 0; i < ehdr -> e_phnum; i++)
    {
      if (phdr[i].p_type == PT_LOAD)
      {
        size_to_be_allocated += phdr[i].p_memsz;
      }
    }

    size_to_be_allocated = roundUpTo4KB(size_to_be_allocated);
    //size_to_be_allocated = size_to_be_allocated * 6;
    printf("size of %d\n", size_to_be_allocated);
    ///size_to_be_allocated = size_to_be_allocated*;
    virtual_mem = mmap( info -> si_addr , size_to_be_allocated , PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE , 0, 0);  

    for (int i = 0; i < ehdr ->e_phnum; i++)
    {
      if (phdr[i].p_type == PT_LOAD){
        check_offset(lseek(fd, 0, SEEK_SET));
        check_offset(lseek(fd, phdr[i].p_offset , SEEK_SET) );
        read(fd, virtual_mem + offset , phdr[i].p_memsz);
        offset += phdr[i].p_offset;
      }
    }
  }
}

void setup_signal_handler(){
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segfault_handler;
    sigaction(SIGSEGV, &sa, NULL);
}
void load_and_run_elf(char* exe) {
  open_elf(exe);

  size_t size_of_phdr = sizeof( Elf32_Phdr ) ,size_of_ehdr = sizeof( Elf32_Ehdr); // size of one program header

  load_ehdr( size_of_ehdr );
  load_phdr( size_of_phdr );

  int (*_start)() = (int(*)())ehdr -> e_entry;
  int result = _start();

  printf("User _start return value = %d\n", result);
  printf("no of faults: %d\n", no_of_faults);
}



int main(int argc, char** argv) 
{
  if(argc != 2) {
    printf("Usage: %s <ELF Executable> \n",argv[0]);
    exit(1);
  }
  setup_signal_handler();
  check_file_read(argv[1]);

  load_and_run_elf(argv[1]);

  free_space();
  unmapping_virtual_memory();

  return 0;
}
