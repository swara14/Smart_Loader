<h1>Simple Smart Loader: </h1><h3>An Updated SimpleLoader in C</h3>

<h2>Implementation:</h2>
This ELF loader implementation loads and runs executable programs in the ELF format. It handles page faults within segments by allocating memory for individual pages. When a page fault occurs, it calculates the page number, allocates a single page at a time, and copies the data from the ELF file into the page. This approach ensures that virtual memory for intra-segment space is contiguous, while physical memory may or may not be contiguous. The code also tracks the number of page faults and internal fragmentation. 


<ol>
  1. load_ehdr(size_t size_of_ehdr): 
In this function, memory is allocated to store the ELF header, and the ELF header is read from the file into memory. The function also checks whether the opened file is a 32-bit ELF file. It's a critical step to load the necessary information about the ELF file's structure.


  2. load_phdr(size_t size_of_phdr): 
Similar to load_ehdr, this function allocates memory for program headers and reads them from the file into memory. Program headers contain essential information about various segments in the ELF file, which is needed to load and execute the program.


  3. setup_signal_handler(): 
This function sets up a signal handler, specifically a segmentation fault (SIGSEGV) handler. The signal handler detects and handles page faults (e.g., missing segments) during the program's execution. It efficiently manages page allocation and fault handling.


  4. segfault_handler(int signum, siginfo_t *sig, void *context): 
The segmentation fault handler is the core of this program. When a page fault occurs, it checks which segment the fault belongs to, allocates memory for the missing segment, and continues the program's execution. It keeps track of the number of page faults and the allocation status of each page within a segment, which is crucial for memory efficiency.


<h2>Sources:</h2>
<ul>
  How to use mmap:
  https://man7.org/linux/man-pages/man2/mmap.2.html
  
  How to create a static library:
  https://makori-mildred.medium.com/how-to-create-static-library-in-c-and-how-to-use-it-b8b3e1fde999
  For finding where the fault occurred
  https://www.mkssoftware.com/docs/man5/siginfo_t.5.asp
</ul>
