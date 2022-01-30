#include <stdint.h>
#include <stddef.h>

#include "stivale2.h"
#include "util.h"
#include "limits.h"

#define ASCII_0 48
#define ASCII_LOWERCASE_A 97
#define UINT_MAX_LENGTH 10
#define HEX_MAX_LENGTH 8

// Reserve space for the stack
static uint8_t stack[8192];

// Request a terminal from the bootloader
static struct stivale2_header_tag_terminal terminal_hdr_tag = {
	.tag = {
    .identifier = STIVALE2_HEADER_TAG_TERMINAL_ID,
    .next = 0
  },
  .flags = 0
};

// Declare the header for the bootloader
__attribute__((section(".stivale2hdr"), used))
static struct stivale2_header stivale_hdr = {
  // Use ELF file's default entry point
  .entry_point = 0,

  // Use stack (starting at the top)
  .stack = (uintptr_t)stack + sizeof(stack),

  // Bit 1: request pointers in the higher half
  // Bit 2: enable protected memory ranges (specified in PHDR)
  // Bit 3: virtual kernel mappings (no constraints on physical memory)
  // Bit 4: required
  .flags = 0x1E,
  
  // First tag struct
  .tags = (uintptr_t)&terminal_hdr_tag
};

// Find a tag with a given ID
void* find_tag(struct stivale2_struct* hdr, uint64_t id) {
  // Start at the first tag
	struct stivale2_tag* current = (struct stivale2_tag*)hdr->tags;

  // Loop as long as there are more tags to examine
	while (current != NULL) {
    // Does the current tag match?
		if (current->identifier == id) {
			return current;
		}

    // Move to the next tag
		current = (struct stivale2_tag*)current->next;
	}

  // No matching tag found
	return NULL;
}

typedef void (*term_write_t)(const char*, size_t);
term_write_t term_write = NULL;

void term_setup(struct stivale2_struct* hdr) {
  // Look for a terminal tag
  struct stivale2_struct_tag_terminal* tag = find_tag(hdr, STIVALE2_STRUCT_TAG_TERMINAL_ID);

  // Make sure we find a terminal tag
  if (tag == NULL) halt();

  // Save the term_write function pointer
	term_write = (term_write_t)tag->term_write;
}

void kprint_c (char c){
  term_write(&c, 1);
}

void kprint_s(const char* str){
  int size = 0;
  const char* current = str;
  while (*current != '\0')
  {
    size += 1;
    current += 1;
  }
  term_write(str, size);
}

void kprint_d(uint64_t value){
  char val_str [UINT_MAX_LENGTH + 1];
  val_str[UINT_MAX_LENGTH] = '\0';
  int i = UINT_MAX_LENGTH - 1;
  val_str[i] = '0';

  while(value > 0){
    val_str[i] = ASCII_0 + (value % 10);
    value = value / 10;
    i--;
  }
  
  kprint_s(&(val_str[i]));
}

void kprint_x(uint64_t value){
  char val_str [HEX_MAX_LENGTH + 1];
  val_str[HEX_MAX_LENGTH] = '\0';
  int i = HEX_MAX_LENGTH - 1;
  val_str[i] = '0';
  int temp;

  while(value > 0){
    temp = value % 16;

    if (temp <= 9){
      val_str[i] = ASCII_0 + temp;
    }
    else {
      val_str[i] = ASCII_LOWERCASE_A + (temp % 10);
    }
    
    value = value / 16;
    i--;
  }

  kprint_s(&(val_str[i]));
}

void kprint_p(void* ptr){
  kprint_s("0x");
  // uintptr_t prt_val = ptr;
  kprint_x(ptr);
}

void _start(struct stivale2_struct* hdr) {
  // We've booted! Let's start processing tags passed to use from the bootloader
  term_setup(hdr);

  kprint_d(12349);
  kprint_d(16);
  kprint_d(0);
  kprint_d(100);
  kprint_d(12349);
  kprint_c('\n');
  // int a = 10;
  // kprint_p(&a);

	// We're done, just hang...
	halt();
}
