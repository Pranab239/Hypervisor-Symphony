#include <stddef.h>
#include <stdint.h>

int flag = 0;
// Function to wrtie a 8-bit value to the specific I/O port
static void outb(uint16_t port, uint8_t value) {
	asm("outb %0, %1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

// Function to wrtie a 32-bit value to the specific I/O port
static void outl(uint16_t port, uint32_t value) {
	asm ("outl %0, %1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

// Function to read a 32-bit value from the specific I/O port
static inline uint32_t in(uint16_t port) {
	uint32_t return_value;
	asm("in %1, %0" : "=a"(return_value) : "Nd"(port) : "memory" );
	return return_value;
}

void HC_print8bit(uint8_t val)
{
	outb(0xE9, val);
}

void HC_print32bit(uint32_t val)
{
	outl(0xEB, val);
}

uint32_t HC_numExits()
{
	uint32_t number_of_exits = in(0xEC);
	return number_of_exits;
}

void HC_printStr(char *str)
{
	outl(0xEA, (uintptr_t)str);
}

char *HC_numExitsByType()
{

    // Use static variables to store addresses
    static char buffer1[25];
    static char buffer2[25];

	// taking the address from the hypervisor
    char *number_of_exits = (char*)(uintptr_t)in(0xED);

	char* address;

	if(flag == 0) {
		address = buffer1;
	}
	else {
		address = buffer2;
	}

	// copying the string from the address
	int i = 0;
	while(number_of_exits[i] != '\0') {
		address[i] = number_of_exits[i];
		i++;
	}

	if(flag == 0) {
		flag = 1;
	}
	else {
		flag = 0;
	}

	return address;
}

// Function to read a specific 32-bit value from specific I/O port
uint32_t getHva(uint16_t port) 
{
	uint32_t hva = in(port);
	return hva;
}

uint32_t HC_gvaToHva(uint32_t gva)
{
	outl(0xEE, gva);
	return getHva(0xEF);
}

void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {
	const char *p;

	for (p = "Hello 695!\n"; *p; ++p)
		HC_print8bit(*p);


	/*----------Don't modify this section. We will use grading script---------*/
	/*---Your submission will fail the testcases if you modify this section---*/
	HC_print32bit(2048);
	HC_print32bit(4294967295);

	uint32_t num_exits_a, num_exits_b;
	num_exits_a = HC_numExits();

	char *str = "CS695 Assignment 2\n";
	HC_printStr(str);

	num_exits_b = HC_numExits();

	HC_print32bit(num_exits_a);
	HC_print32bit(num_exits_b);

	char *firststr = HC_numExitsByType();
	uint32_t hva;
	hva = HC_gvaToHva(1024);
	HC_print32bit(hva);
	hva = HC_gvaToHva(4294967295);
	HC_print32bit(hva);
	char *secondstr = HC_numExitsByType();

	HC_printStr(firststr);
	HC_printStr(secondstr);
	/*------------------------------------------------------------------------*/

	*(long *) 0x400 = 42;

	for (;;)
		asm("hlt" : /* empty */ : "a" (42) : "memory");
}
