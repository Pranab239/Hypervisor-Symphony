#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>

/* My code */
#define MIN_VALID_HVA 0x10000000
#define MAX_VALID_HVA 0xFFFFFFFF

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

/* CR4 bits */
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 8)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)

#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

/* 32-bit page directory entry bits */
#define PDE32_PRESENT 1
#define PDE32_RW (1U << 1)
#define PDE32_USER (1U << 2)
#define PDE32_PS (1U << 7)

/* 64-bit page * entry bits */
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)


struct vm {
	int dev_fd;
	int vm_fd;
	char *mem;
};

struct vcpu {
	int vcpu_fd;
	struct kvm_run *kvm_run;
};

// Function to initialize the virtual machine
void vm_init(struct vm *vm, size_t mem_size)
{
	int kvm_version;
	struct kvm_userspace_memory_region memreg;

	// open fd for the kvm. ioctls on fds to talk to kvm
	// file descriptors: dev_fd is associated with the /dev/kvm device file
	vm->dev_fd = open("/dev/kvm", O_RDWR);
	if (vm->dev_fd < 0) {
		perror("open /dev/kvm");
		exit(1);
	}

	// QEMU communicates with the kvm using ioctl system calls
	// This ioctl call return the kvm api's version
	kvm_version = ioctl(vm->dev_fd, KVM_GET_API_VERSION, 0);
	if (kvm_version < 0) {
		perror("KVM_GET_API_VERSION");
		exit(1);
	}

	if (kvm_version != KVM_API_VERSION) {
		fprintf(stderr, "Got KVM api version %d, expected %d\n", kvm_version, KVM_API_VERSION);
		exit(1);
	}

	// When creating a VM using KVM_CREATE_VM, the kernel allocates resources and creates an internal data structure 
	// to represent the VM. The file descriptor (vm_fd) serves as a handle or identifier for this specific VM, 
	// allowing subsequent interactions and operations on the VM through the KVM API.
	vm->vm_fd = ioctl(vm->dev_fd, KVM_CREATE_VM, 0);
	if (vm->vm_fd < 0) {
		perror("KVM_CREATE_VM");
		exit(1);
	}

	// configuring the virtual machine represented by the file descriptor vm->vm_fd 
	// to use the specified address (0xfffbd000) for its Task State Segment.
	// The Task State Segment (TSS) is a data structure in the x86 architecture that is used to store 
	// information about a task during a task switch.
	if (ioctl(vm->vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
		perror("KVM_SET_TSS_ADDR");
		exit(1);
	}

	// Allocates memory for guest VM physical memory and returns the starting address of the mapped region on success
	// on failure returns MAP_FAILED which is typically (void*) -1.
	vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (vm->mem == MAP_FAILED) {
		perror("mmap mem");
		exit(1);
	}

	// suggests the kernel if the memeory range is suitable for merging
	madvise(vm->mem, mem_size, MADV_MERGEABLE);

	// Initializing the kernel memeory region
	memreg.slot = 0;
	memreg.flags = 0;
	memreg.guest_phys_addr = 0;
	memreg.memory_size = mem_size;
	memreg.userspace_addr = (unsigned long)vm->mem;

	// The `ioctl` call with `KVM_SET_USER_MEMORY_REGION` sets the configuration
	// for a specific memory region associated with a KVM virtual machine.
	if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
		exit(1);
	}
}


// Function to initialize the virtual cpu
void vcpu_init(struct vm *vm, struct vcpu *vcpu)
{
	int vcpu_mmap_size;

	// fd for kvm virtual cpu. create virtual cpu for the virtual machine
	vcpu->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
	if (vcpu->vcpu_fd < 0) {
		perror("KVM_CREATE_VCPU");
		exit(1);
	}

	// how much memory to map in the user space for kvm_run
	vcpu_mmap_size = ioctl(vm->dev_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (vcpu_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
		exit(1);
	}

	// maps a region of the process's address space to the control structure (kvm_run) of a virtual CPU (vcpu) 
	// in a KVM virtual machine. This allows user space to access and control the vCPU's state during 
	// virtual machine execution.
	vcpu->kvm_run = mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu->vcpu_fd, 0);
	if (vcpu->kvm_run == MAP_FAILED) {
		perror("mmap kvm_run");
		exit(1);
	}
}

int run_vm(struct vm *vm, struct vcpu *vcpu, size_t sz)
{
	struct kvm_regs regs;
	uint64_t memval = 0;
	uint32_t number_of_exits = 0;
	uint32_t number_of_in_exits = 0;
	uint32_t gpa = 0;
	uint32_t host_virtual_addr = 0;

	for (;;) {
		if (ioctl(vcpu->vcpu_fd, KVM_RUN, 0) < 0) {
			perror("KVM_RUN");
			exit(1);
		}

		switch (vcpu->kvm_run->exit_reason) {
			case KVM_EXIT_HLT:
				goto check;

			case KVM_EXIT_IO:

				// printf("Total io exits: %d\n", number_of_exits);
				// printf("Total number of in exits: %d\n", number_of_in_exits);

				number_of_exits++;

				// printing the 8-bit data
				if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT && vcpu->kvm_run->io.port == 0xE9) {
					char *p = (char *)vcpu->kvm_run;
					fwrite(p + vcpu->kvm_run->io.data_offset, vcpu->kvm_run->io.size, 1, stdout);
					fflush(stdout);
					// continue;
				}

				// Print 32 bit data
				if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT && vcpu->kvm_run->io.port == 0xEB) {
					fprintf(stdout, "%u\n", *((uint32_t *)((char *)vcpu->kvm_run + vcpu->kvm_run->io.data_offset)));
					fflush(stdout);
					// continue;
				}

				// Print string from address
				if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT && vcpu->kvm_run->io.port == 0xEA) {
					printf("%s", (char *)vm->mem + *((uint32_t *)((char *)vcpu->kvm_run + vcpu->kvm_run->io.data_offset)));
					fflush(stdout);
					// continue;
				}

				// Calculate the number of io_exits
				if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_IN && vcpu->kvm_run->io.port == 0xEC) {
					*((uint32_t *)((char *)vcpu->kvm_run + vcpu->kvm_run->io.data_offset)) = number_of_exits;
					number_of_in_exits++;
					// continue;
				}

				// Calculate the number of io_in and io_exits
				if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_IN && vcpu->kvm_run->io.port == 0xED) {
					number_of_in_exits++;
					char buffer[25];
					snprintf(buffer, 25, "IO in: %d\nIO out: %d\n", number_of_in_exits, number_of_exits - number_of_in_exits);
					char *guest_address = (char *)vm->mem + *((uint32_t *)((char *)vcpu->kvm_run + vcpu->kvm_run->io.data_offset));
					strncpy(guest_address, buffer, 25);
					// continue;
				}

				// Translate the guest virtual address to the host physical address
				if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT && vcpu->kvm_run->io.port == 0xEE) {
					uint32_t gva = *((uint32_t *)((char *)vcpu->kvm_run + vcpu->kvm_run->io.data_offset));

					struct kvm_translation tr = {
						.linear_address = gva,
					};

					// Translate the guest virtual address to the guest physcial address
					ioctl(vcpu->vcpu_fd, KVM_TRANSLATE, &tr);

					// checking if the translattion is valid or not
					if(!tr.valid) {
						printf("Invalid GVA\n");
						host_virtual_addr = 0;
						continue;
					}
					else {

						// tr.physical_address holds the translated guest physical address
						gpa = (uint32_t)tr.physical_address;

						// Logic to convert gpa to hva
						void *hva = vm->mem + gpa;
						host_virtual_addr = (uint32_t)(uintptr_t)hva;
						// printf("Host Virtual Address: %x\n", host_virtual_addr);
					}
					// continue;
				}

				// return a value to the guest vm
				if (vcpu->kvm_run->io.direction == KVM_EXIT_IO_IN && vcpu->kvm_run->io.port == 0xEF) {
					*((uint32_t *)((char *)vcpu->kvm_run + vcpu->kvm_run->io.data_offset)) = host_virtual_addr;
					fflush(stdout);
					number_of_in_exits++;
					// continue;
				}

				// printf("\nTotal io exits: %d\n", number_of_exits);
				// printf("\nTotal number of in exits: %d\n", number_of_in_exits);
				continue;

				/* fall through */
			default:
				fprintf(stderr,	"Got exit_reason %d,"" expected KVM_EXIT_HLT (%d)\n", vcpu->kvm_run->exit_reason, KVM_EXIT_HLT);
				exit(1);
		}
	}

	check:
		if (ioctl(vcpu->vcpu_fd, KVM_GET_REGS, &regs) < 0) {
			perror("KVM_GET_REGS");
			exit(1);
		}

		if (regs.rax != 42) {
			printf("Wrong result: {E,R,}AX is %lld\n", regs.rax);
			return 0;
		}

		memcpy(&memval, &vm->mem[0x400], sz);
		if (memval != 42) {
			printf("Wrong result: memory at 0x400 is %lld\n",
				(unsigned long long)memval);
			return 0;
		}
	return 1;
}

extern const unsigned char guest16[], guest16_end[];

int run_real_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing real mode\n");

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	sregs.cs.selector = 0;
	sregs.cs.base = 0;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest16, guest16_end-guest16);
	return run_vm(vm, vcpu, 2);
}

static void setup_protected_mode(struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.present = 1,
		.type = 11, /* Code: execute, read, accessed */
		.dpl = 0,
		.db = 1,
		.s = 1, /* Code/data */
		.l = 0,
		.g = 1, /* 4KB granularity */
	};

	sregs->cr0 |= CR0_PE; /* enter protected mode */

	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

extern const unsigned char guest32[], guest32_end[];

int run_protected_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing protected mode\n");

        if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_protected_mode(&sregs);

        if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest32, guest32_end-guest32);
	return run_vm(vm, vcpu, 4);
}

static void setup_paged_32bit_mode(struct vm *vm, struct kvm_sregs *sregs)
{
	uint32_t pd_addr = 0x2000;
	uint32_t *pd = (void *)(vm->mem + pd_addr);

	/* A single 4MB page to cover the memory region */
	pd[0] = PDE32_PRESENT | PDE32_RW | PDE32_USER | PDE32_PS;
	/* Other PDEs are left zeroed, meaning not present. */

	sregs->cr3 = pd_addr;
	sregs->cr4 = CR4_PSE;
	sregs->cr0
		= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs->efer = 0;
}

int run_paged_32bit_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing 32-bit paging\n");

        if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_protected_mode(&sregs);
	setup_paged_32bit_mode(vm, &sregs);

        if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest32, guest32_end-guest32);
	return run_vm(vm, vcpu, 4);
}

extern const unsigned char guest64[], guest64_end[];

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.present = 1,
		.type = 11, /* Code: execute, read, accessed */
		.dpl = 0,
		.db = 0,
		.s = 1, /* Code/data */
		.l = 1,
		.g = 1, /* 4KB granularity */
	};

	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs)
{
	uint64_t pml4_addr = 0x2000;
	uint64_t *pml4 = (void *)(vm->mem + pml4_addr);

	uint64_t pdpt_addr = 0x3000;
	uint64_t *pdpt = (void *)(vm->mem + pdpt_addr);

	uint64_t pd_addr = 0x4000;
	uint64_t *pd = (void *)(vm->mem + pd_addr);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
	pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;

	sregs->cr3 = pml4_addr;
	sregs->cr4 = CR4_PAE;
	sregs->cr0
		= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs->efer = EFER_LME | EFER_LMA;

	setup_64bit_code_segment(sregs);
}

int run_long_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing 64-bit mode\n");

        if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_long_mode(vm, &sregs);

        if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest64, guest64_end-guest64);
	return run_vm(vm, vcpu, 8);
}


int main(int argc, char **argv)
{
	struct vm vm;
	struct vcpu vcpu;
	enum {
		REAL_MODE,
		PROTECTED_MODE,
		PAGED_32BIT_MODE,
		LONG_MODE,
	} mode = REAL_MODE;
	int opt;

	while ((opt = getopt(argc, argv, "rspl")) != -1) {
		switch (opt) {
		case 'r':
			mode = REAL_MODE;
			break;

		case 's':
			mode = PROTECTED_MODE;
			break;

		case 'p':
			mode = PAGED_32BIT_MODE;
			break;

		case 'l':
			mode = LONG_MODE;
			break;

		default:
			fprintf(stderr, "Usage: %s [ -r | -s | -p | -l ]\n",
				argv[0]);
			return 1;
		}
	}

	vm_init(&vm, 0x200000);
	vcpu_init(&vm, &vcpu);

	switch (mode) {
	case REAL_MODE:
		return !run_real_mode(&vm, &vcpu);

	case PROTECTED_MODE:
		return !run_protected_mode(&vm, &vcpu);

	case PAGED_32BIT_MODE:
		return !run_paged_32bit_mode(&vm, &vcpu);

	case LONG_MODE:
		return !run_long_mode(&vm, &vcpu);
	}

	return 1;
}
