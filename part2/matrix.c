#include <stdio.h>
#include <sys/mman.h>
#include <pthread.h>
#include <linux/kvm.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <time.h>

#include <stddef.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>

#define _GNU_SOURCE
#include <unistd.h>

#define KVM_DEVICE "/dev/kvm"
#define RAM_SIZE 512000000
#define CODE_START 0x1000
#define BINARY_FILE1 "guest1-b.bin"
#define BINARY_FILE2 "guest2-b.bin"
#define CURRENT_TIME ((double)clock() / CLOCKS_PER_SEC)
#define TIMER_INTERVAL_SEC 2
#define QUANTUM 1
#define FRAC_A 10
#define FRAC_B 0

struct vm
{
    int dev_fd;
    int kvm_version;
    int vm_fd;
    struct kvm_userspace_memory_region mem;
    struct vcpu *vcpus;
    __u64 ram_size;
    __u64 ram_start;
    int vcpu_number;
};

struct vcpu
{
    int vcpu_id;
    int vcpu_fd;
    pthread_t vcpu_thread;
    struct kvm_run *kvm_run;
    int kvm_run_mmap_size;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    void *(*vcpu_thread_func)(void *);
};

timer_t timerid;

void kvm_init(struct vm *vm1, struct vm *vm2)
{
    int dev_fd = open(KVM_DEVICE, O_RDWR);

    if (dev_fd < 0)
    {
        perror("open /dev/kvm");
        exit(1);
    }

    int kvm_version = ioctl(dev_fd, KVM_GET_API_VERSION, 0);

    if (kvm_version < 0)
    {
        perror("KVM_GET_API_VERSION");
        exit(1);
    }

    if (kvm_version != KVM_API_VERSION)
    {
        fprintf(stderr, "Got KVM api version %d, expected %d\n", kvm_version, KVM_API_VERSION);
        exit(1);
    }

    vm1->dev_fd = dev_fd;
    vm2->dev_fd = dev_fd;
    vm1->kvm_version = kvm_version;
    vm2->kvm_version = kvm_version;
}

int kvm_create_vm(struct vm *vm, int ram_size)
{
    int ret = 0;
    vm->vm_fd = ioctl(vm->dev_fd, KVM_CREATE_VM, 0);

    if (vm->vm_fd < 0)
    {
        perror("can not create vm");
        return -1;
    }

    vm->ram_size = ram_size;

    // return the start address of the allocated memory space
    vm->ram_start = (__u64)mmap(NULL, vm->ram_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

    if ((void *)vm->ram_start == MAP_FAILED)
    {
        perror("can not mmap ram");
        return -1;
    }

    vm->mem.slot = 0;
    vm->mem.guest_phys_addr = 0;
    vm->mem.memory_size = vm->ram_size;
    vm->mem.userspace_addr = vm->ram_start;

    ret = ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &(vm->mem));

    if (ret < 0)
    {
        perror("can not set user memory region");
        return ret;
    }

    return ret;
}

void load_binary(struct vm *vm, char *binary_file)
{
    int fd = open(binary_file, O_RDONLY);

    if (fd < 0)
    {
        fprintf(stderr, "can not open binary file\n");
        exit(1);
    }

    int ret = 0;
    char *p = (char *)vm->ram_start;

    // load the program from start of memory space
    while (1)
    {
        ret = read(fd, p, 4096);
        if (ret <= 0)
        {
            break;
        }
        printf("VMFD: %d, Loaded Program with size: %d\n", vm->vm_fd, ret);
        p += ret;
    }
}

struct vcpu *kvm_init_vcpu(struct vm *vm, int vcpu_id, void *(*fn)(void *))
{
    struct vcpu *vcpu = malloc(sizeof(struct vcpu));
    vcpu->vcpu_id = vcpu_id;
    vcpu->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, vcpu->vcpu_id);

    if (vcpu->vcpu_fd < 0)
    {
        perror("can not create vcpu");
        return NULL;
    }

    // The result of this ioctl call is the size of the memory-mapped area needed for the kvm_run 
    vcpu->kvm_run_mmap_size = ioctl(vm->dev_fd, KVM_GET_VCPU_MMAP_SIZE, 0);

    if (vcpu->kvm_run_mmap_size < 0)
    {
        perror("can not get vcpu mmsize");
        return NULL;
    }

    // allocate the memory for the kvm_run
    // The kvm_run structure contains information about the vCPU's state and is updated by the kernel during 
    // the execution of the virtual machine.
    vcpu->kvm_run = mmap(NULL, vcpu->kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu->vcpu_fd, 0);

    if (vcpu->kvm_run == MAP_FAILED)
    {
        perror("can not mmap kvm_run");
        return NULL;
    }

    vcpu->vcpu_thread_func = fn;
    return vcpu;
}

void kvm_reset_vcpu(struct vcpu *vcpu)
{
    if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &(vcpu->sregs)) < 0)
    {
        perror("can not get sregs\n");
        exit(1);
    }

    vcpu->sregs.cs.selector = CODE_START;
    vcpu->sregs.cs.base = CODE_START * 16;
    vcpu->sregs.ss.selector = CODE_START;
    vcpu->sregs.ss.base = CODE_START * 16;
    vcpu->sregs.ds.selector = CODE_START;
    vcpu->sregs.ds.base = CODE_START * 16;
    vcpu->sregs.es.selector = CODE_START;
    vcpu->sregs.es.base = CODE_START * 16;
    vcpu->sregs.fs.selector = CODE_START;
    vcpu->sregs.fs.base = CODE_START * 16;
    vcpu->sregs.gs.selector = CODE_START;

    if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs) < 0)
    {
        perror("can not set sregs");
        exit(1);
    }

    vcpu->regs.rflags = 0x0000000000000002ULL;
    vcpu->regs.rip = 0;
    vcpu->regs.rsp = 0xffffffff;
    vcpu->regs.rbp = 0;

    if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &(vcpu->regs)) < 0)
    {
        perror("KVM SET REGS\n");
        exit(1);
    }
}

void *kvm_cpu_thread(void *data)
{
    // Copy the code from this function to your code implementation in kvm_run_vm() and modify it accordingly
    struct vm *vm = (struct vm *)data;
    int ret = 0;
    kvm_reset_vcpu(vm->vcpus);

    while (1)
    {
        printf("VMFD: %d started running\n", vm->vm_fd);
        ret = ioctl(vm->vcpus->vcpu_fd, KVM_RUN, 0);

        printf("VMFD: %d stopped running - exit reason: %d\n", vm->vm_fd, vm->vcpus->kvm_run->exit_reason);

        switch (vm->vcpus->kvm_run->exit_reason) {
            case KVM_EXIT_UNKNOWN:
                printf("VMFD: %d KVM_EXIT_UNKNOWN\n", vm->vm_fd);
                break;
            case KVM_EXIT_DEBUG:
                printf("VMFD: %d KVM_EXIT_DEBUG\n", vm->vm_fd);
                break;
            case KVM_EXIT_IO:
                printf("VMFD: %d KVM_EXIT_IO\n", vm->vm_fd);
                printf("VMFD: %d out port: %d, data: %d\n", vm->vm_fd, vm->vcpus->kvm_run->io.port, *(int *)((char *)(vm->vcpus->kvm_run) + vm->vcpus->kvm_run->io.data_offset));
                sleep(1);
                break;
            case KVM_EXIT_MMIO:
                printf("VMFD: %d KVM_EXIT_MMIO\n", vm->vm_fd);
                break;
            case KVM_EXIT_INTR:
                printf("VMFD: %d KVM_EXIT_INTR\n", vm->vm_fd);
                break;
            case KVM_EXIT_SHUTDOWN:
                printf("VMFD: %d KVM_EXIT_SHUTDOWN\n", vm->vm_fd);
                goto exit_kvm;
                break;
            default:
                printf("VMFD: %d KVM PANIC\n", vm->vm_fd);
                printf("VMFD: %d KVM exit reason: %d\n", vm->vm_fd, vm->vcpus->kvm_run->exit_reason);
                goto exit_kvm;
        }
        if (ret < 0 && vm->vcpus->kvm_run->exit_reason != KVM_EXIT_INTR)
        {
            fprintf(stderr, "VMFD: %d KVM_RUN failed\n", vm->vm_fd);
            printf("VMFD: %d KVM_RUN return value %d\n", vm->vm_fd, ret);
            exit(1);
        }
    }

    exit_kvm:
    return 0;
}


// Function to handle the timer expiration
void timer_handler(int signo) {
    if (signo == SIGUSR1) {
        printf("Timer expired! Sending signal to VM...\n");
    }
}


// Function to create and start the timer
void start_timer() {
    struct sigevent sev;
    struct itimerspec vm_it;

    // Set up the timer expiration handler
    struct sigaction sa;
    sa.sa_handler = timer_handler;
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    // Create the timer
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGUSR1;
    sev.sigev_value.sival_ptr = &timerid;

    if(timer_create(CLOCK_MONOTONIC, &sev, &timerid) < 0) {
        perror("timer creae failed :");
        exit(EXIT_FAILURE);
    }

    // Set the timer interval
    vm_it.it_value.tv_sec = QUANTUM;
    vm_it.it_value.tv_nsec = 0;
    vm_it.it_interval.tv_sec = QUANTUM;
    vm_it.it_interval.tv_nsec = 0;

    // Start the timer
    if (timer_settime(timerid, 0, &vm_it, NULL) < 0) {
        perror("Timer set time failed\n");
        exit(1);
    }

    // printf("Time created!\n");
}

// Function to delete the timer
void delete_timer() {
    // Delete the timer
    if (timerid != NULL) {
        if (timer_delete(timerid) < 0) {
            perror("Timer deletion failed");
            exit(EXIT_FAILURE);
        }
        printf("Timer deleted\n");
        timerid = NULL; // Set to NULL to avoid accidentally using the deleted timer
    } else {
        printf("Timer not yet created\n");
    }
}

// Function to block the signal for the control thread
void block_signal_for_control_thread() {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);

    // Block SIGUSR1 for the current thread (control thread)
    pthread_sigmask(SIG_BLOCK, &mask, NULL);
}


void kvm_run_vm(struct vm *vm1, struct vm *vm2)
{

    // reset the vcpus
    kvm_reset_vcpu(vm1->vcpus);
    kvm_reset_vcpu(vm2->vcpus);

    // Variable to track switching between VMs
    int switch_to_vm1 = 1;  
    struct vm *vm = vm1;
    int ret = 0;

    // set signal mask
    struct kvm_signal_mask *sigmask = alloca(offsetof(struct kvm_signal_mask, sigset) + sizeof(sigset_t));
	sigset_t *signal_set = (sigset_t *) &sigmask->sigset;
    siginfo_t info;

	sigmask->len = 8;
	pthread_sigmask(0, NULL, signal_set);

	if(ioctl(vm1->vcpus->vcpu_fd, KVM_SET_SIGNAL_MASK, sigmask) < 0) {
        perror("KVM_SET_SIGNAL_MASK\n");
        exit(1);
    }

    if(ioctl(vm2->vcpus->vcpu_fd, KVM_SET_SIGNAL_MASK, sigmask) < 0) {
        perror("KVM_SET_SIGNAL_MASK\n");
        exit(1);
    }

    sigemptyset(signal_set);    // empty the signals from the sigmask
    sigaddset(signal_set, SIGUSR1); // added the signal to the sigmask

    block_signal_for_control_thread();  // block the signal for the control thread
    start_timer();  // start the timer

    // variables for maintaining the ratios vm1_count : 70% and vm2_count: 30%
    int total_count = 0;
    int vm1_count = FRAC_A;
    int vm2_count = FRAC_B;
    

    while (1)
    {
        // switching the vms
        if(switch_to_vm1) {
            vm1_count--;
            vm = vm1;
        }
        else {
            vm2_count--;
            vm = vm2;
        }
        kvm_reset_vcpu(vm->vcpus);

        printf("VMFD: %d started running\n", vm->vm_fd);

        ret = ioctl(vm->vcpus->vcpu_fd, KVM_RUN, 0);

        // printf("ret value: %d\n", ret);
        printf("Time: %f\n", CURRENT_TIME);

        if(ret == -1 || ret == -EINTR) {
            // printf("Signal recieved and VM exited\n");

            // remove the pending signals
            if(sigwaitinfo(signal_set, &info) == -1) {
                perror("sigwaitinfo");
                exit(1);
            }

            // if vm1 runs for the 70% then switch to vm2
            if(vm1_count == 0) {
                switch_to_vm1 = 1 - switch_to_vm1;
                vm1_count = FRAC_A;
            }

            // if vm2 runs for the 30% then switch to vm1
            else if(vm2_count == 0) {
                switch_to_vm1 = 1 - switch_to_vm1;
                vm2_count = FRAC_B;
            }
        }

        printf("VMFD: %d stopped running - exit reason: %d\n", vm->vm_fd, vm->vcpus->kvm_run->exit_reason);

        switch (vm->vcpus->kvm_run->exit_reason) {
            case KVM_EXIT_UNKNOWN:
                printf("VMFD: %d KVM_EXIT_UNKNOWN\n", vm->vm_fd);
                break;
            case KVM_EXIT_DEBUG:
                printf("VMFD: %d KVM_EXIT_DEBUG\n", vm->vm_fd);
                break;
            case KVM_EXIT_IO:
                if(switch_to_vm1) {
                    printf("VMFD: %d KVM_EXIT_IO\n", vm->vm_fd);
                    printf("VMFD: %d out port: %d, data: %d\n", vm->vm_fd, vm->vcpus->kvm_run->io.port, *(int *)((char *)(vm->vcpus->kvm_run) + vm->vcpus->kvm_run->io.data_offset));
                    vm = vm2;
                }
                else {
                    printf("VMFD: %d KVM_EXIT_IO\n", vm->vm_fd);
                    printf("VMFD: %d out port: %d, data: %d\n", vm->vm_fd, vm->vcpus->kvm_run->io.port, *(int *)((char *)(vm->vcpus->kvm_run) + vm->vcpus->kvm_run->io.data_offset));
                    vm = vm1;
                }
                sleep(1);
                switch_to_vm1 = 1 - switch_to_vm1;
                break;
            case KVM_EXIT_MMIO:
                printf("VMFD: %d KVM_EXIT_MMIO\n", vm->vm_fd);
                break;
            case KVM_EXIT_INTR:
                printf("VMFD: %d KVM_EXIT_INTR\n", vm->vm_fd);
                break;
            case KVM_EXIT_SHUTDOWN:
                printf("VMFD: %d KVM_EXIT_SHUTDOWN\n", vm->vm_fd);
                goto exit_kvm;
                break;
            default:
                printf("VMFD: %d KVM PANIC\n", vm->vm_fd);
                printf("VMFD: %d KVM exit reason: %d\n", vm->vm_fd, vm->vcpus->kvm_run->exit_reason);
                goto exit_kvm;
        }
        if (ret < 0 && vm->vcpus->kvm_run->exit_reason != KVM_EXIT_INTR)
        {
            fprintf(stderr, "VMFD: %d KVM_RUN failed\n", vm->vm_fd);
            printf("VMFD: %d KVM_RUN return value %d\n", vm->vm_fd, ret);
            exit(1);
        }
    }

    exit_kvm:
    return;
}

void kvm_clean_vm(struct vm *vm)
{
    close(vm->vm_fd);
    munmap((void *)vm->ram_start, vm->ram_size);
}

void kvm_clean_vcpu(struct vcpu *vcpu)
{
    munmap(vcpu->kvm_run, vcpu->kvm_run_mmap_size);
    close(vcpu->vcpu_fd);
}

void kvm_clean(struct vm *vm)
{
    assert(vm != NULL);
    close(vm->dev_fd);
    free(vm);
}

int main(int argc, char **argv)
{
    struct vm *vm1 = malloc(sizeof(struct vm));
    struct vm *vm2 = malloc(sizeof(struct vm));

    kvm_init(vm1, vm2);

    if (kvm_create_vm(vm1, RAM_SIZE) < 0)
    {
        fprintf(stderr, "create vm fault\n");
        return -1;
    }

    if (kvm_create_vm(vm2, RAM_SIZE) < 0)
    {
        fprintf(stderr, "create vm fault\n");
        return -1;
    }

    load_binary(vm1, BINARY_FILE1);
    load_binary(vm2, BINARY_FILE2);

    vm1->vcpu_number = 1;
    vm1->vcpus = kvm_init_vcpu(vm1, 0, kvm_cpu_thread);

    vm2->vcpu_number = 1;
    vm2->vcpus = kvm_init_vcpu(vm2, 0, kvm_cpu_thread);

    kvm_run_vm(vm1, vm2);

    kvm_clean_vm(vm1);
    kvm_clean_vm(vm2);

    kvm_clean_vcpu(vm1->vcpus);
    kvm_clean_vcpu(vm2->vcpus);
    kvm_clean(vm1);
    kvm_clean(vm2);
}