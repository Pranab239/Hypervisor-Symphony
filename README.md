## Project Overview

This project involves creating a custom hypervisor using KVM (Kernel-based Virtual Machine) in Linux. The project is divided into two main parts: building a DIY hypervisor and creating a fractional scheduling mechanism for multiple VMs. 

### Part 1: DIY Hypervisor

In this part, you will build a simple hypervisor using KVM, allowing it to run a single stream of instructions as a guest OS. The hypervisor will be capable of handling basic I/O operations and implementing several hypercalls.

#### Tasks:

1. **Hypervisor Setup**: Understand the working of `simple-kvm.c` and explain the logical actions to set up and execute a VM in long mode using a detailed flowchart.
2. **Implement Hypercalls**:
    - `HC_print32bit(uint32_t val)`: Print a 32-bit value.
    - `HC_numExits()`: Return the number of VM exits.
    - `HC_printStr(char *str)`: Print a string from the guest.
    - `HC_numExitsByType()`: Return a string with counts of I/O in and out exits.
    - `HC_gvaToHva(uint32_t gva)`: Translate a Guest Virtual Address to a Host Virtual Address.

### Part 2: Matrix Cloud Hypervisor

This part involves creating a hypervisor capable of running two guest VMs, with a scheduling mechanism that ensures controlled execution and fractional time-sharing between the VMs.

#### Tasks:

1. **Single-threaded VM Execution**: Modify the hypervisor to run two VMs alternatively on the same CPU core using a single thread.
2. **Timer-based Scheduling**: Implement a timer-based interrupt mechanism to control VM execution when no I/O operations are occurring.
3. **Fractional Scheduling**: Extend the timer-based approach to implement fractional scheduling, allocating 70% of the CPU time to VM1 (Neo) and 30% to VM2 (Morpheus).

## Directory Structure

```
Hypervisor-Symphony/
├──── .git/
│        └── . . . /* all git-related files */
│
├──── part1b/
│        ├── guest.c
│        ├── guest.ld
│        ├── guest16.s
│        ├── Makefile
│        ├── payload.ld
│        ├── README.md
│        └── simple-kvm.c
│
├──── part2/
│        ├── guest1.s
│        ├── guest1-a.s
│        ├── guest1-b.s
│        ├── guest2.s
│        ├── guest2-a.s
│        ├── guest2-b.s
│        ├── Makefile
│        ├── matrix-a.c
│        ├── matrix-b.c
│        ├── matrix.c
│        └── README.md
│
├──── part1a.pdf
├──── .gitignore
├──── Makefile
└──── README.md
```

## Instructions for Running the Project

### Part 1: DIY Hypervisor

1. **Setup**: Follow the setup instructions provided in the KVM installation guide for your Linux distribution.
2. **Build**: Navigate to the `part1b` directory and run `make`.
3. **Run**: Execute the hypervisor using `./simple-kvm`.

### Part 2: Matrix Cloud Hypervisor

1. **Single-threaded Execution (2a)**:
    - Build: Navigate to the `part2` directory and run `make matrix-a`.
    - Run: Execute using `./matrix-a`.

2. **Timer-based Scheduling (2b)**:
    - Build: Run `make matrix-b`.
    - Run: Execute using `./matrix-b`.

3. **Fractional Scheduling (2c)**:
    - Build: Run `make matrix`.
    - Run: Execute using `./matrix`.

## References

- [KVM Paper](link1)
- [Linux KVM API](link2)
- [KVM Documentation](link3)

---

Enjoy virtualizing and exploring the depths of KVM! For any questions or issues, please refer to the references provided or contact me.

**Long Live Virtualization!**
