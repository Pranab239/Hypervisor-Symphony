# CS695 Assignment 2 - Part 1

simple-kvm is a very simple example program to demonstrate the use of the KVM API provided by the Linux kernel. Tested in Intel processors with the VMX hardware virtualization extensions and AMD processors with AMD-V hardware virtualization extensions.

## How to run

Performing ```make``` or ```make run``` will compile the program and run the program all modes. Otherwise the program can be run in 4 modes specifically using the following commands:

````bash
make simple-kvm
./simple-kvm
./simple-kvm -s
./simple-kvm -p
./simple-kvm -l
````

Performing a ```make clean``` will remove the executable and the object files.

### A couple of aspects are worth noting

Note that the Intel VMX extensions did not initially implement support for real mode.  In fact, they restricted VMX guests to paged protected
mode.  VMM / Hypervisor were expected to emulate the unsupported modes in software, only employing VMX when a guest had entered paged protected mode.  Later VMX implementations include *Unrestricted Guest Mode*: support for virtualization of all x86 modes in hardware.

The code run in the VM code exits with a HLT instruction.  There are many ways to cause a VM exit, so why use a HLT instruction?  The most obvious way might be the VMCALL (or VMMCALL on AMD) instruction, which it specifically intended to call out to the hypervisor.  But it turns out the KVM reserves VMCALL/VMMCALL for its internal hypercall mechanism, without notifying the userspace VM host program of the VM exits caused by these instructions.  So we need some other way to trigger a VM exit.  HLT is convenient because it is a single-byte instruction.
