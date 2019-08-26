### About the Project

The most critical components of the project here are 'Hypervisor' and 'Fuzzer'. Here is a quick glance of following.

#### Fuzzing 

Fuzzing is an software testing technique for finding out security vulnerabilities. Although it appears as a very naive technique, fuzzing has shown to scale well and be remarkably effective in revealing vulnerabilities and undefined behaviour in software. Traditionally, fuzzing tools used to apply random mutations to well formed inputs and feed them to the target program for possible security exceptions. Fuzzing has evolved over the years, inspired by the recent advances in symbolic execution. Coverage guided fuzzing uses techniques like program instrumentation and genetic algorithms to trace the code coverage reached by each input fed to a fuzz target. There are well established tools available which can help in fuzzing of user space, AFL being one of the most prominent among those. Some efforts have been made to find security vulnerabilities in system calls (eg syzkaller) and these projects are  in active development. However, fuzzing operating systems using hypervisor has not been explored much. 

To have a look at what effective fuzzing has achieved in the past, head over to <a href="http://lcamtuf.coredump.cx/afl/"> AFL </a> and have a look at the 'Bug-o-Rama Trophy Case'

#### DRAKVUF

DRAKVUF is a black-box binary analysis system built on top of Xen(a type-1 hypervisor). DRAKVUF is capable of trapping execution of any code in the analysis VM. It inserts breakpoint at desired locations which forwards such events to the control domain, hence providing fidelity. It also provides scalability by making use of Xen’s Copy-on-Write memory interface and Linux Copy-on-write storage interface, hence making optimised use of hardware. It was initially designed to act as a malware analysis system. But with its unique ability to to fetch in-depth execution tracking of execution binary without having to install any special software (hence being stealth), it can find its application in several other areas. DRAKVUF has a libinjector library which can hijack any arbitrary running process running inside the VM and set up the stack to call CreateProcessA function. This was originally meant to initiate the execution of the sample.

#### Goal of the Project

The aim of the project is to integrate AFL with DRAKVUF’s libinjector and perform fuzzing on kernel functions. So, the goal is to get the AFL to work and figure out the challenges involved in the process. The major idea is to explore the limitations of fuzzing the operating system with the help of a hypervisor. Since not much efforts have been done in this aspect, we aimed to find out how effective the technique is in the kernel space. Hence, the project involves a lot of experiments to find out solutions to the problems.

The project here can be distinctively divided into 2 parts here.

1. Modifying libinjector to execute arbitrary functions:
The earlier implementation of the libinjector hijacks an arbitrary process and checks if kernel32.dll is loaded. It the sets up the stack for the execution of CreateProcessA function. The first part of the project was to extend the libinjector library so that it can call arbitrary functions inside the Windows kernel, along with the arguments which we provide. I came up with a couple of approaches to get the first part done, and after a good discussion with my mentor, we firmed up on a idea. I was earlier trying to trap the sys

2. Integration of the fuzzer:
The next and final goal was to check and figure out the various possible ways to integrate a fuzzer with the current setup. 


### Hurdles on the way

Before diving into the project, I knew that certain parts of the project will be particularly difficult. Some of the issues I encountered in the later part of the project were a lot more difficult than I earlier expected. Dividing the section into two parts as the project, here we go.

#### Part 1: Extending the libinjector
Not having used Windows for the past 3 years and having always preferred a Unix environment, I thought that there would be a teep learning curve about the internals of Windows. However, I was pretty pleased to find out all the underlying concepts to be exaclty the same. Understanding the internals turned out to be a relatively easy task and I was confident about it within a week.

I was picky about trapping the kernel entry point, from where I will set up the stack and change the rip to my desired target function. Digging deeper, I read about how the system call entry point is itself referenced in syscall_init(), a function that is called early in the kernel's startup sequence. I believed that this would be the most efficient way to solve our problem. Spending close to 2 weeks on this and not making any good progress, I reverted back to what was suggested by Tamas. I used the drakvuf syscall plugin to set up a breakpoint at each of the Windows syscall. Rekall profile for the windows version supplied the address of the target function. Now, as soon as I receive the trap, I would redirect the flow of the control by diverting the execution to the desired function, after setting up the stack for that function. 

The next and pretty obvious step was to modify the kernel-injector file to take the arguments from the command file, and making sure that the setup works for 32 bit machines as well. 

Getting the GUID for 32 bit machines didnt work as it was working for 64 bit machines, and a significant chuck on time went away there. A quick glimpse of terminal commands which did the job.

```
$ sudo kpartx -l /dev/vgpool_32bit/win7_sp1_32  # This will show all the partiions in the volumn, e,g
vgpool_32bit/win7_sp1_32_1 : 0 204800 /dev/vgpool_32bit/win7_sp1_32 2048
vgpool_32bit/win7_sp1_32_2 : 0 41734144 /dev/vgpool_32bit/win7_sp1_32 206848
$ sudo kpartx -a /dev/vgpool_32bit/lwin7_sp1_32
$ sudo mount -o ro /dev/mapper/vgpool_32bit/win7_sp1_32_2 /mnt  # might change partion to find the Windows/ folder
$ sudo rekal peinfo -f /mnt/Windows/System32/ntoskrnl.exe > /temp/peinfo.txt
$ sudo umount /mnt
$ sudo kpartx -d /dev/vgpool_32bit/lwin7_sp1_32
```

#### Part 2: Integration of the Fuzzer

Here comes the most difficult part of the project. After trying my hands around all over the place, I discussed with my mentor on how to proceed, and the only way ahead that I could see was to go through the following steps:  outline on 1) how afl's code coverage is supposed to work 2) what ideas you had about integrating it into your os fuzzing tool 3) what worked / what didn't work / what wasn't tested.

And here is a brief summary of the above details.

As I understand, firstly we compile the binary with AFL. This leads to block-edge instrumentation in the binary.
In coverage-guided fuzzing, we first supply AFL with a set of test-cases. These test cases form the initial corpus of inputs and form a queue to the AFL. AFL tries to mutate these cases and supply them to the program. With the instrumentation done, it gets the feedback about the program control . So if any of the generated mutations resulted in a new state transition recorded by the instrumentation, add mutated output as a new entry in the queue.

The first option was to check the <b>AFL Qemu mode</b>, which allows us to do black-box fuzzing. So, I stepped in and tried to get AFL working in the Qemu mode. Due to some compatibility issues with the version of Qemu AFL was downloading, I wasted a significant amount on this. After getting it working, I realised this method will not be useful for us at all.

In the black box fuzzing mode, AFL does on the fly instrumentation of black-box binaries. This is done by QEMU running in the "user space emulation" mode. So, in user space mode, QEMU doesn’t emulate all the hardware, but only the CPU. It executes foreign code in the emulated CPU, and then it captures the syscalls and forwards them to the host kernel. Basically, it seems that all the kernel level code won’t be emulated by QEMU and highly likely that the method won’t work. Besides, I was unable to figure out any step to proceed with the integration.

Then, I came across <b>LibFuzzer</b>. This gave me some hope since with this, one can kinda do targeted fuzzing of functions, also it is a guided in-process fuzzing. (everything in a single process, so probably faster). But with my understanding, for this to work, I think source code is a necessity, and we are trying to fuzz functions in a closed source running Kernel. 

Then, I came across this project on Github called <a href="https://github.com/googleprojectzero/winafl"> WinAFL </a>. This project is basically a fork of AFL that uses different instrumentation modes, majorly using DynamoRIO.
Also, to improve startup time, it relies heavily on persistent fuzzing mode, that is, executing multiple input samples without restarting the target process. This is accomplished by selecting a target function (that the user wants to fuzz) and instrumenting it so that it runs in a loop.
This is still a very good candidate method but I am yet to figure out how exactly I can integrate this. It is mainly designed for user-level applications.

<a href="https://github.com/hfiref0x/NtCall64">NtCall64</a> : This is another project which brute-forces a service and tries to call them with all sort of inputs. It can cause the system to crash, and it is basically trying to call user level corresponding functions of those syscalls. As I understand, no coverage-guide. So, this is a very dumb fuzzer basically.
  
Lastly, I found out about <b>AFL-Unicorn</b> and I hope this can help us greatly.
Unicorn is an emulator. All unicorn does basically is it takes the binary code and executes instructions one by one. This can basically fuzz anything that the unicorn engine can emulate. This works by emulation the block-edge instrumentation. AFL basically uses the block coverage from any emulated code snippet to drive its input generation.
We set up a breakpoint at the location which we want to fuzz, run the program. When we hit the breakpoint, we need to be able to dump memory, dump CPU state, and basically the complete memory snapshot of what we want to fuzz.
Now we take the saved state and write a unicorn script, which takes the saved state and emulate the further code of the syscall function. It has all the benefits of AFL(guided coverage and effective mutation of test cases). And allows us to fuzz the part of the code that we want. It seemed for a while that I have found the perfect candidate for the position. 

Howwever, with further discussions, it came to my understanding that it will probably be a better idea to keep everything going within the hypervisor. 

In other terms, the coverage guidance part of AFL is telling AFL which inputs to mutate more because a certain new path is discovered. Hence, 'the new discovered path' is the trigger here. AFL gets this trigger with the instrumentation. However, we can also try to monitor for other types of behaviour, which can help us to mutate our inputs. Some of the possible cases can be reaching a particular kernel function (and this feedback can be obtained by setting up a trap at this particular function. 

During this peak time of the project, I had to go for my undergraduate convocation at my university, BITS Pilani Goa. And later during the same week, I had my flights to the States, where I am starting Masters in Information Securiy at Carnegie Mellon University. Juggling with settling down in a new place, going through necessary orientations and preparing for the classes to be taken this current fall, I had a little time left for the final few days of GSoC.

I realised that I really need to figure out how the coverage guided thing actually gives the feedback and what all possible types of feedback can be given back to the AFL. I couldnt find anything on it available in the docs, so had to check out the code.

Struggling through that for a few days and with the end of the project coming nearer, I  thought it might be better that first I implement a simple fuzzer as a proof of concept of hooking syscalls, and restoring snapshots on crash, to which a more sophisticated fuzzer can be plugged into later. After multiple attemps, I was able to create clone VM machines running the kernel-injector script with the arguments that I supply. 

### Current Project State and TODOs:

All of the code committed in the project lies in the commits made by @vinamrabhatia handle at https://github.com/vinamrabhatia/drakvuf/tree/kernel_injector . 

src/kernel_injector achieves the first half of project, and it takes in the arguments and the function name of the kernel, redirects to that function in the kernel mode and returns back to the normal executation of the function. 
```
sudo ./kernel_injector -r windows7-sp1.rekall.json -d 1 -f KeBugCheckEx -n 5 -a i 0 i 1 i 2 i 3 i 4 
```

src/fuzzer achieves the remaining project. The fuzzer takes in all the necessary arguments, clone a snapshot of the running guest, calls the functions and retunrs back. It is meant to take arguments of the target function from a file supplied by the fuzzer. 

```
sudo ./fuzzer <loop (0) or poll (1)> <origin domain name> <domain config> <rekall_profile> <kernel_function> <number_of_args> <input_file> <max clones> <clone_script> <kernel_injector_script> <cleanup_script>
```

clone_script, kernel_injector_script and cleanup script are available in tools directory. 

TODOs:

I have implemented a simple fuzzer as a proof of concept of hooking syscalls, and restoring snapshots on crash, to which a more sophisticated fuzzer can be plugged into later.

The main leftover of the project is to make the fuzzer get the feedback from the kernel, and accordingly redirect/mutate the possible inputs


### Authors and Contributors
You can @mention a GitHub username to generate a link to their profile. The resulting `<a>` element will link to the contributor's GitHub Profile. For example: In 2007, Chris Wanstrath (@defunkt), PJ Hyett (@pjhyett), and Tom Preston-Werner (@mojombo) founded GitHub.

