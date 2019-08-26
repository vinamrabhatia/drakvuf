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
The next and final goal was to check and figure out the variable possible ways to integrate a fuzzer with the current setup. 


```
$ cd your_repo_root/repo_name
$ git fetch origin
$ git checkout gh-pages
```

### Hurdles on the way

Before diving into the project, I knew that certain parts of the project will be particularly difficult. Some of the issues I encountered in the later part of the project were a lot more difficult than I earlier expected. Dividing the section into two parts as the project, here we go.

Part 1: Extending the libinjector
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

Part 2: Integration of the Fuzzer


### Rather Drive Stick?
If you prefer to not use the automatic generator, push a branch named `gh-pages` to your repository to create a page manually. In addition to supporting regular HTML content, GitHub Pages support Jekyll, a simple, blog aware static site generator written by our own Tom Preston-Werner. Jekyll makes it easy to create site-wide headers and footers without having to copy them across every page. It also offers intelligent blog support and other advanced templating features.

### Authors and Contributors
You can @mention a GitHub username to generate a link to their profile. The resulting `<a>` element will link to the contributor's GitHub Profile. For example: In 2007, Chris Wanstrath (@defunkt), PJ Hyett (@pjhyett), and Tom Preston-Werner (@mojombo) founded GitHub.

### Support or Contact
Having trouble with Pages? Check out the documentation at http://help.github.com/pages or contact support@github.com and we’ll help you sort it out.
