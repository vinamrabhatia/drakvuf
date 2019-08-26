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
The earlier implementation of the libinjector hijacks an arbitrary process and checks if kernel32.dll is loaded. It the sets up the stack for the execution of CreateProcessA function. The first part of the project was to extend the libinjector library so that it can call arbitrary functions inside the Windows kernel, along with the arguments which we provide.

2. Integration of the fuzzer:
The next and final goal was to check and figure out the variable possible ways to integrate a fuzzer with the current setup. 


```
$ cd your_repo_root/repo_name
$ git fetch origin
$ git checkout gh-pages
```

#### Issues Encountered
We've crafted some handsome templates for you to use. Go ahead and continue to layouts to browse through them. You can easily go back to edit your page before publishing. After publishing your page, you can revisit the page generator and switch to another theme. Your Page content will be preserved if it remained markdown format.

### Rather Drive Stick?
If you prefer to not use the automatic generator, push a branch named `gh-pages` to your repository to create a page manually. In addition to supporting regular HTML content, GitHub Pages support Jekyll, a simple, blog aware static site generator written by our own Tom Preston-Werner. Jekyll makes it easy to create site-wide headers and footers without having to copy them across every page. It also offers intelligent blog support and other advanced templating features.

### Authors and Contributors
You can @mention a GitHub username to generate a link to their profile. The resulting `<a>` element will link to the contributor's GitHub Profile. For example: In 2007, Chris Wanstrath (@defunkt), PJ Hyett (@pjhyett), and Tom Preston-Werner (@mojombo) founded GitHub.

### Support or Contact
Having trouble with Pages? Check out the documentation at http://help.github.com/pages or contact support@github.com and we’ll help you sort it out.
