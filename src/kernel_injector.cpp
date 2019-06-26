#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <libvmi/libvmi.h>

#include <libdrakvuf/libdrakvuf.h>
#include <libkernel_injector/kernel_injector.cpp>

static drakvuf_t drakvuf;

static void close_handler(int sig)
{
    drakvuf_interrupt(drakvuf, sig);
}

static inline void print_help(void)
{
    fprintf(stderr, "Required input:\n"
            "\t -r <rekall profile>       The Rekall profile of the OS kernel\n"
            "\t -d <domain ID or name>    The domain's ID or name\n"
            "Optional inputs:\n"
            //For now, I am just calling a particular function
            //TODO: Take the function name and arguments.
            "\t -l                        Use libvmi.conf\n"

#ifdef DRAKVUF_DEBUG
            "\t -v                        Turn on verbose (debug) output\n"
#endif
           );
}

int main(int argc, char** argv)
{
    int rc = 0;
    char c;
    char* rekall_profile = NULL;
    char* domain = NULL;
    bool verbose = 0;
    bool libvmi_conf = false;

    if (argc < 2)
    {
        print_help();
        return 1;
    }

    while ((c = getopt (argc, argv, "r:d:vl")) != -1)
        switch (c)
        {
            case 'r':
                rekall_profile = optarg;
                break;
            case 'd':
                domain = optarg;
                break;
#ifdef DRAKVUF_DEBUG
            case 'v':
                verbose = 1;
                break;
#endif
            case 'l':
                libvmi_conf = true;
                break;
            default:
                fprintf(stderr, "Unrecognized option: %c\n", c);
                return rc;
        }

    if ( !rekall_profile || !domain)
    {
        print_help();
        return 1;
    }

    /* for a clean exit */
    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    if (!drakvuf_init(&drakvuf, domain, rekall_profile, NULL, verbose, libvmi_conf))
    {
        fprintf(stderr, "Failed to initialize on domain %s\n", domain);
        return 1;
    }

    printf("Kernel Injector starting");
    //TODO: Adding name of kernel function we want to start and the arguments to it in the functions!

    int kernel_injection_result = kernel_injector_start(drakvuf, OUTPUT_DEFAULT);

    if (kernel_injection_result)
        printf("Process kernel_injection success\n");
    else
    {
        printf("Process kernel_injection failed\n");
        rc = 1;
    }

    drakvuf_resume(drakvuf);

    drakvuf_close(drakvuf, 0);

    return rc;
}
