#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>
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
            "\t -f <function_name>        The kernel function to be called\n"
            "\t -n <number_of_arguments>  Number of arguments needed in teh function\n"
            "\t -a <arguments>            arguments to the kernel function\n"
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
    int number_of_arguments = 0;
    char* function_name = NULL;
    int lcount = 0;
    struct argument args[20] = { {0} };
    char *next = NULL;
    int index;
    unicode_string_t* string_args[20];
    int number_of_string_args = 0;

    if (argc < 4)
    {
        print_help();
        return 1;
    }

    while ((c = getopt (argc, argv, "r:d:f:n:avl")) != -1)
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
            case 'f':
                function_name = optarg;
                break;
            case 'n':
                number_of_arguments = atoi(optarg);
                break;
            case 'a':
                index = optind;
                while(lcount < number_of_arguments){
                    next = strdup(argv[index]); /* get login */
                    index++;
                    if(next[0] != '-'){         /* check if optarg is next switch */
                        if(next[0]=='i'){
                            next = strdup(argv[index]); /* get login */
                            index++;
                            init_int_argument(&args[lcount], atoi(next));
                        }
                        else if(next[0]=='s'){
                            //Convert into
                            next = strdup(argv[index]);
                            index++;
                            string_args[number_of_string_args] = convert_utf8_to_utf16(next);
                            init_unicode_argument(&args[lcount], string_args[number_of_string_args]);
                            number_of_string_args++;
                        }
                    }
                    else break;
                    lcount++;
                }
                if(lcount != number_of_arguments){
                    print_help();
                    return 1;
                }
                break;
            default:
                fprintf(stderr, "Unrecognized option: %c\n", c);
                return rc;
        }

    if ( !rekall_profile || !domain || !function_name || !number_of_arguments)
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

    int kernel_injection_result = kernel_injector_start(drakvuf, OUTPUT_DEFAULT, function_name,
                                                        number_of_arguments, args,
                                                        string_args, number_of_string_args);

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
