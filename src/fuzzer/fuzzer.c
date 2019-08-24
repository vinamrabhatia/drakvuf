#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <dirent.h>
#include <errno.h>
#include <sys/inotify.h>
#include <signal.h>
#include <time.h>

#include "../xen_helper/xen_helper.h"

#define CLONE_CMD       "%s %s %u %s"
#define CLEANUP_CMD     "%s %u %u"
#define KERNEL_INJECTOR_CMD "%s %s %u %s %u %s"

#define UNUSED(x) (void)(x)

struct start_drakvuf
{
    int threadid;
    domid_t cloneID;
    char* input;
    char* clone_name;
    GMutex timer_lock;
    uint32_t timer;
    time_t utime;
};

static GThreadPool* pool;
static const char* domain_name;
static const char* domain_config;
static const char* rekall_profile;
static const char* kernel_function;
static const char* input_file;
static const char* clone_script;
static const char* kernel_injector_script;
static const char* cleanup_script;
static uint32_t threads;
static uint32_t number_of_args;
static bool shutting_down;

static GMutex locks[128];

xen_interface_t* xen;

void close_handler(int signal)
{
    shutting_down = signal;
}

static void
make_clone(xen_interface_t* xen, domid_t* cloneID, uint16_t vlan, char** clone_name)
{
    char* command;
    command = g_strdup_printf(CLONE_CMD, clone_script, domain_name, vlan, domain_config);
    printf("** RUNNING COMMAND: %s\n", command);
    char* output = NULL;
    g_spawn_command_line_sync(command, &output, NULL, NULL, NULL);
    g_free(command);
    get_dom_info(xen, output, cloneID, clone_name);
    g_free(output);
}

static inline int find_thread()
{
    unsigned int i=0;
    for (; i<threads; i++)
    {
        if (g_mutex_trylock(&locks[i]))
            return i;
    }
    return -1;
}

static inline void cleanup(domid_t cloneID, int vlan)
{
    char* command;
    command = g_strdup_printf(CLEANUP_CMD, cleanup_script, cloneID, vlan);
    printf("** RUNNING COMMAND: %s\n", command);
    g_spawn_command_line_sync(command, NULL, NULL, NULL, NULL);
    g_free(command);
}

gpointer timer_thread(gpointer data)
{

    struct start_drakvuf* start = (struct start_drakvuf*)data;

    gboolean gotlock = FALSE;

    while (start->timer > 0)
    {
        gotlock = g_mutex_trylock(&start->timer_lock);
        if ( gotlock )
        {
            g_mutex_unlock(&start->timer_lock);
            break;
        }

        start->timer--;
        sleep(1);
    }

    if ( !gotlock )
        cleanup(start->cloneID, start->threadid+1);

    return NULL;
}

static struct start_drakvuf* prepare(struct start_drakvuf* start, int _threadid)
{
    if (shutting_down)
        return NULL;

    domid_t cloneID = 0;
    char* clone_name = NULL;
    int threadid = start ? start->threadid : _threadid;

    if ( shutting_down )
        return NULL;

    printf("[%i] Making clone\n", threadid);
    make_clone(xen, &cloneID, threadid+1, &clone_name);

    while ((!clone_name || !cloneID) && !shutting_down)
    {
        printf("[%i] Clone creation failed, trying again\n", threadid);
        free(clone_name);
        clone_name = NULL;
        cloneID = 0;

        make_clone(xen, &cloneID, threadid+1, &clone_name);
    }

    if ( shutting_down )
        return NULL;

    if (!start)
    {
        start = g_malloc0(sizeof(struct start_drakvuf));
        start->threadid = threadid;
        g_mutex_init(&start->timer_lock);
    }

    start->cloneID = cloneID;
    start->clone_name = clone_name;
    start->utime = time(NULL);

    return start;
}

static inline void start(struct start_drakvuf* start, char* line)
{
    if ( shutting_down || !start || !line )
        return;

    start->input = g_strdup(line);
    g_thread_pool_push(pool, start, NULL);
}

void run_drakvuf(gpointer data, gpointer user_data)
{
    UNUSED(user_data);
    struct start_drakvuf* start = data;
    char* command;
    gint rc;
    GThread* timer;

restart:
    command = NULL;
    rc = 0;
    printf("[%i] Starting %s on domid %u\n", start->threadid, start->input, start->cloneID);

    start->timer = 60;
    g_mutex_lock(&start->timer_lock);
    timer = g_thread_new("timer", timer_thread, start);

    command = g_strdup_printf(KERNEL_INJECTOR_CMD, kernel_injector_script, rekall_profile, start->cloneID, kernel_function, number_of_args, start->input);
    printf("[%i] ** RUNNING COMMAND: %s\n", start->threadid, command);
    g_spawn_command_line_sync(command, NULL, NULL, &rc, NULL);
    g_free(command);

    g_mutex_unlock(&start->timer_lock);
    g_thread_join(timer);

    if (!start->timer)
        goto end;

    printf("[%i] ** DRAKVUF finished with RC %i. Timer: %i\n", start->threadid, rc, start->timer);

    if ( start->timer )
    {
        printf("[%i] Finished processing %s\n", start->threadid, start->input);

        g_mutex_unlock(&locks[start->threadid]);
        g_mutex_clear(&start->timer_lock);
        g_free(start->input);
        g_free(start->clone_name);
        g_free(start);
        return;
    }
    else
        cleanup(start->cloneID, start->threadid+1);

end:
    if ( !shutting_down )
    {
        printf("[%i] %s failed to execute on %u because of a timeout, creating new clone\n", start->threadid, start->input, start->cloneID);
        prepare(start, -1);
        goto restart;
    }
}

int main(int argc, char** argv)
{
    FILE* file_pointer;
    unsigned int i;
    unsigned int processed = 0;
    unsigned int total_processed = 0;
    int ret = 0;
    struct sigaction act;
    shutting_down = 0;
    char line[100] = {0};
    size_t read_bytes = 0;

    if (argc!=14)
    {
        printf("Not enough arguments: %i!\n", argc);
        printf("%s <loop (0) or poll (1)> <origin domain name> <domain config> <rekall_profile> <kernel_function> <number_of_args> <input_file> <max clones> <clone_script> <kernel_injector_script> <cleanup_script>\n", argv[0]);
        return 1;
    }

    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    xen_init_interface(&xen);

    int do_poll = atoi(argv[1]);
    domain_name = argv[2];
    domain_config = argv[3];
    rekall_profile = argv[4];
    kernel_function = argv[5];
    number_of_args = atoi(argv[6]);
    input_file = argv[7];
    threads = atoi(argv[8]);
    clone_script = argv[9];
    kernel_injector_script = argv[10];
    cleanup_script = argv[11];

    if (threads > 128)
    {
        printf("Too many clones requested (max 128 is specified right now)\n");
        return 1;
    }

    for (i=0; i<threads; i++)
        g_mutex_init(&locks[i]);

    pool = g_thread_pool_new(run_drakvuf, NULL, threads, TRUE, NULL);

    int fd = inotify_init();
    int wd = inotify_add_watch(fd, input_file, IN_CLOSE_WRITE);
    char buffer[sizeof(struct inotify_event) + NAME_MAX + 1];

    struct pollfd pollfd =
    {
        .fd = fd,
        .events = POLLIN
    };

    int threadid = -1;

    file_pointer = fopen(input_file, "r");
    if(file_pointer == NULL){
        shutting_down = 1;
    }

    do
    {
        if(shutting_down) break;

        processed = 0;

        while (threadid<0 && !shutting_down)
        {
            sleep(1);
            threadid = find_thread();
        }

        line[0]=0;
        if((read_bytes = fscanf(file_pointer, "%[^\n]", line))){
            struct start_drakvuf* _start = prepare(NULL, threadid);
            start(_start, line);

            threadid = -1;
            processed++;
        }
        else{
            printf("File read or fail to read the file further\n");
            ret = 1;
            break;
        }

        if ( processed )
        {
            total_processed += processed;
            printf("Batch processing started %u fuzzing inputs (total %u)\n", processed, total_processed);
        }

        if ( !processed && !shutting_down )
        {
            if ( do_poll )
            {
                do
                {
                    int rv = poll (&pollfd, 1, 1000);
                    if ( rv < 0 )
                    {
                        printf("Error polling\n");
                        ret = 1;
                        break;
                    }
                    if ( rv > 0 && pollfd.revents & POLLIN )
                    {
                        if ( read( fd, buffer, sizeof(struct inotify_event) + NAME_MAX + 1 ) < 0 )
                        {
                            printf("Error reading inotify event\n");
                            ret = 1;
                        }
                        break;
                    }
                }
                while (!shutting_down && !ret);
            }
            else
                sleep(1);
        }
    }
    while (!shutting_down && !ret);

    inotify_rm_watch( fd, wd );
    close(fd);

    g_thread_pool_free(pool, FALSE, TRUE);

    if ( threadid >= 0 )
        g_mutex_unlock(&locks[threadid]);

    for (i=0; i<threads; i++)
        g_mutex_clear(&locks[i]);

    xen_free_interface(xen);

    printf("Finished processing %u fuzzing inputs\n", total_processed);
    return ret;
}

