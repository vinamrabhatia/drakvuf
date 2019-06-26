#ifndef KERNEL_LIBINJECTOR_PRIVATE_H
#define KERNEL_LIBINJECTOR_PRIVATE_H

#ifdef DRAKVUF_DEBUG

extern bool verbose;

#define PRINT_DEBUG(args...) \
    do { \
        if(verbose) fprintf (stderr, args); \
    } while (0)

#else
#define PRINT_DEBUG(args...) \
    do {} while(0)
#endif

#define ARRAY_SIZE(arr) sizeof((arr)) / sizeof((arr)[0])

#ifdef __clang_analyzer__
#define vmi_free_unicode_str g_free
#endif

enum offset
{
    KTHREAD_TRAPFRAME,
    KTRAP_FRAME_RIP,

    OFFSET_MAX
};

static const char* offset_names[OFFSET_MAX][2] =
{
    [KTHREAD_TRAPFRAME] = {"_KTHREAD", "TrapFrame" },
    [KTRAP_FRAME_RIP] = {"_KTRAP_FRAME", "Rip" },
};

#endif  /KERNEL_LIBINJECTOR_PRIVATE_H
