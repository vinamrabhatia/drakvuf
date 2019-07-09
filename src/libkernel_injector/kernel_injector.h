#ifndef KERNEL_LIBINJECTOR_H
#define KERNEL_LIBINJECTOR_H

#include <glib.h>
#include <config.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>
#include <libdrakvuf/libdrakvuf.h>

#include "private.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

typedef struct kernel_injector* kernel_injector_t;

class syscalls
{

private:
    GSList* traps;

public:
    uint8_t reg_size;
    output_format_t format;
    os_t os;

    syscalls(drakvuf_t drakvuf, output_format_t output, kernel_injector_t kernel_injector);
    ~syscalls();
};

int kernel_injector_start(
    drakvuf_t drakvuf,
    output_format_t format);
//TODO: Add arguments and the function you want to call. 


#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif //KERNEL_LIBINJECTOR_H
