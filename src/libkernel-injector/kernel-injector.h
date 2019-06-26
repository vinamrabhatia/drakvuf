#ifndef KERNEL_LIBINJECTOR_H
#define KERNEL_LIBINJECTOR_H

#include <glib.h>
#include <config.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>
#include <libdrakvuf/libdrakvuf.h>

#include "private.h"

class syscalls
{

private:
    GSList* traps;

public:
    uint8_t reg_size;
    output_format_t format;
    os_t os;

    syscalls(drakvuf_t drakvuf, const syscalls_config* config, output_format_t output);
    ~syscalls();
};

#endif //KERNEL_LIBINJECTOR_H

/