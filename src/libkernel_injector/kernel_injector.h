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

typedef enum
{
    ARGUMENT_STRING,
    ARGUMENT_STRUCT,
    ARGUMENT_INT,
    __ARGUMENT_MAX
} argument_type_t;

typedef enum
{
    STATUS_NULL,
    STATUS_ALLOC_OK,
    STATUS_PHYS_ALLOC_OK,
    STATUS_WRITE_OK,
    STATUS_EXEC_OK,
    STATUS_BP_HIT,
    STATUS_CREATE_OK,
    STATUS_RESUME_OK,
    __STATUS_MAX
} status_type_t;

struct argument
{
    uint32_t type;
    uint32_t size;
    uint64_t data_on_stack;
    void* data;
};


void init_argument(struct argument* arg,
                   argument_type_t type,
                   size_t size,
                   void* data);

void init_int_argument(struct argument* arg,
                       uint64_t value);

void init_unicode_argument(struct argument* arg,
                           unicode_string_t* us);

#define init_struct_argument(arg, sv) \
    init_argument((arg), ARGUMENT_STRUCT, sizeof((sv)), (void*)&(sv))

bool setup_stack(drakvuf_t drakvuf,
                 drakvuf_trap_info_t* info,
                 struct argument args[],
                 int nb_args);

bool setup_stack_locked(drakvuf_t drakvuf,
                        vmi_instance_t vmi,
                        drakvuf_trap_info_t* info,
                        struct argument args[],
                        int nb_args);

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
    output_format_t format,
    char* function_name,
    int number_of_arguments,
    struct argument args[],
    unicode_string_t* string_args[],
    int number_of_string_args);


#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif //KERNEL_LIBINJECTOR_H
