//First, we make the traps to happen via Syscalls Plugin.
//Later we checkout the injector

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>

#include "kernel-injector.h"
#include "../plugins/syscalls/winscproto.h"


syscalls::syscalls(drakvuf_t drakvuf, const syscalls_config* c, output_format_t output)
{
    symbols_t* symbols = drakvuf_get_symbols_from_rekall(drakvuf);
    if (!symbols)
    {
        fprintf(stderr, "Failed to get symbols from Rekall profile\n");
        throw -1;
    }

    if (c->syscalls_filter_file)
    {
        symbols_t* filtered_symbols = filter_symbols(symbols, c->syscalls_filter_file);
        drakvuf_free_symbols(symbols);
        if (!filtered_symbols)
        {
            fprintf(stderr, "Failed to apply syscalls filter %s\n", c->syscalls_filter_file);
            throw -1;
        }
        symbols = filtered_symbols;
    }

    this->os = drakvuf_get_os_type(drakvuf);
    this->traps = create_trap_config(drakvuf, this, symbols);
    this->format = output;

    if ( !this->traps )
    {
        drakvuf_free_symbols(symbols);
        throw -1;
    }

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    this->reg_size = vmi_get_address_width(vmi); // 4 or 8 (bytes)
    drakvuf_release_vmi(drakvuf);

    drakvuf_free_symbols(symbols);

    bool error = 0;
    GSList* loop = this->traps;
    while (loop)
    {
        drakvuf_trap_t* trap = (drakvuf_trap_t*)loop->data;

        if ( !drakvuf_add_trap(drakvuf, trap) )
        {
            error = 1;
            break;
        }

        loop = loop->next;
    }

    if ( error )
    {
        loop = this->traps;
        while (loop)
        {
            drakvuf_trap_t* trap = (drakvuf_trap_t*)loop->data;
            drakvuf_remove_trap(drakvuf, trap, NULL);
            g_free(trap->data);
            g_free((gpointer)trap->name);
            g_free(trap);
            loop = loop->next;
        }

        g_slist_free(this->traps);
        this->traps = NULL;

        throw -1;
    }
}

syscalls::~syscalls()
{
    GSList* loop = this->traps;
    while (loop)
    {
        drakvuf_trap_t* trap = (drakvuf_trap_t*)loop->data;
        g_free(trap->_name);
        if (trap->data != (void*)this)
        {
            g_free(trap->data);
        }
        g_free(loop->data);
        loop = loop->next;
    }

    g_slist_free(this->traps);
}


int kernel_injector_start(
    drakvuf_t drakvuf,
    output_format_t format)
{
    int rc = 0;
    PRINT_DEBUG("Target PID %u to start '%s'\n", pid, file);

    //Setting up the breakpoints at the common syscalls. 
    syscalls sc = new syscalls(drakvuf, format);


    return rc;
}
