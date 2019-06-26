//First, we make the traps to happen via Syscalls Plugin.
//Later we checkout the injector

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>

#include "kernel-injector.h"
#include "../plugins/syscalls/winscproto.h"

static char* extract_string(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val)
{
    if ( arg.dir == DIR_IN || arg.dir == DIR_INOUT )
    {
        if ( arg.type == PUNICODE_STRING )
        {
            unicode_string_t* us = drakvuf_read_unicode(drakvuf, info, val);
            if ( us )
            {
                char* str = (char*)us->contents;
                us->contents = nullptr;
                vmi_free_unicode_str(us);
                return str;
            }
        }

        else if ( arg.type == PCHAR )
        {
            char* str = drakvuf_read_ascii_str(drakvuf, info, val);
            return str;
        }

        if ( !strcmp(arg.name, "FileHandle") )
        {
            char* filename = drakvuf_get_filename_from_handle(drakvuf, info, val);
            if ( filename ) return filename;
        }
    }

    return nullptr;
}

static void print_header(output_format_t format, drakvuf_t drakvuf, const drakvuf_trap_info_t* info)
{
    printf("[SYSCALL] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64" %s!%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   info->trap->breakpoint.module, info->trap->name);
}

static void print_nargs(output_format_t format, uint32_t nargs)
{
    printf(" Arguments: %" PRIu32 "\n", nargs);
}


static void print_default_arg(syscalls* s, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val, const char* str)
{
    printf("\t%s %s %s: ", arg_direction_names[arg.dir], type_names[arg.type], arg.name);

    if ( 4 == s->reg_size )
        printf("0x%" PRIx32, static_cast<uint32_t>(val));
    else
        printf("0x%" PRIx64, static_cast<uint64_t>(val));

    if ( str )
    {
        printf(" -> '%s'", str);
    }

    printf("\n");
}

static void print_args(syscalls* s, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const syscall_t* sc, void* args_data)
{
    size_t nargs = sc->num_args;
    uint32_t* args_data32 = (uint32_t*)args_data;
    uint64_t* args_data64 = (uint64_t*)args_data;

    for ( size_t i=0; i<nargs; i++ )
    {
        addr_t val = 0;

        if ( 4 == s->reg_size )
            memcpy(&val, &args_data32[i], sizeof(uint32_t));
        else
            memcpy(&val, &args_data64[i], sizeof(uint64_t));

        char* str = extract_string(drakvuf, info, sc->args[i], val);

        print_default_arg(s, drakvuf, info, sc->args[i], val, str);

        g_free(str);
    }
}

static void print_footer(output_format_t format, uint32_t nargs)
{
	if ( nargs == 0)
		printf("\n");
}


static event_response_t win_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    unsigned int nargs = 0;
    size_t size = 0;
    void* buf = NULL; // pointer to buffer to hold argument values

    syscall_wrapper_t* wrapper = (syscall_wrapper_t*)info->trap->data;
    syscalls* s = wrapper->sc;
    const syscall_t* sc = NULL;

    if (wrapper->syscall_index>-1 )
    {
        // need to malloc buf before setting type of each array cell
        sc = &win_syscalls[wrapper->syscall_index];
        nargs = sc->num_args;
        size = s->reg_size * nargs;
        buf = (unsigned char*)g_malloc(sizeof(char)*size);
    }

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    access_context_t ctx;
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    if ( nargs )
    {
        // get arguments only if we know how many to get

        if ( 4 == s->reg_size )
        {
            // 32 bit os
            ctx.addr = info->regs->rsp + s->reg_size;  // jump over base pointer

            // multiply num args by 4 for 32 bit systems to get the number of bytes we need
            // to read from the stack.  assumes standard calling convention (cdecl) for the
            // visual studio compile.
            if ( VMI_FAILURE == vmi_read(vmi, &ctx, size, buf, NULL) )
                goto exit;
        }
        else
        {
            // 64 bit os
            uint64_t* buf64 = (uint64_t*)buf;
            if ( nargs > 0 )
                buf64[0] = info->regs->rcx;
            if ( nargs > 1 )
                buf64[1] = info->regs->rdx;
            if ( nargs > 2 )
                buf64[2] = info->regs->r8;
            if ( nargs > 3 )
                buf64[3] = info->regs->r9;
            if ( nargs > 4 )
            {
                // first 4 agrs passed via rcx, rdx, r8, and r9
                ctx.addr = info->regs->rsp+0x28;  // jump over homing space + base pointer
                size_t sp_size = s->reg_size * (nargs-4);
                if ( VMI_FAILURE == vmi_read(vmi, &ctx, sp_size, &(buf64[4]), NULL) )
                    goto exit;
            }
        }
    }

    print_header(s->format, drakvuf, info);
    if ( nargs )
    {
        print_nargs(s->format, nargs);
        print_args(s, drakvuf, info, sc, buf);
    }
    print_footer(s->format, nargs);

exit:
    g_free(buf);
    drakvuf_release_vmi(drakvuf);
    return 0;
}


static GSList* create_trap_config(drakvuf_t drakvuf, syscalls* s, symbols_t* symbols)
{

    GSList* ret = NULL;
    unsigned long i;
    unsigned long j;

    PRINT_DEBUG("Received %lu symbols\n", symbols->count);

    if ( s->os == VMI_OS_WINDOWS )
    {
        addr_t ntoskrnl = drakvuf_get_kernel_base(drakvuf);

        if ( !ntoskrnl )
            return NULL;

        for (i=0; i < symbols->count; i++)
        {
            const struct symbol* symbol = &symbols->symbols[i];

            if (strncmp(symbol->name, "Nt", 2))
                continue;

            PRINT_DEBUG("[SYSCALLS] Adding trap to %s\n", symbol->name);

            syscall_wrapper_t* wrapper = (syscall_wrapper_t*)g_malloc(sizeof(syscall_wrapper_t));

            wrapper->syscall_index = -1;
            wrapper->sc=s;

            for (j=0; j<NUM_SYSCALLS_WIN; j++)
            {
                if ( !strcmp(symbol->name,win_syscalls[j].name) )
                {
                    wrapper->syscall_index=j;
                    break;
                }
            }

            if ( wrapper->syscall_index==-1 )
                PRINT_DEBUG("[SYSCALLS]: %s not found in argument list\n", symbol->name);

            drakvuf_trap_t* trap = (drakvuf_trap_t*)g_malloc0(sizeof(drakvuf_trap_t));
            trap->breakpoint.lookup_type = LOOKUP_PID;
            trap->breakpoint.pid = 4;
            trap->breakpoint.addr_type = ADDR_VA;
            trap->breakpoint.addr = ntoskrnl + symbol->rva;
            trap->breakpoint.module = "ntoskrnl.exe";
            trap->name = g_strdup(symbol->name);
            trap->type = BREAKPOINT;
            trap->cb = win_cb;
            trap->data = wrapper;

            ret = g_slist_prepend(ret, trap);
        }
    }

    return ret;
}


syscalls::syscalls(drakvuf_t drakvuf , output_format_t output)
{
    symbols_t* symbols = drakvuf_get_symbols_from_rekall(drakvuf);
    if (!symbols)
    {
        fprintf(stderr, "Failed to get symbols from Rekall profile\n");
        throw -1;
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
