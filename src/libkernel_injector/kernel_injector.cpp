

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>

#include "kernel_injector.h"
#include "../plugins/syscalls/winscproto.h"

struct kernel_injector
{
    // Inputs:
    bool break_loop_on_detection;

    // Internal:
    drakvuf_t drakvuf;
    bool is32bit, hijacked, resumed, detected;
    bool global_search;
    addr_t exec_func;
    reg_t target_rsp;

    // For create process
    addr_t resume_thread;
    uint32_t status;
    addr_t trap_pa;

    // Syscalls related
    syscalls*        sc;
    int              syscall_index;
    uint32_t         flags;
    struct symbol*   function_symbol;

    addr_t process_info;
    x86_registers_t saved_regs;

    drakvuf_trap_t bp;
    GSList* memtraps;

    // Results:
    int rc;
    struct
    {
        bool valid;
        uint32_t code;
        const char* string;
    } error_code;

    uint32_t pid, tid;
    uint64_t hProc, hThr;
};

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
    PRINT_DEBUG("%u\n", format);
    printf("[SYSCALL] TIME:" FORMAT_TIMEVAL " VCPU:%" PRIu32 " CR3:0x%" PRIx64 ",\"%s\" %s:%" PRIi64" %s!%s",
                   UNPACK_TIMEVAL(info->timestamp), info->vcpu, info->regs->cr3, info->proc_data.name,
                   USERIDSTR(drakvuf), info->proc_data.userid,
                   info->trap->breakpoint.module, info->trap->name);
}

static void print_nargs(output_format_t format, uint32_t nargs)
{
    PRINT_DEBUG("%u\n", format);
    printf(" Arguments: %" PRIu32 "\n", nargs);
}


static void print_default_arg(syscalls* s, drakvuf_t drakvuf, drakvuf_trap_info_t* info, const arg_t& arg, addr_t val, const char* str)
{
    printf("\t %p %p" ,&drakvuf, info);
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

static bool setup_create_process_stack(kernel_injector_t kernel_injector, drakvuf_trap_info_t* info, unsigned int nargs)
{
    struct argument args[20] = { {0} };
    printf("%d\n", nargs);

    // CreateProcess(NULL, TARGETPROC, NULL, NULL, 0, 0, NULL, NULL, &si, pi))
    //init_int_argument(&args[0], 0);
    //init_int_argument(&args[1], 0);
    //init_int_argument(&args[2], 0);
    //nit_int_argument(&args[3], 0);
    //init_int_argument(&args[4], 0);
    nargs = 0;

    bool success = setup_stack(kernel_injector->drakvuf, info, args, ARRAY_SIZE(args));
    return success;
}

static event_response_t win_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{

    kernel_injector_t kernel_injector = (kernel_injector_t) info->trap->data;

    if (!kernel_injector->hijacked && kernel_injector->status == STATUS_NULL){
        bool success = false;
        unsigned int nargs = 0;
        size_t size = 0;
        void* buf = NULL; // pointer to buffer to hold argument values

        syscalls* s = kernel_injector->sc;
        const syscall_t* sc = NULL;
        kernel_injector->trap_pa = info->trap_pa;
        PRINT_DEBUG("Trapping happening at the point%lxn", info->trap_pa);
        PRINT_DEBUG("Symbol Name, would be weird%p\n", kernel_injector->function_symbol->name);
        PRINT_DEBUG("Syscall Index: %d\n", kernel_injector->syscall_index);
        PRINT_DEBUG("%s\n", kernel_injector->function_symbol->name);
        PRINT_DEBUG("Symbol RVA %lu\n", kernel_injector->function_symbol->rva);
        memcpy(&kernel_injector->saved_regs, info->regs, sizeof(x86_registers_t));

        addr_t ntoskrnl = drakvuf_get_kernel_base(drakvuf);
        addr_t pa = ntoskrnl + kernel_injector->function_symbol->rva;

        if (kernel_injector->syscall_index>-1 )
        {
            // need to malloc buf before setting type of each array cell
            sc = &win_syscalls[kernel_injector->syscall_index];
            nargs = sc->num_args;
            size = s->reg_size * nargs;
            buf = (unsigned char*)g_malloc(sizeof(char)*size);
        }
        nargs=5; //TODO: getting this from input/dictionary

        //The code works fine with calling a function without any arguments
        //Now trying to call a function with the arguments; calling CreateProcessA!
        success = setup_create_process_stack(kernel_injector, info, nargs);
        kernel_injector->target_rsp = info->regs->rsp;
        PRINT_DEBUG("Setting up stack is done!\n");
        if (!success)
        {
            PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
            return 0;
        }

        kernel_injector->status = STATUS_CREATE_OK;
        kernel_injector->hijacked = true;

        PRINT_DEBUG("Fucntion address is :%lu\n", pa);
        info->regs->rip = pa;
        return VMI_EVENT_RESPONSE_SET_REGISTERS;

        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(kernel_injector->drakvuf);

        access_context_t ctx;
        ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
        ctx.dtb = info->regs->cr3;
        ctx.addr = pa;

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

    exit:
        g_free(buf);
        drakvuf_release_vmi(drakvuf);
        return 0;
    }   


    if (kernel_injector->status == STATUS_CREATE_OK && kernel_injector->trap_pa == info->trap_pa)
    {
        // We are now in the return path from CreateProcessW

        PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);

        uint32_t threadid = 0;
        if (!drakvuf_get_current_thread_id(kernel_injector->drakvuf, info, &threadid) || !threadid)
            return false;
        PRINT_DEBUG("Thread ID:%d\n", threadid);

        
        PRINT_DEBUG("WE are here, make arrangements to check if return value is correct. \n");


        //kernel_injector->rc = info->regs->rax;
        memcpy(info->regs, &kernel_injector->saved_regs, sizeof(x86_registers_t));

        drakvuf_remove_trap(drakvuf, info->trap, NULL);
        drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }
    else if (kernel_injector->status == STATUS_CREATE_OK){
        PRINT_DEBUG("Multi breakpoints mess up!");
    }
    return 0;
}


static GSList* create_trap_config(drakvuf_t drakvuf, syscalls* s, symbols_t* symbols, kernel_injector_t kernel_injector)
{

    GSList* ret = NULL;
    unsigned long i;
    unsigned long j;

    PRINT_DEBUG("Received %lu symbols\n", symbols->count);
    struct symbol* function_symbol = (struct symbol*)g_malloc(sizeof(struct symbol));

    if ( s->os == VMI_OS_WINDOWS )
    {
        addr_t ntoskrnl = drakvuf_get_kernel_base(drakvuf);

        if ( !ntoskrnl )
            return NULL;

        for (i=0; i < symbols->count; i++)
        {
            struct symbol* symbol = &symbols->symbols[i];

            //For now, taking a fixed function!!
            if(!strncmp(symbol->name, "KeGetCurrentThread\0", 19)){
                PRINT_DEBUG("%s\n", symbol->name);
                memcpy(function_symbol, symbol, sizeof(struct symbol));
                continue;
            }

            if (strncmp(symbol->name, "Nt", 2))
                continue;

            PRINT_DEBUG("[SYSCALLS] Adding trap to %s\n", symbol->name);

            //syscall_wrapper_t* wrapper = (syscall_wrapper_t*)g_malloc(sizeof(syscall_wrapper_t));

            kernel_injector->syscall_index = -1;
            kernel_injector->sc=s;
            kernel_injector->function_symbol=function_symbol;

            for (j=0; j<NUM_SYSCALLS_WIN; j++)
            {
                if ( !strcmp(symbol->name,win_syscalls[j].name) )
                {
                    kernel_injector->syscall_index=j;
                    break;
                }
            }

            if ( kernel_injector->syscall_index==-1 )
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
            trap->data = kernel_injector;          

            ret = g_slist_prepend(ret, trap);
            //PRINT_DEBUG("NAME: %s\n", wrapper->function_symbol->name);
            //PRINT_DEBUG("%p\n", wrapper->function_symbol);
            //PRINT_DEBUG("%p\n", wrapper->function_symbol->name);
            //PRINT_DEBUG("%lu\n", wrapper->function_symbol->rva);
        }
    }

    return ret;
}


syscalls::syscalls(drakvuf_t drakvuf , output_format_t output, kernel_injector_t kernel_injector)
{
    symbols_t* symbols = drakvuf_get_symbols_from_rekall(drakvuf);

    if (!symbols)
    {
        fprintf(stderr, "Failed to get symbols from Rekall profile\n");
        throw -1;
    }

    this->os = drakvuf_get_os_type(drakvuf);
    this->traps = create_trap_config(drakvuf, this, symbols, kernel_injector);
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
    //PRINT_DEBUG("Target PID %u to start '%s'\n", pid, file);
    kernel_injector_t kernel_injector = (kernel_injector_t)g_malloc0(sizeof(struct kernel_injector));

    //Initialising Injector Function
    kernel_injector->drakvuf = drakvuf;
    kernel_injector->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    kernel_injector->error_code.valid = false;
    kernel_injector->error_code.code = -1;
    kernel_injector->error_code.string = "<UNKNOWN>";

    //Setting up the breakpoints at the common syscalls. 
    syscalls* sc = new syscalls(drakvuf, format, kernel_injector);
    PRINT_DEBUG("%d\n",sc->reg_size);

    /* Start the event listener */
    drakvuf_loop(drakvuf);

    // //TODO: free injector as well

    return rc;
}
