/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
 *                                                                         *
 * DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be aquired from the author.          *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/

#include <libvmi/libvmi.h>
#include <libvmi/libvmi_extra.h>
#include <libvmi/x86.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <signal.h>
#include <inttypes.h>
#include <glib.h>
#include <json-c/json.h>

#include <libdrakvuf/libdrakvuf.h>
#include <libinjector/libinjector.h>
#include "private.h"

static const char* offset_names[OFFSET_MAX][2] =
{
    [KTHREAD_TRAPFRAME] =   { "_KTHREAD",       "TrapFrame" },
    [KTRAP_FRAME_RIP] =     { "_KTRAP_FRAME",   "Rip" },
};

static void free_injector(injector_t injector)
{
    if (!injector) return;

    PRINT_DEBUG("Injector freed\n");

    free_traps(injector);

    vmi_free_unicode_str(injector->target_file_us);
    vmi_free_unicode_str(injector->cwd_us);

    //g_free(injector->binary);
    //g_free(injector->payload);
    g_free((gpointer)injector);
}

static event_response_t cr3_wait_for_crash_of_target_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    vmi_pid_t crashed_pid = 0;
    if (drakvuf_is_crashreporter(drakvuf, info, &crashed_pid) && crashed_pid == injector->target_pid)
    {
        injector->rc = 0;
        injector->detected = false;
        PRINT_DEBUG("Target process crash detected\n");

        drakvuf_interrupt(drakvuf, -1);
    }

    return 0;
}

static bool inject(drakvuf_t drakvuf, injector_t injector)
{
    injector->hijacked = 0;
    injector->status = STATUS_NULL;

    if (!drakvuf_add_trap(drakvuf, &injector->cr3_wait_for_target))
        return false;

    drakvuf_trap_t trap_crashreporter =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = cr3_wait_for_crash_of_target_process,
        .data = injector,
    };
    if (!drakvuf_add_trap(drakvuf, &trap_crashreporter))
        return false;

    if (!drakvuf_is_interrupted(drakvuf))
    {
        PRINT_DEBUG("Starting injection loop\n");
        drakvuf_loop(drakvuf);
    }

    drakvuf_remove_trap(drakvuf, &injector->cr3_wait_for_target, NULL);
    drakvuf_remove_trap(drakvuf, &trap_crashreporter, NULL);

    return true;
}

/*static bool load_file_to_memory(gpointer* output, size_t* size, const char* file)
{
    size_t payload_size = 0;
    unsigned char* data = NULL;
    FILE* fp = fopen(file, "rb");

    if (!fp)
        return false;

    // obtain file size:
    fseek (fp, 0, SEEK_END);
    payload_size = ftell (fp);
    rewind (fp);

    data = g_malloc0(payload_size);
    if ( !data )
    {
        fclose(fp);
        return false;
    }

    if ( payload_size != fread(data, payload_size, 1, fp) )
    {
        g_free(data);
        fclose(fp);
        return false;
    }

    *output = data;
    *size = payload_size;

    PRINT_DEBUG("Size of file read: %lu\n", payload_size);

    fclose(fp);

    return true;
}*/

static void print_injection_info(output_format_t format, vmi_pid_t pid, uint64_t dtb, const char* file, vmi_pid_t injected_pid, uint32_t injected_tid)
{
    GTimeVal t;
    g_get_current_time(&t);

    char* process_name = NULL;
    char* arguments = NULL;

    char* splitter = " ";
    const char* begin_proc_name = &file[0];

    if (file[0] == '"')
    {
        splitter = "\"";
        begin_proc_name = &file[1];
    }

    char** split_results = g_strsplit_set(begin_proc_name, splitter, 2);
    char** split_results_iterator = split_results;

    if (*split_results_iterator)
    {
        process_name = *(split_results_iterator++);
    }

    if (*split_results_iterator)
    {
        arguments = *(split_results_iterator++);
        if (arguments[0] == ' ')
            arguments++;
    }
    else
    {
        arguments = "";
    }

    char* escaped_arguments = g_strescape(arguments, NULL);

    switch (format)
    {
        case OUTPUT_CSV:
            printf("inject," FORMAT_TIMEVAL ",%u,0x%lx,\"%s\",\"%s\",%u,%u\n",
                   UNPACK_TIMEVAL(t), pid, dtb, process_name, escaped_arguments, injected_pid, injected_tid);
            break;

        case OUTPUT_KV:
            printf("inject Time=" FORMAT_TIMEVAL ",PID=%u,DTB=0x%lx,ProcessName=\"%s\",Arguments=\"%s\",InjectedPid=%u,InjectedTid=%u\n",
                   UNPACK_TIMEVAL(t), pid, dtb, process_name, escaped_arguments, injected_pid, injected_tid);
            break;

        default:
        case OUTPUT_DEFAULT:
            printf("[INJECT] TIME:" FORMAT_TIMEVAL " PID:%u DTB:0x%lx FILE:\"%s\" ARGUMENTS:\"%s\" INJECTED_PID:%u INJECTED_TID:%u\n",
                   UNPACK_TIMEVAL(t), pid, dtb, process_name, escaped_arguments, injected_pid, injected_tid);
            break;
    }

    g_free(escaped_arguments);
    g_strfreev(split_results);
}

static inline bool get_dtb_for_pid(drakvuf_t drakvuf, vmi_pid_t pid, reg_t* p_target_cr3)
{
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool success = ( VMI_FAILURE != vmi_pid_to_dtb(vmi, pid, p_target_cr3) );
    drakvuf_release_vmi(drakvuf);
    return success;
}

static bool initialize_injector_functions(injector_t injector, const char* file, const char* binary_path)
{
    addr_t eprocess_base = 0;
    drakvuf_t drakvuf = injector->drakvuf;

    if ( !drakvuf_find_process(drakvuf, injector->target_pid, NULL, &eprocess_base) )
        return false;

    // Get the offsets from the Rekall profile
    if ( !drakvuf_get_struct_members_array_rva(drakvuf, offset_names, OFFSET_MAX, injector->offsets) )
        PRINT_DEBUG("Failed to find one of offsets.\n");

    switch(injector->method) {
        default:
            return false;

        case INJECT_METHOD_CREATEPROC:
            if ( !init_createprocess(injector, eprocess_base) )
                return false;
            break;

        case INJECT_METHOD_SHELLEXEC:
            injector->exec_func = get_function_va(drakvuf, eprocess_base, "shell32.dll", "ShellExecuteW");
            break;

        /*case INJECT_METHOD_SHELLCODE:
            // Read shellcode from a file
            if ( !load_file_to_memory(&injector->payload, &injector->payload_size, file) )
                return false;

            injector->memset = get_function_va(drakvuf, eprocess_base, "ntdll.dll", "memset");
            if (!injector->memset)
                return false;

            injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "VirtualAlloc");
            break;

#ifdef ENABLE_DOPPELGANGING
        case INJECT_METHOD_DOPP:
            // Check for Windows 10 version 1803 or higher
            int build_1803 = 20180410;
            if ( drakvuf_get_os_build_date(drakvuf) < build_1803 )
            {
                PRINT_DEBUG("This injection method requires Windows 10 version 1803 or higher!\n");
                return false;
            }

            // Read binary to inject from a file
            if ( !load_file_to_memory(&injector->binary, &injector->binary_size, binary_path) )
                return false;

            // Read shellcode from a file
            if ( !load_file_to_memory(&injector->payload, &injector->payload_size, file) )
                return false;

            injector->memset = get_function_va(drakvuf, eprocess_base, "ntdll.dll", "memset");
            if (!injector->memset)
                return false;

            injector->exec_func = get_function_va(drakvuf, eprocess_base, "kernel32.dll", "VirtualAlloc");
            break;
#endif*/
    };

    return injector->exec_func != 0;
}

int injector_start_app(
    drakvuf_t drakvuf,
    vmi_pid_t pid,
    uint32_t tid,
    const char* file,
    const char* cwd,
    injection_method_t method,
    output_format_t format,
    const char* binary_path,
    const char* target_process,
    bool break_loop_on_detection,
    injector_t *to_be_freed_later)
{
    int rc = 0;
    addr_t cr3;
    if (!get_dtb_for_pid(drakvuf, pid, &cr3))
    {
        PRINT_DEBUG("Unable to find target PID's DTB\n");
        return 0;
    }

    PRINT_DEBUG("Target PID %u with DTB 0x%lx to start '%s'\n", pid, cr3, file);

    unicode_string_t* target_file_us = convert_utf8_to_utf16(file);
    if (!target_file_us)
    {
        PRINT_DEBUG("Unable to convert file path from utf8 to utf16\n");
        return 0;
    }

    unicode_string_t* cwd_us = NULL;
    if (cwd)
    {
        cwd_us = convert_utf8_to_utf16(cwd);
        if (!cwd_us)
        {
            PRINT_DEBUG("Unable to convert cwd from utf8 to utf16\n");
            vmi_free_unicode_str(target_file_us);
            return 0;
        }
    }

    injector_t injector = (injector_t)g_malloc0(sizeof(struct injector));
    if (!injector)
    {
        vmi_free_unicode_str(target_file_us);
        vmi_free_unicode_str(cwd_us);
        return 0;
    }

    injector->drakvuf = drakvuf;
    injector->target_pid = pid;
    injector->target_tid = tid;
    injector->target_cr3 = cr3;
    injector->target_file_us = target_file_us;
    injector->cwd_us = cwd_us;
    injector->method = method;
    injector->binary_path = binary_path;
    injector->target_process = target_process;
    injector->status = STATUS_NULL;
    injector->is32bit = (drakvuf_get_page_mode(drakvuf) != VMI_PM_IA32E);
    injector->break_loop_on_detection = break_loop_on_detection;

    injector->cr3_wait_for_target.type = REGISTER;
    injector->cr3_wait_for_target.reg = CR3;
    injector->cr3_wait_for_target.data = injector;

    if (!initialize_injector_functions(injector, file, binary_path))
    {
        PRINT_DEBUG("Unable to initialize injector functions\n");
        free_injector(injector);
        return 0;
    }

    if (inject(drakvuf, injector))
        print_injection_info(format, injector->target_pid, injector->target_cr3, file, injector->pid, injector->tid);

    rc = injector->rc;
    PRINT_DEBUG("Finished with injection. Ret: %i\n", rc);

    switch (method) {
        case INJECT_METHOD_CREATEPROC:
            if ( break_loop_on_detection )
                if ( injector->resumed && injector->detected )
                {
                    free_injector(injector);
                }
                else
                {
                    *to_be_freed_later = injector;
                }
            else
                free_injector(injector);
            break;
        default:
            free_injector(injector);
            break;
    };

    return rc;
}
