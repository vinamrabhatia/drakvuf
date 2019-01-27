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

static event_response_t int3_x64_trapframe_entry(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
static event_response_t int3_x64_createprocess_ret(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
static event_response_t int3_x64_resumethread_ret(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
/*static event_response_t int3_x86_createprocess(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
static event_response_t int3_x86_resumethread(drakvuf_t drakvuf, drakvuf_trap_info_t* info);*/
static event_response_t mem_callback_x86(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

bool init_createprocess(injector_t injector, addr_t eprocess_base)
{
    injector->resume_thread = get_function_va(injector->drakvuf, eprocess_base, "kernel32.dll", "ResumeThread");
    if (!injector->resume_thread)
        return false;

    injector->exec_func = get_function_va(injector->drakvuf, eprocess_base, "kernel32.dll", "CreateProcessW");
    injector->cr3_wait_for_target.cb = cr3_createprocess_wait_for_target_cb;
    return true;
}

static void setup_catch_target_usermode_x64(injector_t injector, addr_t cr3, addr_t thread_base)
{
    drakvuf_t drakvuf = injector->drakvuf;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    addr_t trapframe = 0;

    status_t status = vmi_read_addr_va(vmi,
                              thread_base + injector->offsets[KTHREAD_TRAPFRAME],
                              0, &trapframe);
    if (status == VMI_FAILURE || !trapframe)
    {
        PRINT_DEBUG("cr3_cb: failed to read trapframe (0x%lx)\n", trapframe);
        goto done;
    }

    addr_t bp_addr = 0;
    status = vmi_read_addr_va(vmi,
                              trapframe + injector->offsets[KTRAP_FRAME_RIP],
                              0, &bp_addr);

    if (status == VMI_FAILURE || !bp_addr)
    {
        PRINT_DEBUG("Failed to read RIP from trapframe or RIP is NULL!\n");
        goto done;
    }

    drakvuf_trap_t* new_trap = g_malloc0(sizeof(drakvuf_trap_t));
    new_trap->type = BREAKPOINT;
    new_trap->name = "entry";
    new_trap->cb = int3_x64_trapframe_entry;
    new_trap->data = injector;

    new_trap->breakpoint.lookup_type = LOOKUP_DTB;
    new_trap->breakpoint.dtb = cr3;
    new_trap->breakpoint.addr_type = ADDR_VA;
    new_trap->breakpoint.addr = bp_addr;

    if ( drakvuf_add_trap(injector->drakvuf, new_trap) )
    {
        PRINT_DEBUG("Got return address 0x%lx from trapframe and it's now breakpointed!\n", bp_addr);
        injector->traps = g_slist_prepend(injector->traps, new_trap);
    }
    else
    {
        PRINT_DEBUG("Got return address 0x%lx from trapframe but couldn't breakpoint it!\n", bp_addr);
        g_free(new_trap);
    }

done:
    drakvuf_release_vmi(drakvuf);
    return;
}

static void setup_catch_target_usermode_x86(injector_t injector, addr_t cr3)
{
    drakvuf_t drakvuf = injector->drakvuf;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    drakvuf_pause(drakvuf);

    GSList* va_pages = vmi_get_va_pages(vmi, cr3);
    GSList* loop = va_pages;
    while (loop)
    {
        page_info_t* page = loop->data;
        if (page->vaddr < 0x80000000 && USER_SUPERVISOR(page->x86_pae.pte_value))
        {
            drakvuf_trap_t* new_trap = g_malloc0(sizeof(drakvuf_trap_t));
            new_trap->type = MEMACCESS;
            new_trap->cb = mem_callback_x86;
            new_trap->data = injector;
            new_trap->memaccess.access = VMI_MEMACCESS_X;
            new_trap->memaccess.type = POST;
            new_trap->memaccess.gfn = page->paddr >> 12;
            if ( drakvuf_add_trap(injector->drakvuf, new_trap) )
                injector->traps = g_slist_prepend(injector->traps, new_trap);
            else
                g_free(new_trap);
        }
        g_free(page);
        loop = loop->next;
    }
    g_slist_free(va_pages);

    drakvuf_resume(drakvuf);
    drakvuf_release_vmi(drakvuf);
}

event_response_t cr3_createprocess_wait_for_target_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 ". PID: %u PPID: %u\n",
                info->regs->cr3, info->proc_data.pid, info->proc_data.ppid);

    if (info->regs->cr3 != injector->target_cr3)
        return 0;

    addr_t thread = drakvuf_get_current_thread(drakvuf, info->vcpu);
    if (!thread)
    {
        PRINT_DEBUG("Failed to find current thread\n");
        return 0;
    }

    uint32_t threadid = 0;
    if ( !drakvuf_get_current_thread_id(injector->drakvuf, info->vcpu, &threadid) || !threadid )
        return 0;

    PRINT_DEBUG("Thread @ 0x%lx. ThreadID: %u\n", thread, threadid);

    if (injector->target_tid && injector->target_tid != threadid)
        return 0;

    // Unsubscribe from the CR3 trap
    PRINT_DEBUG("Target identified, removing CR3 listener and setting up usermode traps\n");
    drakvuf_remove_trap(drakvuf, info->trap, NULL);

    /*
     * At this point the process is still in kernel mode, so
     * we need to trap when it enters into user mode.
     * For this we use different mechanisms on 32-bit and 64-bit.
     * The reason for this is that the same methods are not equally
     * reliable.
     *
     * For 64-bit Windows we use the trapframe approach, where we read
     * the saved RIP from the stack trap frame and breakpoint it.
     * When this address is hit, we hijack the flow and afterwards return
     * the registers to the original values, thus the process continues to run.
     * This method is workable on 32-bit Windows as well but finding the trapframe
     * sometimes fail for yet unknown reasons.
     */
    switch(injector->is32bit)
    {
        case true:
            setup_catch_target_usermode_x86(injector, info->regs->cr3);
            break;
        case false:
            setup_catch_target_usermode_x64(injector, info->regs->cr3, thread);
            break;
    };

    return 0;
}

static event_response_t cr3_createprocess_wait_for_injected_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    if (injector->pid != (uint32_t)info->proc_data.pid)
        return 0;

    PRINT_DEBUG("Process start detected %i -> 0x%lx\n", injector->pid, info->regs->cr3);

    drakvuf_remove_trap(drakvuf, info->trap, NULL);

    injector->rc = 1;
    injector->detected = true;

    if ( injector->break_loop_on_detection )
        drakvuf_interrupt(drakvuf, 1);
    else if ( injector->resumed )
        drakvuf_interrupt(drakvuf, 1);

    return 0;
}

static bool setup_create_process_stack(injector_t injector, drakvuf_trap_info_t* info)
{
    struct argument args[10] = { {0} };
    struct startup_info_32 si_32 = { 0 };
    struct process_information_32 pi_32 = { 0 };
    struct startup_info_64 si_64 = { 0 };
    struct process_information_64 pi_64 = { 0 };

    // CreateProcess(NULL, TARGETPROC, NULL, NULL, 0, 0, NULL, NULL, &si, pi))
    init_int_argument(&args[0], 0);
    init_unicode_argument(&args[1], injector->target_file_us);
    init_int_argument(&args[2], 0);
    init_int_argument(&args[3], 0);
    init_int_argument(&args[4], 0);
    init_int_argument(&args[5], CREATE_SUSPENDED);
    init_int_argument(&args[6], 0);
    init_unicode_argument(&args[7], injector->cwd_us);
    if (injector->is32bit)
    {
        init_struct_argument(&args[8], si_32);
        init_struct_argument(&args[9], pi_32);
    }
    else
    {
        init_struct_argument(&args[8], si_64);
        init_struct_argument(&args[9], pi_64);
    }

    bool success = setup_stack(injector->drakvuf, info, args, ARRAY_SIZE(args));
    injector->process_info = args[9].data_on_stack;
    return success;
}

static bool setup_resume_thread_stack(injector_t injector, drakvuf_trap_info_t* info)
{
    struct argument args[1] = { {0} };
    init_int_argument(&args[0], injector->hThr);

    return setup_stack(injector->drakvuf, info, args, ARRAY_SIZE(args));
}

static bool injector_set_hijacked(injector_t injector, drakvuf_trap_info_t* info)
{
    if (!injector->target_tid)
    {
        uint32_t threadid = 0;
        if (!drakvuf_get_current_thread_id(injector->drakvuf, info->vcpu, &threadid) || !threadid)
            return false;

        injector->target_tid = threadid;
    }

    injector->hijacked = true;

    return true;
}

static event_response_t mem_callback_x86(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    (void)drakvuf;
    injector_t injector = info->trap->data;

    if ( info->regs->cr3 != injector->target_cr3 )
    {
        PRINT_DEBUG("MemX received but CR3 (0x%lx) doesn't match target process (0x%lx)\n",
                    info->regs->cr3, injector->target_cr3);
        return 0;
    }

    PRINT_DEBUG("MemX at 0x%lx\n", info->regs->rip);

    /* We might have already hijacked a thread on another vCPU */
    if (injector->hijacked)
        return 0;

    free_traps(injector);

    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

    bool success = success = setup_create_process_stack(injector, info);
    injector->target_rsp = info->regs->rsp;

    if (!success)
    {
        PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
        return 0;
    }

    // TODO
    /*if (!setup_int3_trap(injector, info->regs->cr3, info->regs->rip))
    {
        fprintf(stderr, "Failed to trap return location of injected function call @ 0x%lx!\n",
                info->regs->rip);
        return 0;
    }*/

    if (!injector_set_hijacked(injector, info))
        return 0;

    PRINT_DEBUG("Stack setup finished and return trap added @ 0x%" PRIx64 "\n",
                info->regs->rip);

    info->regs->rip = injector->exec_func;
    injector->status = STATUS_CREATE_OK;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

// Setup callback for waiting for first occurence of resumed thread
static bool setup_wait_for_injected_process_trap(injector_t injector)
{
    injector->cr3_wait_for_target.cb = cr3_createprocess_wait_for_injected_process_cb;
    if (!drakvuf_add_trap(injector->drakvuf, &injector->cr3_wait_for_target))
    {
        PRINT_DEBUG("Failed to setup wait_for_injected_process trap!\n");
        return false;
    }
    PRINT_DEBUG("Waiting for injected process\n");
    return true;
}

static inline bool int3_sanity_check(injector_t injector, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx.\n", info->regs->rip, info->regs->cr3);
    drakvuf_t drakvuf = injector->drakvuf;

    if ( info->regs->cr3 != injector->target_cr3 )
    {
        PRINT_DEBUG("INT3 received but CR3 (0x%lx) doesn't match target process (0x%lx)\n",
                    info->regs->cr3, injector->target_cr3);
        PRINT_DEBUG("INT3 received from PID: %d [%s]\n",
                    info->proc_data.pid, info->proc_data.name);
        return false;
    }

    if (info->regs->rip != info->trap->breakpoint.addr)
        return false;

    if (injector->target_tid)
    {
        uint32_t threadid = 0;
        if (!drakvuf_get_current_thread_id(drakvuf, info->vcpu, &threadid) || threadid != injector->target_tid)
            return false;
    }

    if (injector->target_rsp && info->regs->rsp <= injector->target_rsp)
    {
        PRINT_DEBUG("INT3 received but RSP (0x%lx) doesn't match target rsp (0x%lx)\n",
                    info->regs->rsp, injector->target_rsp);
        return false;
    }

    return true;
}

static event_response_t int3_x64_trapframe_entry(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    if ( !int3_sanity_check(injector, info) )
        return 0;

    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

    bool success = setup_create_process_stack(injector, info);
    injector->target_rsp = info->regs->rsp;

    if (!success)
    {
        PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
        return 0;
    }

    if (!injector_set_hijacked(injector, info))
        return 0;

    injector->status = STATUS_CREATE_OK;

    info->regs->rip = injector->exec_func;
    info->trap->cb = int3_x64_createprocess_ret;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t int3_x64_createprocess_ret(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    if ( !int3_sanity_check(injector, info) )
        return 0;

    if ( !injector->hijacked )
    {
        PRINT_DEBUG("int3_x64_createprocess_ret reached without being hijacked first!\n");
        return 0;
    }

    PRINT_DEBUG("int3_x64_createprocess_ret: 0x%lx\n", info->regs->rax);

    // We are now in the return path from CreateProcessW

    if (info->regs->rax)
        fill_created_process_info(injector, info);

    injector->rc = info->regs->rax;
    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

    if (injector->pid && injector->tid)
    {
        PRINT_DEBUG("Injector created process with PID: %i. TID: %i\n", injector->pid, injector->tid);

        if (!setup_resume_thread_stack(injector, info))
        {
            PRINT_DEBUG("Injector created process but couldn't inject the resume call!\n");
            goto done;
        }

        injector->target_rsp = info->regs->rsp;

        if (!setup_wait_for_injected_process_trap(injector))
        {
            PRINT_DEBUG("Injector created process but couldn't register cr3 listener to catch resume!\n");
            goto done;
        }

        info->regs->rip = injector->resume_thread;
        info->trap->cb = int3_x64_resumethread_ret;
        injector->status = STATUS_RESUME_OK;

        return VMI_EVENT_RESPONSE_SET_REGISTERS;
    }

done:
    PRINT_DEBUG("Injector failed to inject\n");
    injector->rc = 0;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static event_response_t int3_x64_resumethread_ret(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    if ( !int3_sanity_check(injector, info) )
        return 0;

    PRINT_DEBUG("Injector int3_x64_resumethread_ret: 0x%lx\n", info->regs->rax);

    free_traps(injector);

    injector->rc = info->regs->rax;
    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

    if (injector->rc == 1)
    {
        PRINT_DEBUG("Injector resumed\n");
    }
    else
    {
        PRINT_DEBUG("Injector failed to resume\n");
        injector->rc = 0;
        drakvuf_interrupt(drakvuf, -1);
    }

    // If the injected process was already detected to be running but
    // the loop is not broken on detection, that means that resumethread
    // was the last remaining trap we were waiting for and it's time
    // to break the loop now
    //
    // If the injected processwas already detected to be running and
    // the loop is broken on detected, then we are now in a loop
    // outside the normal injection loop (ie. main drakvuf)
    // so we don't break the loop
    if ( injector->detected && !injector->break_loop_on_detection )
        drakvuf_interrupt(drakvuf, 1);

    injector->resumed = true;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

