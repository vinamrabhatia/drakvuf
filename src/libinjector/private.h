/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
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

#ifndef LIBINJECTOR_PRIVATE_H
#define LIBINJECTOR_PRIVATE_H

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

#define SW_SHOWNORMAL           1
#define MEM_COMMIT              0x00001000
#define MEM_RESERVE             0x00002000
#define MEM_PHYSICAL            0x00400000
#define PAGE_EXECUTE_READWRITE  0x40
#define CREATE_SUSPENDED        0x00000004

enum offset
{
    KTHREAD_TRAPFRAME,
    KTRAP_FRAME_RIP,

    OFFSET_MAX
};

struct injector
{
    // Inputs:
    unicode_string_t* target_file_us;
    reg_t target_cr3;
    vmi_pid_t target_pid;
    uint32_t target_tid;
    unicode_string_t* cwd_us;
    bool break_loop_on_detection;

    // Internal:
    drakvuf_t drakvuf;
    bool is32bit, hijacked, resumed, detected;
    injection_method_t method;
    addr_t exec_func;
    reg_t target_rsp;

    union {
        // For create process
        struct {
            addr_t resume_thread;
        };

        // For shellcode execution
        struct {
            gpointer payload;
            addr_t payload_addr, memset;
            size_t binary_size, payload_size;
        };

        // For process doppelganging shellcode
        struct {
            gpointer binary;
            addr_t binary_addr, saved_bp, process_notify;
        };
    };

    uint32_t status;

    const char* binary_path;
    const char* target_process;

    addr_t process_info;
    x86_registers_t saved_regs;

    drakvuf_trap_t cr3_wait_for_target;
    GSList* traps;

    size_t offsets[OFFSET_MAX];

    // Results:
    int rc;
    uint32_t pid, tid;
    uint64_t hProc, hThr;
};

struct startup_info_32
{
    uint32_t cb;
    uint32_t lpReserved;
    uint32_t lpDesktop;
    uint32_t lpTitle;
    uint32_t dwX;
    uint32_t dwY;
    uint32_t dwXSize;
    uint32_t dwYSize;
    uint32_t dwXCountChars;
    uint32_t dwYCountChars;
    uint32_t dwFillAttribute;
    uint32_t dwFlags;
    uint16_t wShowWindow;
    uint16_t cbReserved2;
    uint32_t lpReserved2;
    uint32_t hStdInput;
    uint32_t hStdOutput;
    uint32_t hStdError;
};

struct startup_info_64
{
    uint32_t cb;
    addr_t lpReserved;
    addr_t lpDesktop;
    addr_t lpTitle;
    uint32_t dwX;
    uint32_t dwY;
    uint32_t dwXSize;
    uint32_t dwYSize;
    uint32_t dwXCountChars;
    uint32_t dwYCountChars;
    uint32_t dwFillAttribute;
    uint32_t dwFlags;
    uint16_t wShowWindow;
    uint16_t cbReserved2;
    addr_t lpReserved2;
    addr_t hStdInput;
    addr_t hStdOutput;
    addr_t hStdError;
};

struct process_information_32
{
    uint32_t hProcess;
    uint32_t hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
} __attribute__ ((packed));

struct process_information_64
{
    addr_t hProcess;
    addr_t hThread;
    uint32_t dwProcessId;
    uint32_t dwThreadId;
} __attribute__ ((packed));

/* Convenience functions */
static inline unicode_string_t* convert_utf8_to_utf16(char const* str)
{
    if (!str) return NULL;

    unicode_string_t us =
    {
        .contents = (uint8_t*)g_strdup(str),
        .length = strlen(str),
        .encoding = "UTF-8",
    };

    if (!us.contents) return NULL;

    unicode_string_t* out = (unicode_string_t*)g_malloc0(sizeof(unicode_string_t));
    if (!out)
    {
        g_free(us.contents);
        return NULL;
    }

    status_t rc = vmi_convert_str_encoding(&us, out, "UTF-16LE");
    g_free(us.contents);

    if (VMI_SUCCESS == rc)
        return out;

    g_free(out);
    return NULL;
}

static inline void fill_created_process_info(injector_t injector, drakvuf_trap_info_t* info)
{
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = injector->process_info,
    };

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(injector->drakvuf);

    if (injector->is32bit)
    {
        struct process_information_32 pip = { 0 };
        if ( VMI_SUCCESS == vmi_read(vmi, &ctx, sizeof(struct process_information_32), &pip, NULL) )
        {
            injector->pid = pip.dwProcessId;
            injector->tid = pip.dwThreadId;
            injector->hProc = pip.hProcess;
            injector->hThr = pip.hThread;
        }
    }
    else
    {
        struct process_information_64 pip = { 0 };
        if ( VMI_SUCCESS == vmi_read(vmi, &ctx, sizeof(struct process_information_64), &pip, NULL) )
        {
            injector->pid = pip.dwProcessId;
            injector->tid = pip.dwThreadId;
            injector->hProc = pip.hProcess;
            injector->hThr = pip.hThread;
        }
    }

    drakvuf_release_vmi(injector->drakvuf);
}

static inline void free_traps(injector_t injector)
{
    GSList * loop = injector->traps;

    while (loop)
    {
        drakvuf_remove_trap(injector->drakvuf, loop->data, (drakvuf_trap_free_t)g_free);
        loop = loop->next;
    }

    g_slist_free(injector->traps);
    injector->traps = NULL;
}

static inline addr_t get_function_va(drakvuf_t drakvuf, addr_t eprocess_base, const char* lib, const char* fun)
{
    addr_t addr = drakvuf_exportsym_to_va(drakvuf, eprocess_base, lib, fun);
    if (!addr)
        PRINT_DEBUG("Failed to get address of %s!%s\n", lib, fun);
    return addr;
}

/* CreateProcess */
bool init_createprocess(injector_t injector, addr_t eprocess_base);
event_response_t cr3_createprocess_wait_for_target_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

#endif
