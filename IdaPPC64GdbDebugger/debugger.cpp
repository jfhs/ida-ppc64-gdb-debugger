#include <ida.hpp>
#include <dbg.hpp>
#include <expr.hpp>
#include "debugger.h"
#include "GDBDebugClient.h"

#ifndef _WIN32
#include"fcntl.h"
#else
#include <winsock.h>
#endif

const uchar bpt_code[] = "";

static const char idc_threadlst_args[] = { 0 };

static GDBDebugClient* debugger_instance = nullptr;

static bool idaapi init_debugger(const char *hostname, int port_num, const char *password)
{
	debugger_instance = new GDBDebugClient();

	set_idc_func_ex("threadlst", idc_threadlst, idc_threadlst_args, 0);

	bool result = debugger_instance->connect(hostname, port_num);
	if (!result) {
		delete debugger_instance;
		debugger_instance = nullptr;
	}

	return result;
}

static bool idaapi term_debugger(void)
{
	set_idc_func_ex("threadlst", NULL, idc_threadlst_args, 0);

	delete debugger_instance;
	debugger_instance = nullptr;

	return true;
}

int idaapi process_get_info(int n, process_info_t *info)
{
	return debugger_instance->process_get_info(n, info);
}

static error_t idaapi idc_threadlst(idc_value_t *argv, idc_value_t *res)
{
	return debugger_instance->set_threadlist();
}

static int idaapi start_process(const char *path,
	const char *args,
	const char *startdir,
	int dbg_proc_flags,
	const char *input_path,
	uint32 input_file_crc32)
{
	return debugger_instance->start_process(path, args, startdir, dbg_proc_flags, input_path, input_file_crc32);
}

int idaapi gdb_attach_process(pid_t pid, int event_id)
{
	return debugger_instance->attach_to_process(pid, event_id);
}

int idaapi gdb_detach_process(void)
{
	return debugger_instance->detach();
}

void idaapi rebase_if_required_to(ea_t new_base)
{
	debugger_instance->rebase_if_required_to(new_base);
}

int idaapi prepare_to_pause_process(void)
{
	return debugger_instance->prepare_to_pause();
}

int idaapi gdb_exit_process(void)
{
	return debugger_instance->exit_process();
}

gdecode_t idaapi get_debug_event(debug_event_t *event, int ida_is_idle)
{
	return debugger_instance->get_debug_event(event, ida_is_idle);
}

int idaapi continue_after_event(const debug_event_t *event)
{
	return debugger_instance->continue_after_event(event);
}

void idaapi stopped_at_debug_event(bool dlls_added)
{
	debugger_instance->stopped_at_debug_event(dlls_added);
}

int idaapi thread_suspend(thid_t tid)
{
	return debugger_instance->thread_suspend(tid);
}

int idaapi thread_continue(thid_t tid)
{
	return debugger_instance->thread_continue(tid);
}

int idaapi thread_set_step(thid_t tid)
{
	return debugger_instance->thread_step(tid);
}

int idaapi read_registers(thid_t tid, int clsmask, regval_t *values)
{
	return debugger_instance->read_registers(tid, clsmask, values);
}

int idaapi write_register(thid_t tid, int reg_idx, const regval_t *value)
{
	return debugger_instance->write_register(tid, reg_idx, value);
}

int idaapi get_memory_info(meminfo_vec_t &areas)
{
	return debugger_instance->get_memory_info(areas);
}

ssize_t idaapi read_memory(ea_t ea, void *buffer, size_t size)
{
	return debugger_instance->read_memory(ea, buffer, size);
}

ssize_t idaapi write_memory(ea_t ea, const void *buffer, size_t size)
{
	return debugger_instance->write_memory(ea, buffer, size);
}

int idaapi is_ok_bpt(bpttype_t type, ea_t ea, int len)
{
	return debugger_instance->is_ok_bpt(type, ea, len);
}

int idaapi update_bpts(update_bpt_info_t *bpts, int nadd, int ndel)
{
	return debugger_instance->update_bpts(bpts, nadd, ndel);
}

ea_t idaapi map_address(ea_t off, const regval_t *regs, int regnum)
{
	return debugger_instance->map_address(off, regs, regnum);
}

int idaapi send_ioctl(int fn, const void *buf, size_t size, void **poutbuf, ssize_t *poutsize)
{
	return debugger_instance->send_ioctl(fn, buf, size, poutbuf, poutsize);
}

bool idaapi update_call_stack(thid_t tid, call_stack_t *trace) {
	return debugger_instance->update_call_stack(tid, trace);
}

debugger_t debugger =
{
	IDD_INTERFACE_VERSION,
	DEBUGGER_NAME,				// Short debugger name
	DEBUGGER_ID_PPC64_GDB,	// Debugger API module id
	PROCESSOR_NAME,				// Required processor name
	DBG_FLAG_REMOTE | DBG_FLAG_CAN_CONT_BPT | DBG_FLAG_SAFE | DBG_FLAG_NOPASSWORD | DBG_FLAG_DEBTHREAD,

	register_classes,				// Array of register class names
	RC_GENERAL,					// Mask of default printed register classes
	registers,					// Array of registers
	static_cast<int>(registers_count),			// Number of registers

	0x1000,						// Size of a memory page

	bpt_code,						// Array of bytes for a breakpoint instruction
	qnumber(bpt_code),			// Size of this array
	0,							// for miniidbs: use this value for the file type after attaching
	0,							// reserved

	init_debugger,
	term_debugger,

	process_get_info,
	start_process,
	gdb_attach_process,
	gdb_detach_process,
	rebase_if_required_to,
	prepare_to_pause_process,
	gdb_exit_process,

	get_debug_event,
	continue_after_event,
	NULL, //set_exception_info,
	stopped_at_debug_event,

	thread_suspend,
	thread_continue,
	thread_set_step,
	read_registers,
	write_register,
	NULL, //thread_get_sreg_base

	get_memory_info,
	read_memory,
	write_memory,

	is_ok_bpt,
	update_bpts,
	NULL, //update_lowcnds
	NULL, //open_file
	NULL, //close_file
	NULL, //read_file
	map_address,
	NULL, //set_dbg_options
	NULL, //get_debmod_extensions
	update_call_stack, //update_call_stack
	NULL, //appcall
	NULL, //cleanup_appcall
	NULL, //eval_lowcnd
	NULL, //write_file
	send_ioctl,
};