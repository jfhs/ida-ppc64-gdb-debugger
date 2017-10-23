#pragma once

#include <ida.hpp>

#define DEBUGGER_NAME "ppc64-gdb"
#define DEBUGGER_ID_PPC64_GDB 1873 //random number
#define PROCESSOR_NAME "ppc"

static error_t idaapi idc_threadlst(idc_value_t *argv, idc_value_t *res);
