#include <ida.hpp>
#include <area.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <loader.hpp>
#include <idp.hpp>

extern debugger_t debugger;

static bool init_plugin(void);

bool plugin_inited;

//--------------------------------------------------------------------------
// Initialize debugger plugin
static int idaapi init(void)
{
	if (init_plugin())
	{
		dbg = &debugger;
		plugin_inited = true;
		return PLUGIN_KEEP;
	}
	return PLUGIN_SKIP;
}

//--------------------------------------------------------------------------
// Terminate debugger plugin
static void idaapi term(void)
{
	if (plugin_inited)
	{
		//term_plugin();
		plugin_inited = false;
	}
}

//--------------------------------------------------------------------------
// The plugin method - usually is not used for debugger plugins
static void idaapi run(int /*arg*/)
{

}

//--------------------------------------------------------------------------
// Initialize PPC debugger plugin
static bool init_plugin(void)
{
	if (ph.id != PLFM_PPC)
		return false;

	return true;
}

//--------------------------------------------------------------------------
char comment[] = "PPC64 GDB debugger plugin";

char help[] =
"PPC64 GDB debugger plugin\n"
"\n"
"This module lets you debug programs using remote GDB stub.\n";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_DBG,					// plugin flags
	init,							// initialize

	term,							// terminate. this pointer may be NULL.

	run,							// invoke plugin

	comment,						// long comment about the plugin
									// it could appear in the status line
									// or as a hint

	help,							// multiline help about the plugin

	"PPC64 GDB debugger plugin",		// the preferred short name of the plugin

	""							// the preferred hotkey to run the plugin
};