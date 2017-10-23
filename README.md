PPC64 GDB remote debugger plugin for IDA, tested on version 6.6
Primary goal is to be able to debug in [RPCS3 emulator](https://github.com/rpcs3/rpcs3), so it's bare minimum and may not exactly follow GDB protocol

# Warning!
This is a WIP, and very unstable, so it can CRASH or FREEZE your IDA any time (and it will), so save often!

# Features
- Displays all PPU threads (without names though)
- Breakpoints (can only be added when paused)
- Registers view/modification
- Memory view/modification
- Stack trace
- Pause process

# Building and running
To build you will need:
 - IDA SDK
 - VS 2010
 - Windows SDK v7.1A (or maybe something similar)

 1. Change path to IDA SDK in IdaPPC64GdbDebugger\properties.props
 2. If needed, adjust also Windows SDK libary path for linker
 3. Build Debug_Ida64/Win32 configuration
 4. Copy Debug_Ida64/IdaPPC64GdbDebugger.p64 to <IDA folder>\plugins
 5. Run ida 64 bit, choose new debugger, and connect to something!
 6. If you want to use it with RPCS3, you should build RPCS3 with WITH_GDB_DEBUGGER preprocessor definition