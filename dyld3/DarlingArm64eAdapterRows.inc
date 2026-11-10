// The rows of the arm64e adapter table (DarlingArm64eAdapters.cpp includes this inside the table's initializer).
// symbol, authMask, blockArg, structArg, return fix, argCount, status, evidence. Argument numbers count from 0.
// Provenance: the probed rows are the checks of tests/arm64e-link/abi (L2 ABI probe); every other row follows from the
// public prototype listed by the T0 facts scan of the callback-taking imports of the C++ runtime, ObjC and Foundation
// closures (tests/darling-arm64e-callback-imports.tsv): a code pointer argument in a register is ShapeOnly, anything the
// probe did not run (blocks beyond dispatch_async and dispatch_once, structs that hold code pointers, callbacks passed on the
// stack) is Unsupported and warns when an arm64e image imports it.
	{ "___cxa_atexit", 0x1, 0, 0, ReturnFix::None, 3, AdapterStatus::Probed, "L2 check 02" },
	{ "_atexit", 0x1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "L2 check 01" },
	{ "_pthread_key_create", 0x2, 0, 0, ReturnFix::None, 2, AdapterStatus::Probed, "L2 check 03" },
	{ "_pthread_create", 0x4, 0, 0, ReturnFix::None, 4, AdapterStatus::Probed, "L2 check 04" },
	{ "_pthread_once", 0x2, 0, 0, ReturnFix::None, 2, AdapterStatus::Probed, "L2 check 05" },
	{ "_qsort", 0x8, 0, 0, ReturnFix::None, 4, AdapterStatus::Probed, "L2 check 06" },
	{ "__dyld_register_func_for_add_image", 0x1, 0, 0, ReturnFix::None, 1, AdapterStatus::Probed, "L2 check 10" },
	{ "_dispatch_async", 0x0, 2, 0, ReturnFix::None, 2, AdapterStatus::Probed, "L2 checks 07 and 08 (stack and global block)" },
	{ "_dispatch_once", 0x0, 2, 0, ReturnFix::None, 2, AdapterStatus::Probed, "L2 check 09" },
	{ "_sigaction", 0x0, 0, 2, ReturnFix::None, 3, AdapterStatus::Probed, "L2 check 18 (act only; the old action oact is returned as plain code has it, not shown)" },
	{ "_signal", 0x2, 0, 0, ReturnFix::SignInstalledHandler, 2, AdapterStatus::Probed, "L2 check 19" },
	{ "__Block_copy", 0x0, 0, 0, ReturnFix::ResignCopiedBlock, 1, AdapterStatus::Probed, "L2 check 17" },
	{ "__tlv_atexit", 0x1, 0, 0, ReturnFix::None, 2, AdapterStatus::ShapeOnly, "the shape of L2 checks 01 and 03; imported by test programs, not in the T0 lists" },
