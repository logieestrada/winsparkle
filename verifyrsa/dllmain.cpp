//
//*----------------------------------------------------------------------------
//
//  Copyright (c) 1999-2017 Logitech, Inc.  All Rights Reserved
//
//  This program is a trade secret of LOGITECH, and it is not to be reproduced,
//  published, disclosed to others, copied, adapted, distributed or displayed
//  without the prior authorization of LOGITECH.
//
//  Licensee agrees to attach or embed this notice on all copies of the program,
//  including partial copies or modified versions thereof.
//
//  Description: For RSA signature verification
//--------------------------------------------------------------------------------
//
// verifyrsa.h
//
#include "stdafx.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

