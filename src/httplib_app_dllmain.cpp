/*********************************************************************************************
 *  Description :
 *  License     : The unlicense (https://unlicense.org)
 *	Copyright	(C) 2026  Ignacio Pomar Ballestero
 ********************************************************************************************/

// If we have no header outside the #ifdef block, the intellisense will give the following error:
// IntelliSense: PCH warning: Can not find a suitable header stop location. A PCH file wasn't generated.
#include <stdio.h>
#if defined _WIN32 && !defined _WIN32_WCE

#	include <windows.h>

BOOLEAN WINAPI DllMain (IN HINSTANCE hDllHandle, IN DWORD nReason, IN LPVOID Reserved)
{
	BOOLEAN bSuccess = TRUE;

	//  Perform global initialization.
	switch (nReason)
	{
	case DLL_PROCESS_ATTACH: break;
	case DLL_PROCESS_DETACH: break;
	}

	return bSuccess;
}

#endif    // WIN32
          //  end DllMain
