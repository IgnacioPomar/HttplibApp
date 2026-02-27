/*********************************************************************************************
 *  Description : HAPP export configuration
 *  License     : The unlicense (https://unlicense.org)
 *	Copyright	(C) 2026  Ignacio Pomar Ballestero
 ********************************************************************************************/

#pragma once
#ifndef _HAPP_CFG_H_
#	define _HAPP_CFG_H_

// If the solution is a dinamic library (dll), we need the next macro
#	define HAPP_DLL

// IMPORTANT: the project who exports must have the preprocessor macro STREAMLOGGER_EXPORTS

// see http://gcc.gnu.org/wiki/Visibility

// Generic helper definitions for shared library support
#	if defined _WIN32 || defined __CYGWIN__
#		define HAPP_HELPER_DLL_IMPORT __declspec (dllimport)
#		define HAPP_HELPER_DLL_EXPORT __declspec (dllexport)
#		define HAPP_HELPER_DLL_LOCAL
#	else
#		if __GNUC__ >= 4
#			define HAPP_HELPER_DLL_IMPORT __attribute__ ((visibility ("default")))
#			define HAPP_HELPER_DLL_EXPORT __attribute__ ((visibility ("default")))
#			define HAPP_HELPER_DLL_LOCAL  __attribute__ ((visibility ("hidden")))
#		else
#			define HAPP_HELPER_DLL_IMPORT
#			define HAPP_HELPER_DLL_EXPORT
#			define HAPP_HELPER_DLL_LOCAL
#		endif
#	endif

// Now we use the generic helper definitions above to define HAPP_API and HAPP_LOCAL.
// HAPP_API is used for the public API symbols. It either DLL imports or DLL exports (or does nothing for static build)
// HAPP_LOCAL is used for non-api symbols.

#	ifdef HAPP_DLL                  // defined if HAPP is compiled as a DLL
#		ifdef HTTPLIBAPP_EXPORTS    // defined if we are building the HAPP DLL (instead of using it)
#			define HAPP_API HAPP_HELPER_DLL_EXPORT
#		else
#			define HAPP_API HAPP_HELPER_DLL_IMPORT
#		endif    // HTTPLIBAPP_EXPORTS
#		define HAPP_LOCAL HAPP_HELPER_DLL_LOCAL
#	else    // HAPP_DLL is not defined: this means HAPP is a static lib.
#		define HAPP_API
#		define HAPP_LOCAL
#	endif    // HAPP_DLL

#	ifdef __GNUC__
#		define DEPRECATED __attribute__ ((deprecated))
#	elif defined(_MSC_VER)
#		define DEPRECATED __declspec (deprecated)
#	else
#		pragma message("WARNING: You need to implement DEPRECATED for this compiler")
#		define DEPRECATED
#	endif

#endif    //_HAPP_CFG_H_
