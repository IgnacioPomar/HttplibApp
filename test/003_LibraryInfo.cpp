/*********************************************************************************************
 *  Description : Unit tests for the library information (name, version, build date)
 *  License     : The unlicense (https://unlicense.org)
 *	Copyright	(C) 2026  Ignacio Pomar Ballestero
 ********************************************************************************************/

#include <catch2/catch_test_macros.hpp>
#include "HttplibApp/LibraryInfo.h"

#include <cctype>
#include <format>
#include <string>

TEST_CASE ("The version macros are consistent", "[version]")
{
	CHECK (std::string (HTTPLIBAPP_NAME) == "HttplibApp");
	CHECK (std::string (HTTPLIBAPP_DESCRIPTION) != "");
	CHECK (std::string (HTTPLIBAPP_VERSION)
	       == std::format ("{}.{}.{}", HTTPLIBAPP_VERSION_MAJOR, HTTPLIBAPP_VERSION_MINOR, HTTPLIBAPP_VERSION_PATCH));
}

TEST_CASE ("The loaded library reports the version it was compiled with", "[version]")
{
	const ipb::http::LibraryInfo &info = ipb::http::getLibraryInfo();

	// The tester is built with the library: both versions must be the same
	CHECK (std::string (info.name) == HTTPLIBAPP_NAME);
	CHECK (std::string (info.description) == HTTPLIBAPP_DESCRIPTION);
	CHECK (std::string (info.version) == HTTPLIBAPP_VERSION);
	CHECK (info.versionMajor == HTTPLIBAPP_VERSION_MAJOR);
	CHECK (info.versionMinor == HTTPLIBAPP_VERSION_MINOR);
	CHECK (info.versionPatch == HTTPLIBAPP_VERSION_PATCH);
}

TEST_CASE ("The build date is YYYY-MM-DD HH:MM:SS", "[version]")
{
	const std::string buildDate = ipb::http::getLibraryInfo().buildDate;

	REQUIRE (buildDate.size() == 19);
	for (std::size_t i : {0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18})
	{
		CHECK (std::isdigit (static_cast<unsigned char> (buildDate [i])));
	}
	CHECK (buildDate.substr (4, 1) == "-");
	CHECK (buildDate.substr (7, 1) == "-");
	CHECK (buildDate.substr (10, 1) == " ");
	CHECK (buildDate.substr (13, 1) == ":");
	CHECK (buildDate.substr (16, 1) == ":");
	CHECK (buildDate.substr (5, 2) >= "01");
	CHECK (buildDate.substr (5, 2) <= "12");
}
