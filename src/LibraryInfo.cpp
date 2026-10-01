/*********************************************************************************************
 *  Description : Name, description, version and build date of the library
 *  License     : The unlicense (https://unlicense.org)
 *	Copyright	(C) 2026  Ignacio Pomar Ballestero
 ********************************************************************************************/

#include "HttplibApp/LibraryInfo.h"

#include <array>
#include <string_view>

namespace ipb::http
{
	namespace
	{
		// __DATE__ ("Oct  1 2026") and __TIME__ ("14:16:58") -> "2026-10-01 14:16:58"
		constexpr std::array<char, 20> isoBuildDate (std::string_view date, std::string_view time)
		{
			constexpr std::string_view months = "JanFebMarAprMayJunJulAugSepOctNovDec";
			const int month                   = static_cast<int> (months.find (date.substr (0, 3))) / 3 + 1;

			std::array<char, 20> iso {};
			for (int i = 0; i < 4; ++i)
			{
				iso [i] = date [7 + i];    // Year
			}
			iso [4]  = '-';
			iso [5]  = static_cast<char> ('0' + month / 10);
			iso [6]  = static_cast<char> ('0' + month % 10);
			iso [7]  = '-';
			iso [8]  = (date [4] == ' ') ? '0' : date [4];    // Day, padded with a space
			iso [9]  = date [5];
			iso [10] = ' ';
			for (int i = 0; i < 8; ++i)
			{
				iso [11 + i] = time [i];
			}
			iso [19] = '\0';
			return iso;
		}

		// Expanded when this file is compiled: CMake recompiles it whenever the library changes
		constexpr std::array<char, 20> buildDate = isoBuildDate (__DATE__, __TIME__);
	}    // namespace

	// The macros are expanded here, when the library is compiled: the values are the ones of the loaded library
	const LibraryInfo &getLibraryInfo () noexcept
	{
		static constexpr LibraryInfo libraryInfo {
		    HTTPLIBAPP_NAME,          HTTPLIBAPP_DESCRIPTION,   HTTPLIBAPP_VERSION,       buildDate.data(),
		    HTTPLIBAPP_VERSION_MAJOR, HTTPLIBAPP_VERSION_MINOR, HTTPLIBAPP_VERSION_PATCH,
		};
		return libraryInfo;
	}
}    // namespace ipb::http
