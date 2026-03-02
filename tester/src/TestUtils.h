#pragma once

#include "Jwt.h"

#include <filesystem>
#include <string>
#include <vector>

#if defined(_WIN32)
#	include <windows.h>
#endif

namespace ipb::http::testutil
{
	inline std::filesystem::path executableDir ()
	{
#if defined(_WIN32)
		std::vector<wchar_t> buffer (MAX_PATH);
		DWORD len = 0;
		for (;;)
		{
			len = GetModuleFileNameW (nullptr, buffer.data(), static_cast<DWORD> (buffer.size()));
			if (len == 0)
			{
				break;
			}
			if (len < buffer.size() - 1)
			{
				return std::filesystem::path (std::wstring (buffer.data(), len)).parent_path();
			}
			buffer.resize (buffer.size() * 2);
		}
#endif
		return std::filesystem::current_path();
	}

	inline jwt::Error ensureJwtKeyPairInDir (jwt::Jwt &jwt, std::string_view kid, jwt::JwtAlg alg,
	                                         const std::filesystem::path &dir,
	                                         std::string_view privateKeyFileName = "jwt.private.pem",
	                                         std::string_view publicKeyFileName  = "jwt.public.pem",
	                                         jwt::JwtUse use = jwt::JwtUse::Sig,
	                                         std::string_view params = {})
	{
		if (privateKeyFileName.empty() || publicKeyFileName.empty())
		{
			return {.code = jwt::ErrorCode::IOError, .message = "Key file names cannot be empty"};
		}

		const auto privatePath = dir / std::string (privateKeyFileName);
		const auto publicPath  = dir / std::string (publicKeyFileName);

		const bool privateExists = std::filesystem::exists (privatePath);
		const bool publicExists  = std::filesystem::exists (publicPath);

		if (privateExists && publicExists)
		{
			auto error = jwt.loadPrivateKeyFromPemFile (kid, privatePath.string());
			if (error.code != jwt::ErrorCode::Ok)
			{
				return error;
			}
			return jwt.loadPublicKeyFromPemFile (kid, publicPath.string(), use);
		}

		auto error = jwt.generateKeyPair (kid, alg, params);
		if (error.code != jwt::ErrorCode::Ok)
		{
			return error;
		}

		error = jwt.savePrivateKeyToPemFile (kid, privatePath.string());
		if (error.code != jwt::ErrorCode::Ok)
		{
			return error;
		}

		return jwt.savePublicKeyToPemFile (kid, publicPath.string(), use);
	}
}    // namespace ipb::http::testutil
