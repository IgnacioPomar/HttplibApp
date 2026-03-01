/*********************************************************************************************
 *  Description : JWT API - provider-based crypto/json engine with cached keys and token workflows
 *  License     : The unlicense (https://unlicense.org)
 *  Copyright    (C) 2026  Ignacio Pomar Ballestero
 *********************************************************************************************/

#pragma once
#ifndef JWT_H_
#	define JWT_H_

#	include <cstddef>
#	include <cstdint>
#	include <memory>
#	include <optional>
#	include <span>
#	include <string>
#	include <string_view>
#	include <unordered_map>
#	include <variant>
#	include <vector>

#	include "httplib_app_exportcfg.h"

namespace ipb::http::jwt
{
	using ByteBuffer = std::vector<uint8_t>;

	enum class JwtAlg : uint8_t
	{
		HS256 = 0,
		RS256 = 1,
		ES256 = 2,
		EdDSA = 3
	};

	enum class JwtUse : uint8_t
	{
		Sig = 0, // sign and verify signatures (default)
		Enc = 1 // future use: cryptographic operations beyond signing (e.g. encryption)
	};

	enum class ErrorCode : uint16_t
	{
		Ok = 0,
		InvalidFormat,
		InvalidBase64Url,
		InvalidJson,
		UnsupportedAlg,
		KeyNotFound,
		SignatureMismatch,
		Expired,
		NotYetValid,
		InvalidIssuer,
		InvalidAudience,
		PolicyViolation,
		CryptoError,
		JsonError,
		IOError,
		CertificateNotFound
	};

	inline constexpr std::string_view toString (ErrorCode code) noexcept
	{
		switch (code)
		{
		case ErrorCode::Ok: return "Ok";
		case ErrorCode::InvalidFormat: return "InvalidFormat";
		case ErrorCode::InvalidBase64Url: return "InvalidBase64Url";
		case ErrorCode::InvalidJson: return "InvalidJson";
		case ErrorCode::UnsupportedAlg: return "UnsupportedAlg";
		case ErrorCode::KeyNotFound: return "KeyNotFound";
		case ErrorCode::SignatureMismatch: return "SignatureMismatch";
		case ErrorCode::Expired: return "Expired";
		case ErrorCode::NotYetValid: return "NotYetValid";
		case ErrorCode::InvalidIssuer: return "InvalidIssuer";
		case ErrorCode::InvalidAudience: return "InvalidAudience";
		case ErrorCode::PolicyViolation: return "PolicyViolation";
		case ErrorCode::CryptoError: return "CryptoError";
		case ErrorCode::JsonError: return "JsonError";
		case ErrorCode::IOError: return "IOError";
		case ErrorCode::CertificateNotFound: return "CertificateNotFound";
		default: return "Unknown";
		}
	}

	struct Error
	{
		ErrorCode code = ErrorCode::Ok;
		std::string message;
	};

	using ClaimValue = std::variant<std::nullptr_t, bool, int64_t, double, std::string>;
	using ClaimMap   = std::unordered_map<std::string, ClaimValue>;
	using HeaderMap  = std::unordered_map<std::string, ClaimValue>;

	struct Policy
	{
		std::vector<JwtAlg> allowedAlgs;
		std::optional<std::string> expectedIss;
		std::optional<std::string> expectedAud;
		int64_t leewaySeconds = 0;
		bool requireExp       = true;
		bool requireNbf       = false;
	};

	struct EngineOptions
	{
		Policy policy;
		bool threadSafe = true;
	};

	class HAPP_API ICryptoProvider
	{
		public:
			virtual ~ICryptoProvider () = default;

			virtual Error loadPrivateKeyFromPemFile (std::string_view kid, std::string_view pemPath) = 0;
			virtual Error loadPublicKeyFromPemFile (std::string_view kid, std::string_view pemPath, JwtUse use) = 0;
			virtual Error loadCertificateFromPemFile (std::string_view kid, std::string_view pemPath)            = 0;
			virtual Error savePrivateKeyToPemFile (std::string_view kid, std::string_view pemPath)              = 0;
			virtual Error savePublicKeyToPemFile (std::string_view kid, std::string_view pemPath, JwtUse use)   = 0;
			virtual Error generateKeyPair (std::string_view kid, JwtAlg alg, std::string_view params = {})       = 0;
			virtual Error removeKey (std::string_view kid)                                                         = 0;

			virtual Error sign (JwtAlg alg, std::string_view kid, std::span<const uint8_t> data,
			                    ByteBuffer &outSignature) const
			    = 0;
			virtual Error verify (JwtAlg alg, std::string_view kid, std::span<const uint8_t> data,
			                      std::span<const uint8_t> signature) const
			    = 0;

			virtual Error base64UrlEncode (std::span<const uint8_t> data, std::string &outText) const = 0;
			virtual Error base64UrlDecode (std::string_view text, ByteBuffer &outData) const           = 0;
	};

	class HAPP_API IJsonProvider
	{
		public:
			virtual ~IJsonProvider () = default;

			virtual Error parseHeader (std::string_view text, HeaderMap &outHeader) const = 0;
			virtual Error parseClaims (std::string_view text, ClaimMap &outClaims) const   = 0;

			virtual Error toJson (const ClaimMap &values, std::string &outJson) const = 0;
	};

	class Jwt;

	class  Verifier
	{
		public:
			HAPP_API Verifier ();
			HAPP_API ~Verifier ();
			HAPP_API Verifier (const Verifier &other);
			HAPP_API Verifier &operator= (const Verifier &other);
			HAPP_API Verifier (Verifier &&other) noexcept;
			HAPP_API Verifier &operator= (Verifier &&other) noexcept;

			HAPP_API bool ok () const noexcept;
			HAPP_API const Error &error () const noexcept;

			HAPP_API std::string_view rawToken () const noexcept;
			HAPP_API std::string_view rawHeaderJson () const noexcept;
			HAPP_API std::string_view rawPayloadJson () const noexcept;

			HAPP_API const HeaderMap &header () const noexcept;
			HAPP_API const ClaimMap &claims () const noexcept;

			HAPP_API bool hasClaim (std::string_view name) const noexcept;
			HAPP_API std::optional<std::string> claimString (std::string_view name) const;
			HAPP_API std::optional<int64_t> claimInt (std::string_view name) const;
			HAPP_API std::optional<double> claimDouble (std::string_view name) const;
			HAPP_API std::optional<bool> claimBool (std::string_view name) const;

		private:
			friend class Jwt;

			class Impl;
			std::unique_ptr<Impl> impl_;
	};

	class  TokenBuilder
	{
		public:
			HAPP_API explicit TokenBuilder (const Jwt &jwt);

			HAPP_API TokenBuilder &alg (JwtAlg value);
			HAPP_API TokenBuilder &kid (std::string value);
			HAPP_API TokenBuilder &type (std::string value = "JWT");

			HAPP_API TokenBuilder &claim (std::string name, ClaimValue value);
			HAPP_API TokenBuilder &claim (std::string name, const char *value);
			HAPP_API TokenBuilder &claim (std::string name, std::string value);
			HAPP_API TokenBuilder &claim (std::string name, std::string_view value);
			HAPP_API TokenBuilder &claim (std::string name, int64_t value);
			HAPP_API TokenBuilder &claim (std::string name, double value);
			HAPP_API TokenBuilder &claim (std::string name, bool value);

			HAPP_API TokenBuilder &issuer (std::string value);
			HAPP_API TokenBuilder &subject (std::string value);
			HAPP_API TokenBuilder &audience (std::string value);
			HAPP_API TokenBuilder &jwtId (std::string value);
			HAPP_API TokenBuilder &expiresAt (int64_t epochSeconds);
			HAPP_API TokenBuilder &notBefore (int64_t epochSeconds);
			HAPP_API TokenBuilder &issuedAt (int64_t epochSeconds);

			HAPP_API Error sign (std::string &outToken) const;

			HAPP_API const HeaderMap &header () const noexcept;
			HAPP_API const ClaimMap &claims () const noexcept;
			HAPP_API void clearClaims () noexcept;

		private:
			const Jwt &jwt_;
			HeaderMap header_;
			ClaimMap claims_;
	};

	class  Jwt
	{
		public:
			HAPP_API explicit Jwt (ICryptoProvider &cryptoProvider, IJsonProvider &jsonProvider,
			              EngineOptions options = {});
			HAPP_API~Jwt();

			Jwt (const Jwt &)            = delete;
			Jwt &operator= (const Jwt &) = delete;
			HAPP_API Jwt (Jwt &&) noexcept;
			HAPP_API Jwt &operator= (Jwt &&) noexcept;

			HAPP_API Error loadPrivateKeyFromPemFile (std::string_view kid, std::string_view pemPath);
			HAPP_API Error loadPublicKeyFromPemFile (std::string_view kid, std::string_view pemPath, JwtUse use = JwtUse::Sig);
			HAPP_API Error loadCertificateFromPemFile (std::string_view kid, std::string_view pemPath);
			HAPP_API Error savePrivateKeyToPemFile (std::string_view kid, std::string_view pemPath);
			HAPP_API Error savePublicKeyToPemFile (std::string_view kid, std::string_view pemPath, JwtUse use = JwtUse::Sig);
			HAPP_API Error generateKeyPair (std::string_view kid, JwtAlg alg, std::string_view params = {});
			HAPP_API Error removeKey (std::string_view kid);
			HAPP_API Error ensureKeyPairInBinaryDir (std::string_view kid, JwtAlg alg,
			                                         std::string_view privateKeyFileName = "jwt.private.pem",
			                                         std::string_view publicKeyFileName  = "jwt.public.pem",
			                                         JwtUse use = JwtUse::Sig,
			                                         std::string_view params = {});

			HAPP_API Error verify (std::string_view token, Verifier &outVerifier) const;
			HAPP_API TokenBuilder token () const;

			HAPP_API const EngineOptions &options () const noexcept;
			HAPP_API void setOptions (EngineOptions options);

			HAPP_API ICryptoProvider &crypto () noexcept;
			HAPP_API const ICryptoProvider &crypto () const noexcept;
			HAPP_API IJsonProvider &json () noexcept;
			HAPP_API const IJsonProvider &json () const noexcept;

		private:
			class Impl;
			std::unique_ptr<Impl> impl_;
	};



}    // namespace ipb::http::jwt

#endif
