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

	class HAPP_API Verifier
	{
		public:
			Verifier ();
			~Verifier ();
			Verifier (const Verifier &other);
			Verifier &operator= (const Verifier &other);
			Verifier (Verifier &&other) noexcept;
			Verifier &operator= (Verifier &&other) noexcept;

			bool ok () const noexcept;
			const Error &error () const noexcept;

			std::string_view rawToken () const noexcept;
			std::string_view rawHeaderJson () const noexcept;
			std::string_view rawPayloadJson () const noexcept;

			const HeaderMap &header () const noexcept;
			const ClaimMap &claims () const noexcept;

			bool hasClaim (std::string_view name) const noexcept;
			std::optional<std::string> claimString (std::string_view name) const;
			std::optional<int64_t> claimInt (std::string_view name) const;
			std::optional<double> claimDouble (std::string_view name) const;
			std::optional<bool> claimBool (std::string_view name) const;

		private:
			friend class Jwt;

			class Impl;
			std::unique_ptr<Impl> impl_;
	};

	class HAPP_API TokenBuilder
	{
		public:
			explicit TokenBuilder (const Jwt &jwt);

			TokenBuilder &alg (JwtAlg value);
			TokenBuilder &kid (std::string value);
			TokenBuilder &type (std::string value = "JWT");

			TokenBuilder &claim (std::string name, ClaimValue value);
			TokenBuilder &claim (std::string name, std::string value);
			TokenBuilder &claim (std::string name, std::string_view value);
			TokenBuilder &claim (std::string name, int64_t value);
			TokenBuilder &claim (std::string name, double value);
			TokenBuilder &claim (std::string name, bool value);

			TokenBuilder &issuer (std::string value);
			TokenBuilder &subject (std::string value);
			TokenBuilder &audience (std::string value);
			TokenBuilder &jwtId (std::string value);
			TokenBuilder &expiresAt (int64_t epochSeconds);
			TokenBuilder &notBefore (int64_t epochSeconds);
			TokenBuilder &issuedAt (int64_t epochSeconds);

			Error sign (std::string &outToken) const;

			const HeaderMap &header () const noexcept;
			const ClaimMap &claims () const noexcept;
			void clearClaims () noexcept;

		private:
			const Jwt &jwt_;
			HeaderMap header_;
			ClaimMap claims_;
	};

	class HAPP_API Jwt
	{
		public:
			explicit Jwt (ICryptoProvider &cryptoProvider, IJsonProvider &jsonProvider,
			              EngineOptions options = {});
			~Jwt();

			Jwt (const Jwt &)            = delete;
			Jwt &operator= (const Jwt &) = delete;
			Jwt (Jwt &&) noexcept;
			Jwt &operator= (Jwt &&) noexcept;

			Error loadPrivateKeyFromPemFile (std::string_view kid, std::string_view pemPath);
			Error loadPublicKeyFromPemFile (std::string_view kid, std::string_view pemPath, JwtUse use = JwtUse::Sig);
			Error loadCertificateFromPemFile (std::string_view kid, std::string_view pemPath);
			Error savePrivateKeyToPemFile (std::string_view kid, std::string_view pemPath);
			Error savePublicKeyToPemFile (std::string_view kid, std::string_view pemPath, JwtUse use = JwtUse::Sig);
			Error generateKeyPair (std::string_view kid, JwtAlg alg, std::string_view params = {});
			Error removeKey (std::string_view kid);

			Error verify (std::string_view token, Verifier &outVerifier) const;
			TokenBuilder token () const;

			const EngineOptions &options () const noexcept;
			void setOptions (EngineOptions options);

			ICryptoProvider &crypto () noexcept;
			const ICryptoProvider &crypto () const noexcept;
			IJsonProvider &json () noexcept;
			const IJsonProvider &json () const noexcept;

		private:
			class Impl;
			std::unique_ptr<Impl> impl_;
	};



}    // namespace ipb::http::jwt

#endif
