/*********************************************************************************************
 *  Description : JWT API implementation
 *  License     : The unlicense (https://unlicense.org)
 *  Copyright    (C) 2026  Ignacio Pomar Ballestero
 *********************************************************************************************/

#include "Jwt.h"

#include <algorithm>
#include <cmath>
#include <ctime>
#include <utility>

namespace ipb::http::jwt
{
	namespace
	{
		static Error makeError (ErrorCode code, std::string message = {})
		{
			return Error {.code = code, .message = std::move (message)};
		}

		static bool isOk (const Error &error)
		{
			return error.code == ErrorCode::Ok;
		}

		static std::span<const uint8_t> asBytes (std::string_view text)
		{
			return std::span<const uint8_t> (reinterpret_cast<const uint8_t *> (text.data()), text.size());
		}

		static std::optional<std::string> getStringValue (const HeaderMap &map, std::string_view key)
		{
			if (auto it = map.find (std::string (key)); it != map.end())
			{
				if (auto value = std::get_if<std::string> (&it->second))
				{
					return *value;
				}
			}
			return std::nullopt;
		}

		static std::optional<int64_t> getIntValue (const ClaimMap &map, std::string_view key)
		{
			if (auto it = map.find (std::string (key)); it != map.end())
			{
				if (auto value = std::get_if<int64_t> (&it->second))
				{
					return *value;
				}
				if (auto value = std::get_if<double> (&it->second))
				{
					const auto rounded = std::floor (*value);
					if (rounded == *value)
					{
						return static_cast<int64_t> (rounded);
					}
				}
			}
			return std::nullopt;
		}

		static std::optional<std::string> getStringClaim (const ClaimMap &map, std::string_view key)
		{
			if (auto it = map.find (std::string (key)); it != map.end())
			{
				if (auto value = std::get_if<std::string> (&it->second))
				{
					return *value;
				}
			}
			return std::nullopt;
		}

		static std::optional<JwtAlg> fromAlgString (std::string_view alg)
		{
			if (alg == "HS256")
			{
				return JwtAlg::HS256;
			}
			if (alg == "RS256")
			{
				return JwtAlg::RS256;
			}
			if (alg == "ES256")
			{
				return JwtAlg::ES256;
			}
			if (alg == "EdDSA")
			{
				return JwtAlg::EdDSA;
			}

			return std::nullopt;
		}

		static std::string toAlgString (JwtAlg alg)
		{
			switch (alg)
			{
			case JwtAlg::HS256: return "HS256";
			case JwtAlg::RS256: return "RS256";
			case JwtAlg::ES256: return "ES256";
			case JwtAlg::EdDSA: return "EdDSA";
			default: return "";
			}
		}

		static bool containsAlg (const std::vector<JwtAlg> &allowed, JwtAlg alg)
		{
			if (allowed.empty())
			{
				return true;
			}
			return std::find (allowed.begin(), allowed.end(), alg) != allowed.end();
		}

		static Error validatePolicy (const Policy &policy, const ClaimMap &claims)
		{
			if (policy.expectedIss.has_value())
			{
				if (auto iss = getStringClaim (claims, "iss");
				    !iss.has_value() || iss.value() != policy.expectedIss.value())
				{
					return makeError (ErrorCode::InvalidIssuer, "Issuer claim does not match policy");
				}
			}

			if (policy.expectedAud.has_value())
			{
				if (auto aud = getStringClaim (claims, "aud");
				    !aud.has_value() || aud.value() != policy.expectedAud.value())
				{
					return makeError (ErrorCode::InvalidAudience, "Audience claim does not match policy");
				}
			}

			const int64_t now = static_cast<int64_t> (std::time (nullptr));

			if (policy.requireExp)
			{
				auto exp = getIntValue (claims, "exp");
				if (!exp.has_value())
				{
					return makeError (ErrorCode::PolicyViolation, "exp claim is required by policy");
				}
				if (now > exp.value() + policy.leewaySeconds)
				{
					return makeError (ErrorCode::Expired, "Token has expired");
				}
			}

			if (policy.requireNbf)
			{
				auto nbf = getIntValue (claims, "nbf");
				if (!nbf.has_value())
				{
					return makeError (ErrorCode::PolicyViolation, "nbf claim is required by policy");
				}
				if (now + policy.leewaySeconds < nbf.value())
				{
					return makeError (ErrorCode::NotYetValid, "Token not valid yet");
				}
			}

			return makeError (ErrorCode::Ok);
		}
	}    // namespace

	class Jwt::Impl
	{
		public:
			Impl (ICryptoProvider &cryptoProvider, IJsonProvider &jsonProvider, EngineOptions options)
			    : crypto_ (cryptoProvider)
			    , json_ (jsonProvider)
			    , options_ (std::move (options))
			{
			}

			ICryptoProvider &crypto_;
			IJsonProvider &json_;
			EngineOptions options_;
	};

	class Verifier::Impl
	{
		public:
			bool ok_ = false;
			Error error_;
			std::string rawToken_;
			std::string rawHeaderJson_;
			std::string rawPayloadJson_;
			HeaderMap header_;
			ClaimMap claims_;
	};

	Verifier::Verifier ()
	    : impl_ (std::make_unique<Impl>())
	{
	}

	Verifier::~Verifier () = default;

	Verifier::Verifier (const Verifier &other)
	    : impl_ (std::make_unique<Impl> (*other.impl_))
	{
	}

	Verifier &Verifier::operator= (const Verifier &other)
	{
		if (this != &other)
		{
			*impl_ = *other.impl_;
		}
		return *this;
	}

	Verifier::Verifier (Verifier &&other) noexcept = default;

	Verifier &Verifier::operator= (Verifier &&other) noexcept = default;

	bool Verifier::ok () const noexcept
	{
		return impl_->ok_;
	}

	const Error &Verifier::error () const noexcept
	{
		return impl_->error_;
	}

	std::string_view Verifier::rawToken () const noexcept
	{
		return impl_->rawToken_;
	}

	std::string_view Verifier::rawHeaderJson () const noexcept
	{
		return impl_->rawHeaderJson_;
	}

	std::string_view Verifier::rawPayloadJson () const noexcept
	{
		return impl_->rawPayloadJson_;
	}

	const HeaderMap &Verifier::header () const noexcept
	{
		return impl_->header_;
	}

	const ClaimMap &Verifier::claims () const noexcept
	{
		return impl_->claims_;
	}

	bool Verifier::hasClaim (std::string_view name) const noexcept
	{
		return impl_->claims_.find (std::string (name)) != impl_->claims_.end();
	}

	std::optional<std::string> Verifier::claimString (std::string_view name) const
	{
		if (auto it = impl_->claims_.find (std::string (name)); it != impl_->claims_.end())
		{
			if (const auto *value = std::get_if<std::string> (&it->second))
			{
				return *value;
			}
		}
		return std::nullopt;
	}

	std::optional<int64_t> Verifier::claimInt (std::string_view name) const
	{
		return getIntValue (impl_->claims_, name);
	}

	std::optional<double> Verifier::claimDouble (std::string_view name) const
	{
		if (auto it = impl_->claims_.find (std::string (name)); it != impl_->claims_.end())
		{
			if (const auto *value = std::get_if<double> (&it->second))
			{
				return *value;
			}
			if (const auto *intValue = std::get_if<int64_t> (&it->second))
			{
				return static_cast<double> (*intValue);
			}
		}
		return std::nullopt;
	}

	std::optional<bool> Verifier::claimBool (std::string_view name) const
	{
		if (auto it = impl_->claims_.find (std::string (name)); it != impl_->claims_.end())
		{
			if (const auto *value = std::get_if<bool> (&it->second))
			{
				return *value;
			}
		}
		return std::nullopt;
	}

	TokenBuilder::TokenBuilder (const Jwt &jwt)
	    : jwt_ (jwt)
	{
		header_ ["alg"] = toAlgString (JwtAlg::HS256);
		header_ ["typ"] = std::string ("JWT");
	}

	TokenBuilder &TokenBuilder::alg (JwtAlg value)
	{
		header_ ["alg"] = toAlgString (value);
		return *this;
	}

	TokenBuilder &TokenBuilder::kid (std::string value)
	{
		header_ ["kid"] = std::move (value);
		return *this;
	}

	TokenBuilder &TokenBuilder::type (std::string value)
	{
		header_ ["typ"] = std::move (value);
		return *this;
	}

	TokenBuilder &TokenBuilder::claim (std::string name, ClaimValue value)
	{
		claims_ [std::move (name)] = std::move (value);
		return *this;
	}

	TokenBuilder &TokenBuilder::claim (std::string name, std::string value)
	{
		return claim (std::move (name), ClaimValue {std::move (value)});
	}

	TokenBuilder &TokenBuilder::claim (std::string name, std::string_view value)
	{
		return claim (std::move (name), std::string (value));
	}

	TokenBuilder &TokenBuilder::claim (std::string name, int64_t value)
	{
		return claim (std::move (name), ClaimValue {value});
	}

	TokenBuilder &TokenBuilder::claim (std::string name, double value)
	{
		return claim (std::move (name), ClaimValue {value});
	}

	TokenBuilder &TokenBuilder::claim (std::string name, bool value)
	{
		return claim (std::move (name), ClaimValue {value});
	}

	TokenBuilder &TokenBuilder::issuer (std::string value)
	{
		return claim ("iss", std::move (value));
	}

	TokenBuilder &TokenBuilder::subject (std::string value)
	{
		return claim ("sub", std::move (value));
	}

	TokenBuilder &TokenBuilder::audience (std::string value)
	{
		return claim ("aud", std::move (value));
	}

	TokenBuilder &TokenBuilder::jwtId (std::string value)
	{
		return claim ("jti", std::move (value));
	}

	TokenBuilder &TokenBuilder::expiresAt (int64_t epochSeconds)
	{
		return claim ("exp", epochSeconds);
	}

	TokenBuilder &TokenBuilder::notBefore (int64_t epochSeconds)
	{
		return claim ("nbf", epochSeconds);
	}

	TokenBuilder &TokenBuilder::issuedAt (int64_t epochSeconds)
	{
		return claim ("iat", epochSeconds);
	}

	Error TokenBuilder::sign (std::string &outToken) const
	{
		auto algText = getStringValue (header_, "alg");
		if (!algText.has_value())
		{
			return makeError (ErrorCode::UnsupportedAlg, "Missing algorithm in token header");
		}

		auto alg = fromAlgString (algText.value());
		if (!alg.has_value())
		{
			return makeError (ErrorCode::UnsupportedAlg, "Unsupported algorithm in token header");
		}

		auto kidText = getStringValue (header_, "kid");
		if (!kidText.has_value())
		{
			return makeError (ErrorCode::KeyNotFound, "Missing kid in token header");
		}

		std::string headerJson;
		if (auto error = jwt_.json().toJson (header_, headerJson); !isOk (error))
		{
			return error;
		}

		std::string payloadJson;
		if (auto error = jwt_.json().toJson (claims_, payloadJson); !isOk (error))
		{
			return error;
		}

		std::string headerB64;
		if (auto error = jwt_.crypto().base64UrlEncode (asBytes (headerJson), headerB64); !isOk (error))
		{
			return error;
		}

		std::string payloadB64;
		if (auto error = jwt_.crypto().base64UrlEncode (asBytes (payloadJson), payloadB64); !isOk (error))
		{
			return error;
		}

		const std::string signingInput = headerB64 + "." + payloadB64;

		ByteBuffer signature;
		if (auto error = jwt_.crypto().sign (alg.value(), kidText.value(), asBytes (signingInput), signature);
		    !isOk (error))
		{
			return error;
		}

		std::string signatureB64;
		if (auto error = jwt_.crypto().base64UrlEncode (signature, signatureB64); !isOk (error))
		{
			return error;
		}

		outToken = signingInput + "." + signatureB64;
		return makeError (ErrorCode::Ok);
	}

	const HeaderMap &TokenBuilder::header () const noexcept
	{
		return header_;
	}

	const ClaimMap &TokenBuilder::claims () const noexcept
	{
		return claims_;
	}

	void TokenBuilder::clearClaims () noexcept
	{
		claims_.clear();
	}

	Jwt::Jwt (ICryptoProvider &cryptoProvider, IJsonProvider &jsonProvider, EngineOptions options)
	    : impl_ (std::make_unique<Impl> (cryptoProvider, jsonProvider, std::move (options)))
	{
	}

	Jwt::~Jwt ()                          = default;
	Jwt::Jwt (Jwt &&) noexcept            = default;
	Jwt &Jwt::operator= (Jwt &&) noexcept = default;

	Error Jwt::loadPrivateKeyFromPemFile (std::string_view kid, std::string_view pemPath)
	{
		return impl_->crypto_.loadPrivateKeyFromPemFile (kid, pemPath);
	}

	Error Jwt::loadPublicKeyFromPemFile (std::string_view kid, std::string_view pemPath, JwtUse use)
	{
		return impl_->crypto_.loadPublicKeyFromPemFile (kid, pemPath, use);
	}

	Error Jwt::loadCertificateFromPemFile (std::string_view kid, std::string_view pemPath)
	{
		return impl_->crypto_.loadCertificateFromPemFile (kid, pemPath);
	}

	Error Jwt::savePrivateKeyToPemFile (std::string_view kid, std::string_view pemPath)
	{
		return impl_->crypto_.savePrivateKeyToPemFile (kid, pemPath);
	}

	Error Jwt::savePublicKeyToPemFile (std::string_view kid, std::string_view pemPath, JwtUse use)
	{
		return impl_->crypto_.savePublicKeyToPemFile (kid, pemPath, use);
	}

	Error Jwt::generateKeyPair (std::string_view kid, JwtAlg alg, std::string_view params)
	{
		return impl_->crypto_.generateKeyPair (kid, alg, params);
	}

	Error Jwt::removeKey (std::string_view kid)
	{
		return impl_->crypto_.removeKey (kid);
	}

	Error Jwt::verify (std::string_view token, Verifier &outVerifier) const
	{
		outVerifier                  = Verifier {};
		outVerifier.impl_->rawToken_ = std::string (token);

		const auto firstDot = token.find ('.');
		if (firstDot == std::string_view::npos)
		{
			outVerifier.impl_->error_ = makeError (ErrorCode::InvalidFormat, "Token must contain 3 parts");
			return outVerifier.impl_->error_;
		}

		const auto secondDot = token.find ('.', firstDot + 1);
		if (secondDot == std::string_view::npos || token.find ('.', secondDot + 1) != std::string_view::npos)
		{
			outVerifier.impl_->error_ = makeError (ErrorCode::InvalidFormat, "Token must contain exactly 3 parts");
			return outVerifier.impl_->error_;
		}

		const std::string_view headerPart    = token.substr (0, firstDot);
		const std::string_view payloadPart   = token.substr (firstDot + 1, secondDot - firstDot - 1);
		const std::string_view signaturePart = token.substr (secondDot + 1);

		ByteBuffer headerBytes;
		if (auto error = impl_->crypto_.base64UrlDecode (headerPart, headerBytes); !isOk (error))
		{
			outVerifier.impl_->error_ = error;
			return error;
		}

		ByteBuffer payloadBytes;
		if (auto error = impl_->crypto_.base64UrlDecode (payloadPart, payloadBytes); !isOk (error))
		{
			outVerifier.impl_->error_ = error;
			return error;
		}

		ByteBuffer signatureBytes;
		if (auto error = impl_->crypto_.base64UrlDecode (signaturePart, signatureBytes); !isOk (error))
		{
			outVerifier.impl_->error_ = error;
			return error;
		}

		outVerifier.impl_->rawHeaderJson_ =
		    std::string (reinterpret_cast<const char *> (headerBytes.data()), headerBytes.size());
		outVerifier.impl_->rawPayloadJson_ =
		    std::string (reinterpret_cast<const char *> (payloadBytes.data()), payloadBytes.size());

		if (auto error = impl_->json_.parseHeader (outVerifier.impl_->rawHeaderJson_, outVerifier.impl_->header_);
		    !isOk (error))
		{
			outVerifier.impl_->error_ = error;
			return error;
		}

		if (auto error = impl_->json_.parseClaims (outVerifier.impl_->rawPayloadJson_, outVerifier.impl_->claims_);
		    !isOk (error))
		{
			outVerifier.impl_->error_ = error;
			return error;
		}

		auto algText = getStringValue (outVerifier.impl_->header_, "alg");
		if (!algText.has_value())
		{
			outVerifier.impl_->error_ = makeError (ErrorCode::UnsupportedAlg, "Missing alg header");
			return outVerifier.impl_->error_;
		}

		auto alg = fromAlgString (algText.value());
		if (!alg.has_value())
		{
			outVerifier.impl_->error_ = makeError (ErrorCode::UnsupportedAlg, "Unknown algorithm");
			return outVerifier.impl_->error_;
		}

		if (!containsAlg (impl_->options_.policy.allowedAlgs, alg.value()))
		{
			outVerifier.impl_->error_ = makeError (ErrorCode::UnsupportedAlg, "Algorithm not allowed by policy");
			return outVerifier.impl_->error_;
		}

		auto kidText = getStringValue (outVerifier.impl_->header_, "kid");
		if (!kidText.has_value())
		{
			outVerifier.impl_->error_ = makeError (ErrorCode::KeyNotFound, "Missing kid header");
			return outVerifier.impl_->error_;
		}

		const std::string signingInput = std::string (headerPart) + "." + std::string (payloadPart);
		if (auto error = impl_->crypto_.verify (alg.value(), kidText.value(), asBytes (signingInput), signatureBytes);
		    !isOk (error))
		{
			outVerifier.impl_->error_ = error;
			return error;
		}

		if (auto error = validatePolicy (impl_->options_.policy, outVerifier.impl_->claims_); !isOk (error))
		{
			outVerifier.impl_->error_ = error;
			return error;
		}

		outVerifier.impl_->ok_    = true;
		outVerifier.impl_->error_ = makeError (ErrorCode::Ok);
		return outVerifier.impl_->error_;
	}

	TokenBuilder Jwt::token () const
	{
		return TokenBuilder (*this);
	}

	const EngineOptions &Jwt::options () const noexcept
	{
		return impl_->options_;
	}

	void Jwt::setOptions (EngineOptions options)
	{
		impl_->options_ = std::move (options);
	}

	ICryptoProvider &Jwt::crypto () noexcept
	{
		return impl_->crypto_;
	}

	const ICryptoProvider &Jwt::crypto () const noexcept
	{
		return impl_->crypto_;
	}

	IJsonProvider &Jwt::json () noexcept
	{
		return impl_->json_;
	}

	const IJsonProvider &Jwt::json () const noexcept
	{
		return impl_->json_;
	}

}    // namespace ipb::http::jwt
