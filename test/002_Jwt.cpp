/*********************************************************************************************
 *  Description : Unit tests for JWT API
 *  License     : The unlicense (https://unlicense.org)
 *  Copyright    (C) 2026  Ignacio Pomar Ballestero
 *********************************************************************************************/

#include <catch2/catch_test_macros.hpp>

#include "HttplibApp/Jwt.h"
#include "JwtTestProviders.h"
#include "TestUtils.h"

#include <cmath>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <stdexcept>

namespace ipb::http::jwt
{
	class JwtTester
	{
		protected:
			static constexpr const char *kKid        = "k-startup";
			static constexpr const char *kPrivFile   = "jwt.private.pem";
			static constexpr const char *kPublicFile = "jwt.public.pem";

			FakeCryptoProvider crypto;
			FakeJsonProvider json;
			EngineOptions options;
			Jwt jwt {crypto, json, options};

			/**
			 * Bootstraps the shared key pair once for the whole suite.
			 * This ensures the first test starts with deterministic key material
			 * and avoids per-test generation cost when files already exist.
			 */
			static void bootstrapKeyPair ()
			{
				FakeCryptoProvider bootstrapCrypto;
				FakeJsonProvider bootstrapJson;
				EngineOptions bootstrapOptions;
				Jwt bootstrapJwt {bootstrapCrypto, bootstrapJson, bootstrapOptions};

				auto error = testutil::ensureJwtKeyPairInDir (bootstrapJwt, kKid, JwtAlg::HS256,
				                                              testutil::executableDir(), kPrivFile, kPublicFile);
				if (error.code != ErrorCode::Ok)
				{
					throw std::runtime_error ("Failed to bootstrap JWT key pair for tests: " + error.message);
				}
			}

			/**
			 * Ensures the runtime Jwt instance has the working key pair loaded.
			 * If files are missing, the helper creates them; otherwise it reuses
			 * existing files from the executable directory.
			 */
			JwtTester ()
			{
				static std::once_flag bootstrapped;
				std::call_once (bootstrapped, bootstrapKeyPair);

				auto error = testutil::ensureJwtKeyPairInDir (jwt, kKid, JwtAlg::HS256, testutil::executableDir(),
				                                              kPrivFile, kPublicFile);
				REQUIRE (error.code == ErrorCode::Ok);
			}
	};

	/**
	 * Verifies the happy path for token creation and validation.
	 * The test signs a token with standard claims and checks that
	 * signature validation and claim extraction both succeed.
	 */
	TEST_CASE_METHOD (JwtTester, "SignAndVerifySuccess", "[jwt]")
	{
		std::string token;
		auto signError = jwt.token()
		                     .alg (JwtAlg::HS256)
		                     .kid (kKid)
		                     .issuer ("auth0")
		                     .subject ("user-1")
		                     .claim ("sample", "test")
		                     .expiresAt (static_cast<int64_t> (std::time (nullptr)) + 3600)
		                     .sign (token);
		REQUIRE (signError.code == ErrorCode::Ok);
		REQUIRE_FALSE (token.empty());

		Verifier verifier;
		auto verifyError = jwt.verify (token, verifier);
		REQUIRE (verifyError.code == ErrorCode::Ok);
		REQUIRE (verifier.ok());
		CHECK (verifier.claimString ("sample").value_or ("") == "test");
		CHECK (verifier.claimString ("iss").value_or ("") == "auth0");
	}

	/**
	 * Verifies integrity protection.
	 * After mutating the token payload/signature bytes, verification
	 * must fail with SignatureMismatch.
	 */
	TEST_CASE_METHOD (JwtTester, "VerifyFailsOnSignatureMismatch", "[jwt]")
	{
		std::string token;
		REQUIRE (jwt.token().alg (JwtAlg::HS256).kid (kKid).claim ("sample", "test").sign (token).code == ErrorCode::Ok);
		REQUIRE_FALSE (token.empty());
		token.back() = (token.back() == 'A') ? 'B' : 'A';

		Verifier verifier;
		auto verifyError = jwt.verify (token, verifier);
		CHECK (verifyError.code == ErrorCode::SignatureMismatch);
		CHECK_FALSE (verifier.ok());
	}

	/**
	 * Verifies issuer policy enforcement.
	 * A token signed correctly but with an unexpected issuer must be
	 * rejected with InvalidIssuer.
	 */
	TEST_CASE_METHOD (JwtTester, "VerifyChecksIssuerPolicy", "[jwt]")
	{
		options.policy.expectedIss = "auth0";
		jwt.setOptions (options);

		std::string token;
		REQUIRE (jwt.token().alg (JwtAlg::HS256).kid (kKid).issuer ("other").sign (token).code == ErrorCode::Ok);

		Verifier verifier;
		auto verifyError = jwt.verify (token, verifier);
		CHECK (verifyError.code == ErrorCode::InvalidIssuer);
	}

	/**
	 * Verifies key lifecycle behavior.
	 * Once the signing key is removed, previously signed tokens can no
	 * longer be verified because the kid cannot be resolved.
	 */
	TEST_CASE_METHOD (JwtTester, "RemoveKeyInvalidatesFutureVerification", "[jwt]")
	{
		std::string token;
		REQUIRE (jwt.token().alg (JwtAlg::HS256).kid (kKid).claim ("sample", "test").sign (token).code == ErrorCode::Ok);
		REQUIRE (jwt.removeKey (kKid).code == ErrorCode::Ok);

		Verifier verifier;
		auto verifyError = jwt.verify (token, verifier);
		CHECK (verifyError.code == ErrorCode::KeyNotFound);
	}

	/**
	 * Verifies that PEM persistence methods are callable and succeed
	 * for a key that is already available in the Jwt instance.
	 */
	TEST_CASE_METHOD (JwtTester, "SaveKeyFunctionsExistAndReturnOk", "[jwt]")
	{
		CHECK (jwt.savePrivateKeyToPemFile (kKid, "k1.priv.pem").code == ErrorCode::Ok);
		CHECK (jwt.savePublicKeyToPemFile (kKid, "k1.pub.pem").code == ErrorCode::Ok);
	}

	/**
	 * Verifies claim typing for C-string literals.
	 * A literal passed to claim(...) must be encoded and recovered as
	 * a string claim value during verification.
	 */
	TEST_CASE_METHOD (JwtTester, "ClaimWithCStringLiteralIsStoredAsString", "[jwt]")
	{
		std::string token;
		REQUIRE (jwt.token()
		               .alg (JwtAlg::HS256)
		               .kid (kKid)
		               .claim ("sample", "test")
		               .expiresAt (static_cast<int64_t> (std::time (nullptr)) + 3600)
		               .sign (token)
		               .code == ErrorCode::Ok);

		Verifier verifier;
		REQUIRE (jwt.verify (token, verifier).code == ErrorCode::Ok);
		CHECK (verifier.claimString ("sample").value_or ("") == "test");
	}

	/**
	 * Infrastructure test for tester helper methods.
	 * This validates testutil::ensureJwtKeyPairInDir(...) in the branch
	 * where files are missing: it must generate and save the key pair.
	 */
	TEST_CASE_METHOD (JwtTester, "EnsureKeyPairInBinaryDirCreatesFilesWhenMissing", "[jwt]")
	{
		crypto.resetCounters();
		const auto privFile = "jwt-test-create.private.pem";
		const auto pubFile  = "jwt-test-create.public.pem";
		const auto binDir   = testutil::executableDir();
		const auto privPath = binDir / privFile;
		const auto pubPath  = binDir / pubFile;
		std::error_code ec;
		std::filesystem::remove (privPath, ec);
		std::filesystem::remove (pubPath, ec);

		auto error = testutil::ensureJwtKeyPairInDir (jwt, "k-startup", JwtAlg::HS256, binDir, privFile, pubFile);
		REQUIRE (error.code == ErrorCode::Ok);
		CHECK (std::filesystem::exists (privPath));
		CHECK (std::filesystem::exists (pubPath));
		CHECK (crypto.generateCalls == 1);
		CHECK (crypto.savePrivateCalls == 1);
		CHECK (crypto.savePublicCalls == 1);
		CHECK (crypto.loadPrivateCalls == 0);
		CHECK (crypto.loadPublicCalls == 0);

		std::filesystem::remove (privPath, ec);
		std::filesystem::remove (pubPath, ec);
	}

	/**
	 * Infrastructure test for tester helper methods.
	 * This validates testutil::ensureJwtKeyPairInDir(...) in the branch
	 * where files exist: it must load keys without regenerating/resaving.
	 */
	TEST_CASE_METHOD (JwtTester, "EnsureKeyPairInBinaryDirLoadsFilesWhenPresent", "[jwt]")
	{
		crypto.resetCounters();
		const auto privFile = "jwt-test-load.private.pem";
		const auto pubFile  = "jwt-test-load.public.pem";
		const auto binDir   = testutil::executableDir();
		const auto privPath = binDir / privFile;
		const auto pubPath  = binDir / pubFile;
		{
			std::ofstream privOut (privPath, std::ios::binary | std::ios::trunc);
			std::ofstream pubOut (pubPath, std::ios::binary | std::ios::trunc);
			REQUIRE (privOut.good());
			REQUIRE (pubOut.good());
		}

		auto error = testutil::ensureJwtKeyPairInDir (jwt, "k-startup", JwtAlg::HS256, binDir, privFile, pubFile);
		REQUIRE (error.code == ErrorCode::Ok);
		CHECK (crypto.generateCalls == 0);
		CHECK (crypto.savePrivateCalls == 0);
		CHECK (crypto.savePublicCalls == 0);
		CHECK (crypto.loadPrivateCalls == 1);
		CHECK (crypto.loadPublicCalls == 1);
		CHECK (std::filesystem::path (crypto.lastPrivatePath).filename().string() == privFile);
		CHECK (std::filesystem::path (crypto.lastPublicPath).filename().string() == pubFile);

		std::error_code ec;
		std::filesystem::remove (privPath, ec);
		std::filesystem::remove (pubPath, ec);
	}

} /* namespace ipb::http::jwt */
