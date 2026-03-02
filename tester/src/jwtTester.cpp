/*********************************************************************************************
 *  Description : Unit tests for JWT API
 *  License     : The unlicense (https://unlicense.org)
 *  Copyright    (C) 2026  Ignacio Pomar Ballestero
 *********************************************************************************************/

#include <gtest/gtest.h>

#include "Jwt.h"
#include "JwtTestProviders.h"
#include "TestUtils.h"

#include <cmath>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace ipb::http::jwt
{
	class JwtTester : public ::testing::Test
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
			static void SetUpTestSuite ()
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
			void SetUp () override
			{
				auto error = testutil::ensureJwtKeyPairInDir (jwt, kKid, JwtAlg::HS256, testutil::executableDir(),
				                                              kPrivFile, kPublicFile);
				ASSERT_EQ (error.code, ErrorCode::Ok);
			}
	};

	/**
	 * Verifies the happy path for token creation and validation.
	 * The test signs a token with standard claims and checks that
	 * signature validation and claim extraction both succeed.
	 */
	TEST_F (JwtTester, SignAndVerifySuccess)
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
		ASSERT_EQ (signError.code, ErrorCode::Ok);
		ASSERT_FALSE (token.empty());

		Verifier verifier;
		auto verifyError = jwt.verify (token, verifier);
		ASSERT_EQ (verifyError.code, ErrorCode::Ok);
		ASSERT_TRUE (verifier.ok());
		EXPECT_EQ (verifier.claimString ("sample").value_or (""), "test");
		EXPECT_EQ (verifier.claimString ("iss").value_or (""), "auth0");
	}

	/**
	 * Verifies integrity protection.
	 * After mutating the token payload/signature bytes, verification
	 * must fail with SignatureMismatch.
	 */
	TEST_F (JwtTester, VerifyFailsOnSignatureMismatch)
	{
		std::string token;
		ASSERT_EQ (jwt.token().alg (JwtAlg::HS256).kid (kKid).claim ("sample", "test").sign (token).code,
		           ErrorCode::Ok);
		ASSERT_FALSE (token.empty());
		token.back() = (token.back() == 'A') ? 'B' : 'A';

		Verifier verifier;
		auto verifyError = jwt.verify (token, verifier);
		EXPECT_EQ (verifyError.code, ErrorCode::SignatureMismatch);
		EXPECT_FALSE (verifier.ok());
	}

	/**
	 * Verifies issuer policy enforcement.
	 * A token signed correctly but with an unexpected issuer must be
	 * rejected with InvalidIssuer.
	 */
	TEST_F (JwtTester, VerifyChecksIssuerPolicy)
	{
		options.policy.expectedIss = "auth0";
		jwt.setOptions (options);

		std::string token;
		ASSERT_EQ (jwt.token().alg (JwtAlg::HS256).kid (kKid).issuer ("other").sign (token).code, ErrorCode::Ok);

		Verifier verifier;
		auto verifyError = jwt.verify (token, verifier);
		EXPECT_EQ (verifyError.code, ErrorCode::InvalidIssuer);
	}

	/**
	 * Verifies key lifecycle behavior.
	 * Once the signing key is removed, previously signed tokens can no
	 * longer be verified because the kid cannot be resolved.
	 */
	TEST_F (JwtTester, RemoveKeyInvalidatesFutureVerification)
	{
		std::string token;
		ASSERT_EQ (jwt.token().alg (JwtAlg::HS256).kid (kKid).claim ("sample", "test").sign (token).code,
		           ErrorCode::Ok);
		ASSERT_EQ (jwt.removeKey (kKid).code, ErrorCode::Ok);

		Verifier verifier;
		auto verifyError = jwt.verify (token, verifier);
		EXPECT_EQ (verifyError.code, ErrorCode::KeyNotFound);
	}

	/**
	 * Verifies that PEM persistence methods are callable and succeed
	 * for a key that is already available in the Jwt instance.
	 */
	TEST_F (JwtTester, SaveKeyFunctionsExistAndReturnOk)
	{
		EXPECT_EQ (jwt.savePrivateKeyToPemFile (kKid, "k1.priv.pem").code, ErrorCode::Ok);
		EXPECT_EQ (jwt.savePublicKeyToPemFile (kKid, "k1.pub.pem").code, ErrorCode::Ok);
	}

	/**
	 * Verifies claim typing for C-string literals.
	 * A literal passed to claim(...) must be encoded and recovered as
	 * a string claim value during verification.
	 */
	TEST_F (JwtTester, ClaimWithCStringLiteralIsStoredAsString)
	{
		std::string token;
		ASSERT_EQ (jwt.token()
		               .alg (JwtAlg::HS256)
		               .kid (kKid)
		               .claim ("sample", "test")
		               .expiresAt (static_cast<int64_t> (std::time (nullptr)) + 3600)
		               .sign (token)
		               .code,
		           ErrorCode::Ok);

		Verifier verifier;
		ASSERT_EQ (jwt.verify (token, verifier).code, ErrorCode::Ok);
		EXPECT_EQ (verifier.claimString ("sample").value_or (""), "test");
	}

	/**
	 * Infrastructure test for tester helper methods.
	 * This validates testutil::ensureJwtKeyPairInDir(...) in the branch
	 * where files are missing: it must generate and save the key pair.
	 */
	TEST_F (JwtTester, EnsureKeyPairInBinaryDirCreatesFilesWhenMissing)
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
		ASSERT_EQ (error.code, ErrorCode::Ok);
		EXPECT_TRUE (std::filesystem::exists (privPath));
		EXPECT_TRUE (std::filesystem::exists (pubPath));
		EXPECT_EQ (crypto.generateCalls, 1);
		EXPECT_EQ (crypto.savePrivateCalls, 1);
		EXPECT_EQ (crypto.savePublicCalls, 1);
		EXPECT_EQ (crypto.loadPrivateCalls, 0);
		EXPECT_EQ (crypto.loadPublicCalls, 0);

		std::filesystem::remove (privPath, ec);
		std::filesystem::remove (pubPath, ec);
	}

	/**
	 * Infrastructure test for tester helper methods.
	 * This validates testutil::ensureJwtKeyPairInDir(...) in the branch
	 * where files exist: it must load keys without regenerating/resaving.
	 */
	TEST_F (JwtTester, EnsureKeyPairInBinaryDirLoadsFilesWhenPresent)
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
			ASSERT_TRUE (privOut.good());
			ASSERT_TRUE (pubOut.good());
		}

		auto error = testutil::ensureJwtKeyPairInDir (jwt, "k-startup", JwtAlg::HS256, binDir, privFile, pubFile);
		ASSERT_EQ (error.code, ErrorCode::Ok);
		EXPECT_EQ (crypto.generateCalls, 0);
		EXPECT_EQ (crypto.savePrivateCalls, 0);
		EXPECT_EQ (crypto.savePublicCalls, 0);
		EXPECT_EQ (crypto.loadPrivateCalls, 1);
		EXPECT_EQ (crypto.loadPublicCalls, 1);
		EXPECT_EQ (std::filesystem::path (crypto.lastPrivatePath).filename().string(), privFile);
		EXPECT_EQ (std::filesystem::path (crypto.lastPublicPath).filename().string(), pubFile);

		std::error_code ec;
		std::filesystem::remove (privPath, ec);
		std::filesystem::remove (pubPath, ec);
	}

} /* namespace ipb::http::jwt */
