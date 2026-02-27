/*********************************************************************************************
 *  Description : Unit tests for Router class with typed parameters and Trie structure
 *  License     : The unlicense (https://unlicense.org)
 *	Copyright	(C) 2026  Ignacio Pomar Ballestero
 ********************************************************************************************/

#include <gtest/gtest.h>
#include "Route.h"
#include <string>
#include <unordered_map>

namespace ipb::http
{
	// Mock Ctx for testing - implementa ICtx
	class MockCtx : public ICtx
	{
		public:
			std::unordered_map<std::string, std::string> params_;

			void setParam (std::string_view name, std::string_view value) override
			{
				params_ [std::string (name)] = std::string (value);
			}

			void clear ()
			{
				params_.clear();
			}

			std::optional<std::string> get (std::string_view name) const
			{
				if (auto it = params_.find (std::string (name)); it != params_.end())
				{
					return it->second;
				}
				return std::nullopt;
			}

			bool empty () const
			{
				return params_.empty();
			}

			size_t size () const
			{
				return params_.size();
			}
	};

}    // namespace ipb::http

using namespace ipb::http;

// ============================================================================
// Test Fixtures
// ============================================================================

class RouterTest : public ::testing::Test
{
	protected:
		Router router;
		MockCtx ctx;

		static void dummyHandler (ICtx &ctx) {}

		void SetUp () override
		{
			ctx.clear();
		}
};

// ============================================================================
// Router::add() Tests - Rutas Básicas
// ============================================================================

TEST_F (RouterTest, AddSimpleRoute)
{
	router.add (HttpMethod::GET, "/users", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->pattern, "/users");
	EXPECT_EQ (result.value()->method, HttpMethod::GET);
	EXPECT_TRUE (ctx.empty());
}

TEST_F (RouterTest, AddRootPath)
{
	router.add (HttpMethod::GET, "/", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->pattern, "/");
}

TEST_F (RouterTest, AddNestedRoute)
{
	router.add (HttpMethod::GET, "/api/v1/users/list", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/api/v1/users/list", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->pattern, "/api/v1/users/list");
}

TEST_F (RouterTest, AddRouteWithMiddleware)
{
	auto &route = router.add (HttpMethod::GET, "/protected", dummyHandler);

	router.addMiddleware (route,
	                      [] (ICtx &ctx, Next next)
	                      {
		                      next();
	                      });

	auto result = router.match (HttpMethod::GET, "/protected", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->middlewares.size(), 1);
}

// ============================================================================
// Router::add() Tests - Múltiples Métodos
// ============================================================================

TEST_F (RouterTest, AddSamePathDifferentMethods)
{
	router.add (HttpMethod::GET, "/users", dummyHandler);
	router.add (HttpMethod::POST, "/users", dummyHandler);
	router.add (HttpMethod::PUT, "/users", dummyHandler);
	router.add (HttpMethod::DELETE_, "/users", dummyHandler);

	MockCtx ctx1, ctx2, ctx3, ctx4;
	auto get_result    = router.match (HttpMethod::GET, "/users", ctx1);
	auto post_result   = router.match (HttpMethod::POST, "/users", ctx2);
	auto put_result    = router.match (HttpMethod::PUT, "/users", ctx3);
	auto delete_result = router.match (HttpMethod::DELETE_, "/users", ctx4);

	ASSERT_TRUE (get_result.has_value());
	ASSERT_TRUE (post_result.has_value());
	ASSERT_TRUE (put_result.has_value());
	ASSERT_TRUE (delete_result.has_value());

	EXPECT_EQ (get_result.value()->method, HttpMethod::GET);
	EXPECT_EQ (post_result.value()->method, HttpMethod::POST);
	EXPECT_EQ (put_result.value()->method, HttpMethod::PUT);
	EXPECT_EQ (delete_result.value()->method, HttpMethod::DELETE_);
}

TEST_F (RouterTest, AddMethodANY)
{
	router.add (HttpMethod::ANY, "/health", dummyHandler);

	MockCtx ctx1, ctx2, ctx3;
	auto get_result  = router.match (HttpMethod::GET, "/health", ctx1);
	auto post_result = router.match (HttpMethod::POST, "/health", ctx2);
	auto put_result  = router.match (HttpMethod::PUT, "/health", ctx3);

	EXPECT_TRUE (get_result.has_value());
	EXPECT_TRUE (post_result.has_value());
	EXPECT_TRUE (put_result.has_value());
}

TEST_F (RouterTest, SpecificMethodOverridesANY)
{
	router.add (HttpMethod::ANY, "/api", dummyHandler);
	router.add (HttpMethod::POST, "/api", dummyHandler);

	MockCtx ctx1, ctx2;
	auto get_result  = router.match (HttpMethod::GET, "/api", ctx1);
	auto post_result = router.match (HttpMethod::POST, "/api", ctx2);

	ASSERT_TRUE (get_result.has_value());
	ASSERT_TRUE (post_result.has_value());

	// POST debe usar la ruta específica, no ANY
	EXPECT_EQ (post_result.value()->method, HttpMethod::POST);
	// GET debe usar ANY
	EXPECT_EQ (get_result.value()->method, HttpMethod::ANY);
}

// ============================================================================
// Router::add() Tests - Parámetros Genéricos
// ============================================================================

TEST_F (RouterTest, AddRouteWithGenericParameter)
{
	router.add (HttpMethod::GET, "/users/<id>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/123", ctx);

	ASSERT_TRUE (result.has_value());
	ASSERT_EQ (ctx.size(), 1);
	EXPECT_EQ (ctx.get ("id").value(), "123");
}

TEST_F (RouterTest, AddRouteWithMultipleGenericParameters)
{
	router.add (HttpMethod::GET, "/users/<userId>/posts/<postId>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/42/posts/100", ctx);

	ASSERT_TRUE (result.has_value());
	ASSERT_EQ (ctx.size(), 2);
	EXPECT_EQ (ctx.get ("userId").value(), "42");
	EXPECT_EQ (ctx.get ("postId").value(), "100");
}

// ============================================================================
// Router::add() Tests - Parámetros Tipados
// ============================================================================

TEST_F (RouterTest, AddRouteWithIntParameter)
{
	router.add (HttpMethod::GET, "/users/<id:int>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/123", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (ctx.get ("id").value(), "123");

	// No debe matchear con string
	ctx.clear();
	auto no_match = router.match (HttpMethod::GET, "/users/john", ctx);
	EXPECT_FALSE (no_match.has_value());
}

TEST_F (RouterTest, AddRouteWithStringParameter)
{
	router.add (HttpMethod::GET, "/users/<alias:string>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/john", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (ctx.get ("alias").value(), "john");
}

TEST_F (RouterTest, AddRouteWithUUIDParameter)
{
	router.add (HttpMethod::GET, "/resources/<id:uuid>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/resources/550e8400-e29b-41d4-a716-446655440000", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (ctx.get ("id").value(), "550e8400-e29b-41d4-a716-446655440000");

	// No debe matchear con formato incorrecto
	ctx.clear();
	auto no_match = router.match (HttpMethod::GET, "/resources/not-a-uuid", ctx);
	EXPECT_FALSE (no_match.has_value());
}

TEST_F (RouterTest, AddRouteWithFloatParameter)
{
	router.add (HttpMethod::GET, "/values/<amount:float>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/values/123.45", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (ctx.get ("amount").value(), "123.45");

	// También debe matchear enteros
	ctx.clear();
	auto int_result = router.match (HttpMethod::GET, "/values/100", ctx);
	ASSERT_TRUE (int_result.has_value());
}

TEST_F (RouterTest, AddRouteWithMixedTypedParameters)
{
	router.add (HttpMethod::GET, "/users/<userId:int>/posts/<slug:string>/comments/<commentId:int>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/42/posts/my-article/comments/99", ctx);

	ASSERT_TRUE (result.has_value());
	ASSERT_EQ (ctx.size(), 3);
	EXPECT_EQ (ctx.get ("userId").value(), "42");
	EXPECT_EQ (ctx.get ("slug").value(), "my-article");
	EXPECT_EQ (ctx.get ("commentId").value(), "99");
}

// ============================================================================
// Router::match() Tests - Prioridades
// ============================================================================

TEST_F (RouterTest, LiteralHasPriorityOverParameter)
{
	router.add (HttpMethod::GET, "/users/<id:int>", dummyHandler);
	router.add (HttpMethod::GET, "/users/new", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/new", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->pattern, "/users/new");
	EXPECT_TRUE (ctx.empty());    // No debe capturar "new" como parámetro
}

TEST_F (RouterTest, IntParameterHasPriorityOverString)
{
	router.add (HttpMethod::GET, "/users/<id:int>", dummyHandler);
	router.add (HttpMethod::GET, "/users/<alias:string>", dummyHandler);

	// Número debe matchear con int primero
	auto int_result = router.match (HttpMethod::GET, "/users/123", ctx);
	ASSERT_TRUE (int_result.has_value());
	EXPECT_EQ (int_result.value()->pattern, "/users/<id:int>");
	EXPECT_EQ (ctx.get ("id").value(), "123");

	ctx.clear();

	// String no numérico debe matchear con string
	auto string_result = router.match (HttpMethod::GET, "/users/john", ctx);
	ASSERT_TRUE (string_result.has_value());
	EXPECT_EQ (string_result.value()->pattern, "/users/<alias:string>");
	EXPECT_EQ (ctx.get ("alias").value(), "john");
}

TEST_F (RouterTest, TypedParameterHasPriorityOverGeneric)
{
	router.add (HttpMethod::GET, "/items/<id:int>", dummyHandler);
	router.add (HttpMethod::GET, "/items/<any>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/items/456", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->pattern, "/items/<id:int>");
	EXPECT_EQ (ctx.get ("id").value(), "456");
}

// ============================================================================
// Router::match() Tests - Edge Cases
// ============================================================================

TEST_F (RouterTest, MatchNotFound)
{
	router.add (HttpMethod::GET, "/users", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/posts", ctx);

	EXPECT_FALSE (result.has_value());
	EXPECT_TRUE (ctx.empty());
}

TEST_F (RouterTest, MatchWrongMethod)
{
	router.add (HttpMethod::GET, "/users", dummyHandler);

	auto result = router.match (HttpMethod::POST, "/users", ctx);

	EXPECT_FALSE (result.has_value());
}

TEST_F (RouterTest, MatchTrailingSlashNormalization)
{
	router.add (HttpMethod::GET, "/users", dummyHandler);

	MockCtx ctx1, ctx2;
	auto without_slash = router.match (HttpMethod::GET, "/users", ctx1);
	auto with_slash    = router.match (HttpMethod::GET, "/users/", ctx2);

	EXPECT_TRUE (without_slash.has_value());
	EXPECT_TRUE (with_slash.has_value());    // Debe normalizar
}

TEST_F (RouterTest, MatchParameterWithSpecialCharacters)
{
	router.add (HttpMethod::GET, "/files/<filename>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/files/document-2024.pdf", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (ctx.get ("filename").value(), "document-2024.pdf");
}

TEST_F (RouterTest, MatchVeryLongPath)
{
	router.add (HttpMethod::GET, "/a/b/c/d/e/f/g/h/i/j", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/a/b/c/d/e/f/g/h/i/j", ctx);

	ASSERT_TRUE (result.has_value());
}

// ============================================================================
// Router::fromMethodString() Tests
// ============================================================================

TEST_F (RouterTest, FromMethodString_AllMethods)
{
	EXPECT_EQ (Router::fromMethodString ("GET"), HttpMethod::GET);
	EXPECT_EQ (Router::fromMethodString ("POST"), HttpMethod::POST);
	EXPECT_EQ (Router::fromMethodString ("PUT"), HttpMethod::PUT);
	EXPECT_EQ (Router::fromMethodString ("PATCH"), HttpMethod::PATCH);
	EXPECT_EQ (Router::fromMethodString ("DELETE"), HttpMethod::DELETE_);
	EXPECT_EQ (Router::fromMethodString ("OPTIONS"), HttpMethod::OPTIONS);
	EXPECT_EQ (Router::fromMethodString ("HEAD"), HttpMethod::HEAD);
}

TEST_F (RouterTest, FromMethodString_InvalidDefaultsToGET)
{
	EXPECT_EQ (Router::fromMethodString ("INVALID"), HttpMethod::GET);
	EXPECT_EQ (Router::fromMethodString (""), HttpMethod::GET);
	EXPECT_EQ (Router::fromMethodString ("get"), HttpMethod::GET);    // Case sensitive
}

// ============================================================================
// Router::addMiddleware() Tests
// ============================================================================

TEST_F (RouterTest, AddMiddlewareToExistingRoute)
{
	auto &route = router.add (HttpMethod::GET, "/users", dummyHandler);

	bool added = router.addMiddleware (route,
	                                   [] (ICtx &ctx, Next next)
	                                   {
		                                   next();
	                                   });

	EXPECT_TRUE (added);

	auto result = router.match (HttpMethod::GET, "/users", ctx);
	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->middlewares.size(), 1);
}

// ============================================================================
// Complex Scenario Tests
// ============================================================================

TEST_F (RouterTest, ComplexRESTAPI)
{
	// Simular una API REST completa
	router.add (HttpMethod::GET, "/api/v1/users", dummyHandler);
	router.add (HttpMethod::POST, "/api/v1/users", dummyHandler);
	router.add (HttpMethod::GET, "/api/v1/users/<id:int>", dummyHandler);
	router.add (HttpMethod::PUT, "/api/v1/users/<id:int>", dummyHandler);
	router.add (HttpMethod::DELETE_, "/api/v1/users/<id:int>", dummyHandler);
	router.add (HttpMethod::GET, "/api/v1/users/<id:int>/posts", dummyHandler);
	router.add (HttpMethod::POST, "/api/v1/users/<id:int>/posts", dummyHandler);

	// Verificar todas las rutas
	MockCtx ctx1;
	auto get_users = router.match (HttpMethod::GET, "/api/v1/users", ctx1);
	EXPECT_TRUE (get_users.has_value());

	MockCtx ctx2;
	auto get_user = router.match (HttpMethod::GET, "/api/v1/users/42", ctx2);
	EXPECT_TRUE (get_user.has_value());
	EXPECT_EQ (ctx2.get ("id").value(), "42");

	MockCtx ctx3;
	auto get_posts = router.match (HttpMethod::GET, "/api/v1/users/42/posts", ctx3);
	EXPECT_TRUE (get_posts.has_value());
	EXPECT_EQ (ctx3.get ("id").value(), "42");
}

TEST_F (RouterTest, MultipleRoutersIndependent)
{
	Router router1;
	Router router2;

	router1.add (HttpMethod::GET, "/users", dummyHandler);
	router2.add (HttpMethod::GET, "/posts", dummyHandler);

	MockCtx ctx1, ctx2;
	auto result1 = router1.match (HttpMethod::GET, "/users", ctx1);
	auto result2 = router1.match (HttpMethod::GET, "/posts", ctx2);

	EXPECT_TRUE (result1.has_value());
	EXPECT_FALSE (result2.has_value());    // router1 no debe tener /posts
}

TEST_F (RouterTest, AddRouteWithBase64IdParameter)
{
	router.add (HttpMethod::GET, "/resources/<id:base64id>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/resources/AbCdEfGhIjKlMnOpQrStUv", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (ctx.get ("id").value(), "AbCdEfGhIjKlMnOpQrStUv");

	// Invalid value (contains '+' which is not Base64URL)
	ctx.clear();
	auto no_match_invalid_char = router.match (HttpMethod::GET, "/resources/AbCdEfGhIjKlMnOpQrStU+", ctx);
	EXPECT_FALSE (no_match_invalid_char.has_value());

	// Invalid value (wrong length)
	ctx.clear();
	auto no_match_invalid_len = router.match (HttpMethod::GET, "/resources/AbCdEfGhIjKlMnOpQrStU", ctx);
	EXPECT_FALSE (no_match_invalid_len.has_value());
}

TEST_F (RouterTest, AddRouteWithBase64IdParameter_Padded)
{
	router.add (HttpMethod::GET, "/resources/<id:base64id>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/resources/AbCdEfGhIjKlMnOpQrStUv==", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (ctx.get ("id").value(), "AbCdEfGhIjKlMnOpQrStUv==");
}

TEST_F (RouterTest, Base64IdParameterHasPriorityOverString)
{
	router.add (HttpMethod::GET, "/tokens/<id:base64id>", dummyHandler);
	router.add (HttpMethod::GET, "/tokens/<value:string>", dummyHandler);

	// Base64URL-like token should match base64id before string
	auto result = router.match (HttpMethod::GET, "/tokens/AbCdEfGhIjKlMnOpQrStUv", ctx);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->pattern, "/tokens/<id:base64id>");
	EXPECT_EQ (ctx.get ("id").value(), "AbCdEfGhIjKlMnOpQrStUv");
}
