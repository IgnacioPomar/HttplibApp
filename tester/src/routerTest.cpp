#include <gtest/gtest.h>
#include "../include/router.hpp"
#include "../include/types.hpp"
#include "../include/ctx.hpp"

#include <httplib.h>
#include <string>
#include <unordered_map>

using namespace ipb::http;

// ============================================================================
// Test Fixtures
// ============================================================================

class RouterTest : public ::testing::Test
{
	protected:
		Router router;
		std::unordered_map<std::string, std::string> params;

		void SetUp () override
		{
			params.clear();
		}
};

// ============================================================================
// Router::add() Tests
// ============================================================================

TEST_F (RouterTest, AddSimpleRoute)
{
	bool handler_called = false;

	router.add (Router::Method::GET, "/users",
	            [&] (Ctx &ctx)
	            {
		            handler_called = true;
	            });

	auto result = router.match (Router::Method::GET, "/users", params);

	ASSERT_TRUE (result.has_value());
	EXPECT_NE (result.value(), nullptr);
	EXPECT_EQ (result.value()->pattern, "/users");
}

TEST_F (RouterTest, AddMultipleRoutes)
{
	router.add (Router::Method::GET, "/users",
	            [] (Ctx &ctx)
	            {
	            });
	router.add (Router::Method::POST, "/users",
	            [] (Ctx &ctx)
	            {
	            });
	router.add (Router::Method::GET, "/posts",
	            [] (Ctx &ctx)
	            {
	            });

	auto get_users  = router.match (Router::Method::GET, "/users", params);
	auto post_users = router.match (Router::Method::POST, "/users", params);
	auto get_posts  = router.match (Router::Method::GET, "/posts", params);

	ASSERT_TRUE (get_users.has_value());
	ASSERT_TRUE (post_users.has_value());
	ASSERT_TRUE (get_posts.has_value());

	// Verificar que cada ruta tiene su patrón correcto
	EXPECT_EQ (get_users.value()->pattern, "/users");
	EXPECT_EQ (get_users.value()->method, Router::Method::GET);

	EXPECT_EQ (post_users.value()->pattern, "/users");
	EXPECT_EQ (post_users.value()->method, Router::Method::POST);

	EXPECT_EQ (get_posts.value()->pattern, "/posts");
	EXPECT_EQ (get_posts.value()->method, Router::Method::GET);
}

TEST_F (RouterTest, AddRouteWithMiddleware)
{
	std::vector<Middleware> mws;
	mws.push_back (
	    [] (Ctx &ctx, Next next)
	    {
		    next();
	    });

	router.add (
	    Router::Method::GET, "/protected",
	    [] (Ctx &ctx)
	    {
	    },
	    mws);

	auto result = router.match (Router::Method::GET, "/protected", params);

	ASSERT_TRUE (result.has_value());
	EXPECT_FALSE (result.value()->mws.empty());
}

// ============================================================================
// Router::match() Tests - Rutas literales
// ============================================================================

TEST_F (RouterTest, MatchExactPath)
{
	router.add (Router::Method::GET, "/api/users",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/api/users", params);

	ASSERT_TRUE (result.has_value());
	EXPECT_TRUE (params.empty());
}

TEST_F (RouterTest, MatchRootPath)
{
	router.add (Router::Method::GET, "/",
	            [] (Ctx &ctx)
	            {
	            });

	// El path raíz debe matchear con o sin trailing slash
	auto result1 = router.match (Router::Method::GET, "/", params);
	auto result2 = router.match (Router::Method::GET, "", params);

	// Al menos uno debe funcionar (dependiendo de la implementación)
	EXPECT_TRUE (result1.has_value() || result2.has_value());
}

TEST_F (RouterTest, MatchNotFound)
{
	router.add (Router::Method::GET, "/users",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/posts", params);

	EXPECT_FALSE (result.has_value());
}

TEST_F (RouterTest, MatchWrongMethod)
{
	router.add (Router::Method::GET, "/users",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::POST, "/users", params);

	EXPECT_FALSE (result.has_value());
}

TEST_F (RouterTest, MatchNestedPath)
{
	router.add (Router::Method::GET, "/api/v1/users/list",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/api/v1/users/list", params);

	ASSERT_TRUE (result.has_value());
}

// ============================================================================
// Router::match() Tests - Parámetros
// ============================================================================

TEST_F (RouterTest, MatchSingleParameter)
{
	router.add (Router::Method::GET, "/users/<id>",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/users/123", params);

	ASSERT_TRUE (result.has_value());
	ASSERT_EQ (params.size(), 1);
	EXPECT_EQ (params ["id"], "123");
}

TEST_F (RouterTest, MatchMultipleParameters)
{
	router.add (Router::Method::GET, "/users/<userId>/posts/<postId>",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/users/42/posts/100", params);

	ASSERT_TRUE (result.has_value());
	ASSERT_EQ (params.size(), 2);
	EXPECT_EQ (params ["userId"], "42");
	EXPECT_EQ (params ["postId"], "100");
}

TEST_F (RouterTest, MatchParameterWithSpecialCharacters)
{
	router.add (Router::Method::GET, "/files/<filename>",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/files/document-2024.pdf", params);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (params ["filename"], "document-2024.pdf");
}

TEST_F (RouterTest, MatchMixedLiteralAndParameter)
{
	router.add (Router::Method::GET, "/api/users/<id>/profile",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/api/users/999/profile", params);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (params ["id"], "999");
}

// ============================================================================
// Router::match() Tests - Prioridad
// ============================================================================

TEST_F (RouterTest, MatchLiteralOverParameter)
{
	// Literal debe tener mayor prioridad que parámetro
	router.add (Router::Method::GET, "/users/<id>",
	            [] (Ctx &ctx)
	            {
	            });
	router.add (Router::Method::GET, "/users/new",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/users/new", params);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->pattern, "/users/new");
	EXPECT_TRUE (params.empty());
}

TEST_F (RouterTest, MatchParameterWhenNoLiteral)
{
	router.add (Router::Method::GET, "/users/<id>",
	            [] (Ctx &ctx)
	            {
	            });
	router.add (Router::Method::GET, "/users/new",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/users/123", params);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->pattern, "/users/<id>");
	ASSERT_EQ (params.size(), 1);
	EXPECT_EQ (params ["id"], "123");
}

// ============================================================================
// Router::match() Tests - Method::ANY
// ============================================================================

TEST_F (RouterTest, MatchAnyMethod)
{
	router.add (Router::Method::ANY, "/health",
	            [] (Ctx &ctx)
	            {
	            });

	auto get_result  = router.match (Router::Method::GET, "/health", params);
	auto post_result = router.match (Router::Method::POST, "/health", params);
	auto put_result  = router.match (Router::Method::PUT, "/health", params);

	EXPECT_TRUE (get_result.has_value());
	EXPECT_TRUE (post_result.has_value());
	EXPECT_TRUE (put_result.has_value());
}

TEST_F (RouterTest, SpecificMethodOverridesAny)
{
	router.add (Router::Method::ANY, "/api",
	            [] (Ctx &ctx)
	            {
	            });
	router.add (Router::Method::POST, "/api",
	            [] (Ctx &ctx)
	            {
	            });

	auto get_result  = router.match (Router::Method::GET, "/api", params);
	auto post_result = router.match (Router::Method::POST, "/api", params);

	ASSERT_TRUE (get_result.has_value());
	ASSERT_TRUE (post_result.has_value());

	// POST debe coincidir con la ruta específica primero
	EXPECT_EQ (post_result.value()->method, Router::Method::POST);
}

// ============================================================================
// Router::from_method_string() Tests
// ============================================================================

TEST_F (RouterTest, FromMethodString_GET)
{
	auto method = Router::from_method_string ("GET");
	EXPECT_EQ (method, Router::Method::GET);
}

TEST_F (RouterTest, FromMethodString_POST)
{
	auto method = Router::from_method_string ("POST");
	EXPECT_EQ (method, Router::Method::POST);
}

TEST_F (RouterTest, FromMethodString_PUT)
{
	auto method = Router::from_method_string ("PUT");
	EXPECT_EQ (method, Router::Method::PUT);
}

TEST_F (RouterTest, FromMethodString_PATCH)
{
	auto method = Router::from_method_string ("PATCH");
	EXPECT_EQ (method, Router::Method::PATCH);
}

TEST_F (RouterTest, FromMethodString_DELETE)
{
	auto method = Router::from_method_string ("DELETE");
	EXPECT_EQ (method, Router::Method::DELETE_);
}

TEST_F (RouterTest, FromMethodString_OPTIONS)
{
	auto method = Router::from_method_string ("OPTIONS");
	EXPECT_EQ (method, Router::Method::OPTIONS);
}

TEST_F (RouterTest, FromMethodString_HEAD)
{
	auto method = Router::from_method_string ("HEAD");
	EXPECT_EQ (method, Router::Method::HEAD);
}

TEST_F (RouterTest, FromMethodString_UnknownDefaultsToGET)
{
	auto method = Router::from_method_string ("INVALID");
	EXPECT_EQ (method, Router::Method::GET);
}

TEST_F (RouterTest, FromMethodString_CaseSensitive)
{
	auto method = Router::from_method_string ("get");
	EXPECT_EQ (method, Router::Method::GET);    // Fallback por case-sensitive
}

// ============================================================================
// Router Compilation Tests (compile() - indirecto)
// ============================================================================

TEST_F (RouterTest, CompileSimplePath)
{
	router.add (Router::Method::GET, "/users",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/users", params);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->segments.size(), 1);
}

TEST_F (RouterTest, CompilePathWithMultipleSegments)
{
	router.add (Router::Method::GET, "/api/v1/users",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/api/v1/users", params);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->segments.size(), 3);
}

TEST_F (RouterTest, CompilePathWithParameter)
{
	router.add (Router::Method::GET, "/users/<id>",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/users/123", params);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (result.value()->segments.size(), 2);
}

TEST_F (RouterTest, CompileEmptyPath)
{
	router.add (Router::Method::GET, "/",
	            [] (Ctx &ctx)
	            {
	            });

	// El path "/" se compila a 0 segmentos
	auto result = router.match (Router::Method::GET, "/", params);

	ASSERT_TRUE (result.has_value());
	// Verificar que tiene 0 segmentos (path raíz)
	EXPECT_EQ (result.value()->segments.size(), 0);
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F (RouterTest, MatchEmptyParamsMapClearedOnNoMatch)
{
	router.add (Router::Method::GET, "/users/<id>",
	            [] (Ctx &ctx)
	            {
	            });

	params ["existing"] = "value";

	auto result = router.match (Router::Method::GET, "/posts/123", params);

	EXPECT_FALSE (result.has_value());
	EXPECT_TRUE (params.empty());
}

TEST_F (RouterTest, MatchTrailingSlashSensitive)
{
	router.add (Router::Method::GET, "/users",
	            [] (Ctx &ctx)
	            {
	            });

	auto without_slash = router.match (Router::Method::GET, "/users", params);
	auto with_slash    = router.match (Router::Method::GET, "/users/", params);

	EXPECT_TRUE (without_slash.has_value());
	EXPECT_FALSE (with_slash.has_value());    // Debe normalizar externamente
}

TEST_F (RouterTest, MatchVeryLongPath)
{
	router.add (Router::Method::GET, "/a/b/c/d/e/f/g/h/i/j",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/a/b/c/d/e/f/g/h/i/j", params);

	ASSERT_TRUE (result.has_value());
}

TEST_F (RouterTest, MatchNumericParameters)
{
	router.add (Router::Method::GET, "/items/<id>",
	            [] (Ctx &ctx)
	            {
	            });

	auto result = router.match (Router::Method::GET, "/items/999999", params);

	ASSERT_TRUE (result.has_value());
	EXPECT_EQ (params ["id"], "999999");
}

TEST_F (RouterTest, MultipleRoutesWithDifferentMethods)
{
	router.add (Router::Method::GET, "/resource",
	            [] (Ctx &ctx)
	            {
	            });
	router.add (Router::Method::POST, "/resource",
	            [] (Ctx &ctx)
	            {
	            });
	router.add (Router::Method::PUT, "/resource",
	            [] (Ctx &ctx)
	            {
	            });
	router.add (Router::Method::DELETE_, "/resource",
	            [] (Ctx &ctx)
	            {
	            });

	auto get_r  = router.match (Router::Method::GET, "/resource", params);
	auto post_r = router.match (Router::Method::POST, "/resource", params);
	auto put_r  = router.match (Router::Method::PUT, "/resource", params);
	auto del_r  = router.match (Router::Method::DELETE_, "/resource", params);

	EXPECT_TRUE (get_r.has_value());
	EXPECT_TRUE (post_r.has_value());
	EXPECT_TRUE (put_r.has_value());
	EXPECT_TRUE (del_r.has_value());
}
