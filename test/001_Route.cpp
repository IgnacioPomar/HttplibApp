/*********************************************************************************************
 *  Description : Unit tests for Router class with typed parameters and Trie structure
 *  License     : The unlicense (https://unlicense.org)
 *	Copyright	(C) 2026  Ignacio Pomar Ballestero
 ********************************************************************************************/

#include <catch2/catch_test_macros.hpp>
#include "HttplibApp/Route.h"
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

class RouterTest
{
	protected:
		Router router;
		MockCtx ctx;

		static void dummyHandler (ICtx &) {}
};

// ============================================================================
// Router::add() Tests - Rutas Básicas
// ============================================================================

TEST_CASE_METHOD (RouterTest, "AddSimpleRoute", "[route]")
{
	router.add (HttpMethod::GET, "/users", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users", ctx);

	REQUIRE (result.has_value());
	CHECK (result.value().get().pattern == "/users");
	CHECK (result.value().get().method == HttpMethod::GET);
	CHECK (ctx.empty());
}

TEST_CASE_METHOD (RouterTest, "AddRootPath", "[route]")
{
	router.add (HttpMethod::GET, "/", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/", ctx);

	REQUIRE (result.has_value());
	CHECK (result.value().get().pattern == "/");
}

TEST_CASE_METHOD (RouterTest, "AddNestedRoute", "[route]")
{
	router.add (HttpMethod::GET, "/api/v1/users/list", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/api/v1/users/list", ctx);

	REQUIRE (result.has_value());
	CHECK (result.value().get().pattern == "/api/v1/users/list");
}

TEST_CASE_METHOD (RouterTest, "AddRouteWithMiddleware", "[route]")
{
	auto &route = router.add (HttpMethod::GET, "/protected", dummyHandler);

	router.addMiddleware (route,
	                      [] (ICtx &, IMiddlewareNext &next)
	                      {
		                      next.next();
	                      });

	auto result = router.match (HttpMethod::GET, "/protected", ctx);

	REQUIRE (result.has_value());
	CHECK (result.value().get().middlewares.size() == 1);
}

// ============================================================================
// Router::add() Tests - Múltiples Métodos
// ============================================================================

TEST_CASE_METHOD (RouterTest, "AddSamePathDifferentMethods", "[route]")
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

	REQUIRE (get_result.has_value());
	REQUIRE (post_result.has_value());
	REQUIRE (put_result.has_value());
	REQUIRE (delete_result.has_value());

	CHECK (get_result.value().get().method == HttpMethod::GET);
	CHECK (post_result.value().get().method == HttpMethod::POST);
	CHECK (put_result.value().get().method == HttpMethod::PUT);
	CHECK (delete_result.value().get().method == HttpMethod::DELETE_);
}

TEST_CASE_METHOD (RouterTest, "AddMethodANY", "[route]")
{
	router.add (HttpMethod::ANY, "/health", dummyHandler);

	MockCtx ctx1, ctx2, ctx3;
	auto get_result  = router.match (HttpMethod::GET, "/health", ctx1);
	auto post_result = router.match (HttpMethod::POST, "/health", ctx2);
	auto put_result  = router.match (HttpMethod::PUT, "/health", ctx3);

	CHECK (get_result.has_value());
	CHECK (post_result.has_value());
	CHECK (put_result.has_value());
}

TEST_CASE_METHOD (RouterTest, "SpecificMethodOverridesANY", "[route]")
{
	router.add (HttpMethod::ANY, "/api", dummyHandler);
	router.add (HttpMethod::POST, "/api", dummyHandler);

	MockCtx ctx1, ctx2;
	auto get_result  = router.match (HttpMethod::GET, "/api", ctx1);
	auto post_result = router.match (HttpMethod::POST, "/api", ctx2);

	REQUIRE (get_result.has_value());
	REQUIRE (post_result.has_value());

	// POST debe usar la ruta específica, no ANY
	CHECK (post_result.value().get().method == HttpMethod::POST);
	// GET debe usar ANY
	CHECK (get_result.value().get().method == HttpMethod::ANY);
}

// ============================================================================
// Router::add() Tests - Parámetros Genéricos
// ============================================================================

TEST_CASE_METHOD (RouterTest, "AddRouteWithGenericParameter", "[route]")
{
	router.add (HttpMethod::GET, "/users/<id>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/123", ctx);

	REQUIRE (result.has_value());
	REQUIRE (ctx.size() == 1);
	CHECK (ctx.get ("id").value() == "123");
}

TEST_CASE_METHOD (RouterTest, "AddRouteWithMultipleGenericParameters", "[route]")
{
	router.add (HttpMethod::GET, "/users/<userId>/posts/<postId>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/42/posts/100", ctx);

	REQUIRE (result.has_value());
	REQUIRE (ctx.size() == 2);
	CHECK (ctx.get ("userId").value() == "42");
	CHECK (ctx.get ("postId").value() == "100");
}

// ============================================================================
// Router::add() Tests - Parámetros Tipados
// ============================================================================

TEST_CASE_METHOD (RouterTest, "AddRouteWithIntParameter", "[route]")
{
	router.add (HttpMethod::GET, "/users/<id:int>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/123", ctx);

	REQUIRE (result.has_value());
	CHECK (ctx.get ("id").value() == "123");

	// No debe matchear con string
	ctx.clear();
	auto no_match = router.match (HttpMethod::GET, "/users/john", ctx);
	CHECK_FALSE (no_match.has_value());
}

TEST_CASE_METHOD (RouterTest, "AddRouteWithStringParameter", "[route]")
{
	router.add (HttpMethod::GET, "/users/<alias:string>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/john", ctx);

	REQUIRE (result.has_value());
	CHECK (ctx.get ("alias").value() == "john");
}

TEST_CASE_METHOD (RouterTest, "AddRouteWithUUIDParameter", "[route]")
{
	router.add (HttpMethod::GET, "/resources/<id:uuid>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/resources/550e8400-e29b-41d4-a716-446655440000", ctx);

	REQUIRE (result.has_value());
	CHECK (ctx.get ("id").value() == "550e8400-e29b-41d4-a716-446655440000");

	// No debe matchear con formato incorrecto
	ctx.clear();
	auto no_match = router.match (HttpMethod::GET, "/resources/not-a-uuid", ctx);
	CHECK_FALSE (no_match.has_value());
}

TEST_CASE_METHOD (RouterTest, "AddRouteWithFloatParameter", "[route]")
{
	router.add (HttpMethod::GET, "/values/<amount:float>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/values/123.45", ctx);

	REQUIRE (result.has_value());
	CHECK (ctx.get ("amount").value() == "123.45");

	// También debe matchear enteros
	ctx.clear();
	auto int_result = router.match (HttpMethod::GET, "/values/100", ctx);
	REQUIRE (int_result.has_value());
}

TEST_CASE_METHOD (RouterTest, "AddRouteWithMixedTypedParameters", "[route]")
{
	router.add (HttpMethod::GET, "/users/<userId:int>/posts/<slug:string>/comments/<commentId:int>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/42/posts/my-article/comments/99", ctx);

	REQUIRE (result.has_value());
	REQUIRE (ctx.size() == 3);
	CHECK (ctx.get ("userId").value() == "42");
	CHECK (ctx.get ("slug").value() == "my-article");
	CHECK (ctx.get ("commentId").value() == "99");
}

// ============================================================================
// Router::match() Tests - Prioridades
// ============================================================================

TEST_CASE_METHOD (RouterTest, "LiteralHasPriorityOverParameter", "[route]")
{
	router.add (HttpMethod::GET, "/users/<id:int>", dummyHandler);
	router.add (HttpMethod::GET, "/users/new", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/users/new", ctx);

	REQUIRE (result.has_value());
	CHECK (result.value().get().pattern == "/users/new");
	CHECK (ctx.empty());    // No debe capturar "new" como parámetro
}

TEST_CASE_METHOD (RouterTest, "IntParameterHasPriorityOverString", "[route]")
{
	router.add (HttpMethod::GET, "/users/<id:int>", dummyHandler);
	router.add (HttpMethod::GET, "/users/<alias:string>", dummyHandler);

	// Número debe matchear con int primero
	auto int_result = router.match (HttpMethod::GET, "/users/123", ctx);
	REQUIRE (int_result.has_value());
	CHECK (int_result.value().get().pattern == "/users/<id:int>");
	CHECK (ctx.get ("id").value() == "123");

	ctx.clear();

	// String no numérico debe matchear con string
	auto string_result = router.match (HttpMethod::GET, "/users/john", ctx);
	REQUIRE (string_result.has_value());
	CHECK (string_result.value().get().pattern == "/users/<alias:string>");
	CHECK (ctx.get ("alias").value() == "john");
}

TEST_CASE_METHOD (RouterTest, "TypedParameterHasPriorityOverGeneric", "[route]")
{
	router.add (HttpMethod::GET, "/items/<id:int>", dummyHandler);
	router.add (HttpMethod::GET, "/items/<any>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/items/456", ctx);

	REQUIRE (result.has_value());
	CHECK (result.value().get().pattern == "/items/<id:int>");
	CHECK (ctx.get ("id").value() == "456");
}

// ============================================================================
// Router::match() Tests - Edge Cases
// ============================================================================

TEST_CASE_METHOD (RouterTest, "MatchNotFound", "[route]")
{
	router.add (HttpMethod::GET, "/users", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/posts", ctx);

	CHECK_FALSE (result.has_value());
	CHECK (ctx.empty());
}

TEST_CASE_METHOD (RouterTest, "MatchWrongMethod", "[route]")
{
	router.add (HttpMethod::GET, "/users", dummyHandler);

	auto result = router.match (HttpMethod::POST, "/users", ctx);

	CHECK_FALSE (result.has_value());
}

TEST_CASE_METHOD (RouterTest, "MatchTrailingSlashNormalization", "[route]")
{
	router.add (HttpMethod::GET, "/users", dummyHandler);

	MockCtx ctx1, ctx2;
	auto without_slash = router.match (HttpMethod::GET, "/users", ctx1);
	auto with_slash    = router.match (HttpMethod::GET, "/users/", ctx2);

	CHECK (without_slash.has_value());
	CHECK (with_slash.has_value());    // Debe normalizar
}

TEST_CASE_METHOD (RouterTest, "MatchParameterWithSpecialCharacters", "[route]")
{
	router.add (HttpMethod::GET, "/files/<filename>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/files/document-2024.pdf", ctx);

	REQUIRE (result.has_value());
	CHECK (ctx.get ("filename").value() == "document-2024.pdf");
}

TEST_CASE_METHOD (RouterTest, "MatchVeryLongPath", "[route]")
{
	router.add (HttpMethod::GET, "/a/b/c/d/e/f/g/h/i/j", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/a/b/c/d/e/f/g/h/i/j", ctx);

	REQUIRE (result.has_value());
}

// ============================================================================
// Router::fromMethodString() Tests
// ============================================================================

TEST_CASE_METHOD (RouterTest, "FromMethodString_AllMethods", "[route]")
{
	CHECK (Router::fromMethodString ("GET") == HttpMethod::GET);
	CHECK (Router::fromMethodString ("POST") == HttpMethod::POST);
	CHECK (Router::fromMethodString ("PUT") == HttpMethod::PUT);
	CHECK (Router::fromMethodString ("PATCH") == HttpMethod::PATCH);
	CHECK (Router::fromMethodString ("DELETE") == HttpMethod::DELETE_);
	CHECK (Router::fromMethodString ("OPTIONS") == HttpMethod::OPTIONS);
	CHECK (Router::fromMethodString ("HEAD") == HttpMethod::HEAD);
}

TEST_CASE_METHOD (RouterTest, "FromMethodString_InvalidDefaultsToGET", "[route]")
{
	CHECK (Router::fromMethodString ("INVALID") == HttpMethod::GET);
	CHECK (Router::fromMethodString ("") == HttpMethod::GET);
	CHECK (Router::fromMethodString ("get") == HttpMethod::GET);    // Case sensitive
}

// ============================================================================
// Router::addMiddleware() Tests
// ============================================================================

TEST_CASE_METHOD (RouterTest, "AddMiddlewareToExistingRoute", "[route]")
{
	auto &route = router.add (HttpMethod::GET, "/users", dummyHandler);

	bool added = router.addMiddleware (route,
	                                   [] (ICtx &, IMiddlewareNext &next)
	                                   {
		                                   next.next();
	                                   });

	CHECK (added);

	auto result = router.match (HttpMethod::GET, "/users", ctx);
	REQUIRE (result.has_value());
	CHECK (result.value().get().middlewares.size() == 1);
}

// ============================================================================
// Complex Scenario Tests
// ============================================================================

TEST_CASE_METHOD (RouterTest, "ComplexRESTAPI", "[route]")
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
	CHECK (get_users.has_value());

	MockCtx ctx2;
	auto get_user = router.match (HttpMethod::GET, "/api/v1/users/42", ctx2);
	CHECK (get_user.has_value());
	CHECK (ctx2.get ("id").value() == "42");

	MockCtx ctx3;
	auto get_posts = router.match (HttpMethod::GET, "/api/v1/users/42/posts", ctx3);
	CHECK (get_posts.has_value());
	CHECK (ctx3.get ("id").value() == "42");
}

TEST_CASE_METHOD (RouterTest, "MultipleRoutersIndependent", "[route]")
{
	Router router1;
	Router router2;

	router1.add (HttpMethod::GET, "/users", dummyHandler);
	router2.add (HttpMethod::GET, "/posts", dummyHandler);

	MockCtx ctx1, ctx2;
	auto result1 = router1.match (HttpMethod::GET, "/users", ctx1);
	auto result2 = router1.match (HttpMethod::GET, "/posts", ctx2);

	CHECK (result1.has_value());
	CHECK_FALSE (result2.has_value());    // router1 no debe tener /posts
}

TEST_CASE_METHOD (RouterTest, "AddRouteWithBase64IdParameter", "[route]")
{
	router.add (HttpMethod::GET, "/resources/<id:base64id>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/resources/AbCdEfGhIjKlMnOpQrStUv", ctx);

	REQUIRE (result.has_value());
	CHECK (ctx.get ("id").value() == "AbCdEfGhIjKlMnOpQrStUv");

	// Invalid value (contains '+' which is not Base64URL)
	ctx.clear();
	auto no_match_invalid_char = router.match (HttpMethod::GET, "/resources/AbCdEfGhIjKlMnOpQrStU+", ctx);
	CHECK_FALSE (no_match_invalid_char.has_value());

	// Invalid value (wrong length)
	ctx.clear();
	auto no_match_invalid_len = router.match (HttpMethod::GET, "/resources/AbCdEfGhIjKlMnOpQrStU", ctx);
	CHECK_FALSE (no_match_invalid_len.has_value());
}

TEST_CASE_METHOD (RouterTest, "AddRouteWithBase64IdParameter_Padded", "[route]")
{
	router.add (HttpMethod::GET, "/resources/<id:base64id>", dummyHandler);

	auto result = router.match (HttpMethod::GET, "/resources/AbCdEfGhIjKlMnOpQrStUv==", ctx);

	REQUIRE (result.has_value());
	CHECK (ctx.get ("id").value() == "AbCdEfGhIjKlMnOpQrStUv==");
}

TEST_CASE_METHOD (RouterTest, "Base64IdParameterHasPriorityOverString", "[route]")
{
	router.add (HttpMethod::GET, "/tokens/<id:base64id>", dummyHandler);
	router.add (HttpMethod::GET, "/tokens/<value:string>", dummyHandler);

	// Base64URL-like token should match base64id before string
	auto result = router.match (HttpMethod::GET, "/tokens/AbCdEfGhIjKlMnOpQrStUv", ctx);

	REQUIRE (result.has_value());
	CHECK (result.value().get().pattern == "/tokens/<id:base64id>");
	CHECK (ctx.get ("id").value() == "AbCdEfGhIjKlMnOpQrStUv");
}

TEST_CASE_METHOD (RouterTest, "MiddlewareChainContinuesAndExecutesHandler", "[route]")
{
	std::vector<std::string> calls;

	auto &route = router.add (HttpMethod::GET, "/pipeline",
	                          [&] (ICtx &)
	                          {
		                          calls.push_back ("handler");
	                          });

	router.addMiddleware (route,
	                      [&] (ICtx &, IMiddlewareNext &next)
	                      {
		                      calls.push_back ("mw1.before");
		                      next.next();
		                      calls.push_back ("mw1.after");
	                      });

	router.addMiddleware (route,
	                      [&] (ICtx &, IMiddlewareNext &next)
	                      {
		                      calls.push_back ("mw2.before");
		                      next.next();
		                      calls.push_back ("mw2.after");
	                      });

	auto result = router.match (HttpMethod::GET, "/pipeline", ctx);
	REQUIRE (result.has_value());

	router.execute (result.value().get(), ctx);

	const std::vector<std::string> expected = {"mw1.before", "mw2.before", "handler", "mw2.after", "mw1.after"};
	CHECK (calls == expected);
}

TEST_CASE_METHOD (RouterTest, "MiddlewareCanInterruptChain", "[route]")
{
	std::vector<std::string> calls;

	auto &route = router.add (HttpMethod::GET, "/blocked",
	                          [&] (ICtx &)
	                          {
		                          calls.push_back ("handler");
	                          });

	router.addMiddleware (route,
	                      [&] (ICtx &, IMiddlewareNext &)
	                      {
		                      calls.push_back ("mw.block");
		                      // Intentionally no next.next(): chain stops here.
	                      });

	router.addMiddleware (route,
	                      [&] (ICtx &, IMiddlewareNext &next)
	                      {
		                      calls.push_back ("mw2.before");
		                      next.next();
	                      });

	auto result = router.match (HttpMethod::GET, "/blocked", ctx);
	REQUIRE (result.has_value());

	router.execute (result.value().get(), ctx);

	const std::vector<std::string> expected = {"mw.block"};
	CHECK (calls == expected);
}

TEST_CASE_METHOD (RouterTest, "MiddlewareCallingNextTwiceDoesNotRunHandlerTwice", "[route]")
{
	int handler_calls = 0;

	auto &route = router.add (HttpMethod::GET, "/double-next",
	                          [&] (ICtx &)
	                          {
		                          ++handler_calls;
	                          });

	router.addMiddleware (route,
	                      [&] (ICtx &, IMiddlewareNext &next)
	                      {
		                      next.next();
		                      next.next();    // Should be ignored by guard.
	                      });

	auto result = router.match (HttpMethod::GET, "/double-next", ctx);
	REQUIRE (result.has_value());

	router.execute (result.value().get(), ctx);

	CHECK (handler_calls == 1);
}

TEST_CASE_METHOD (RouterTest, "GlobalMiddlewaresRunBeforeRouteMiddlewares", "[route]")
{
	std::vector<std::string> calls;

	router.addMiddleware (
	    [&] (ICtx &, IMiddlewareNext &next)
	    {
		    calls.push_back ("g1.before");
		    next.next();
		    calls.push_back ("g1.after");
	    });

	router.addMiddleware (
	    [&] (ICtx &, IMiddlewareNext &next)
	    {
		    calls.push_back ("g2.before");
		    next.next();
		    calls.push_back ("g2.after");
	    });

	auto &route = router.add (HttpMethod::GET, "/global-order",
	                          [&] (ICtx &)
	                          {
		                          calls.push_back ("handler");
	                          });

	router.addMiddleware (route,
	                      [&] (ICtx &, IMiddlewareNext &next)
	                      {
		                      calls.push_back ("r1.before");
		                      next.next();
		                      calls.push_back ("r1.after");
	                      });

	auto result = router.match (HttpMethod::GET, "/global-order", ctx);
	REQUIRE (result.has_value());

	router.execute (result.value().get(), ctx);

	const std::vector<std::string> expected = {"g1.before", "g2.before", "r1.before", "handler",
	                                           "r1.after",  "g2.after",  "g1.after"};
	CHECK (calls == expected);
}

TEST_CASE_METHOD (RouterTest, "GlobalMiddlewareCanInterruptChain", "[route]")
{
	std::vector<std::string> calls;

	router.addMiddleware (
	    [&] (ICtx &, IMiddlewareNext &)
	    {
		    calls.push_back ("g.block");
		    // No next.next(): stop the whole chain.
	    });

	auto &route = router.add (HttpMethod::GET, "/global-block",
	                          [&] (ICtx &)
	                          {
		                          calls.push_back ("handler");
	                          });

	router.addMiddleware (route,
	                      [&] (ICtx &, IMiddlewareNext &next)
	                      {
		                      calls.push_back ("r1.before");
		                      next.next();
	                      });

	auto result = router.match (HttpMethod::GET, "/global-block", ctx);
	REQUIRE (result.has_value());

	router.execute (result.value().get(), ctx);

	const std::vector<std::string> expected = {"g.block"};
	CHECK (calls == expected);
}
