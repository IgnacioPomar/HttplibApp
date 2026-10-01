/*********************************************************************************************
 *  Description : API DRAFT (not compiled) - specification of the pending cpp-httplib integration
 *  License     : The unlicense (https://unlicense.org)
 *	Copyright	(C) 2026  Ignacio Pomar Ballestero
 *
 *  Tests written before the code: they describe the planned facade over httplib::Server
 *  (HttplibApp, Ctx, Next, Middleware, HttpServerConfig). Those headers do not exist yet, and
 *  they will be hand written (they are not generated). When the API is implemented, this file
 *  must be translated to Catch2 and moved to test/.
 ********************************************************************************************/

#include <gtest/gtest.h>
#include "HttplibApp/httplib_app.hpp"
#include "HttplibApp/ctx.hpp"

using namespace ipb::http;

// ============================================================================
// Test Fixtures
// ============================================================================

class HttplibAppTest : public ::testing::Test
{
	protected:
		HttpServerConfig default_config;

		void SetUp () override
		{
			default_config.host = "127.0.0.1";
			default_config.port = 9999;
		}
};

// ============================================================================
// Constructor Tests
// ============================================================================

TEST_F (HttplibAppTest, DefaultConstructor)
{
	HttplibApp app;

	EXPECT_EQ (app.config().host, "0.0.0.0");
	EXPECT_EQ (app.config().port, 8080);
	EXPECT_EQ (app.config().threads, 0);
	EXPECT_TRUE (app.config().normalize_trailing_slash);
}

TEST_F (HttplibAppTest, CustomConfigConstructor)
{
	HttpServerConfig cfg;
	cfg.host                     = "localhost";
	cfg.port                     = 3000;
	cfg.threads                  = 4;
	cfg.normalize_trailing_slash = false;

	HttplibApp app (cfg);

	EXPECT_EQ (app.config().host, "localhost");
	EXPECT_EQ (app.config().port, 3000);
	EXPECT_EQ (app.config().threads, 4);
	EXPECT_FALSE (app.config().normalize_trailing_slash);
}

// ============================================================================
// Route Registration Tests
// ============================================================================

TEST_F (HttplibAppTest, RegisterGetRoute)
{
	HttplibApp app (default_config);

	bool handler_called = false;
	app.get ("/test",
	         [&] (Ctx &ctx)
	         {
		         handler_called = true;
	         });

	// La ruta se registra sin error
	SUCCEED();
}

TEST_F (HttplibAppTest, RegisterPostRoute)
{
	HttplibApp app (default_config);

	app.post ("/users",
	          [] (Ctx &ctx)
	          {
	          });

	SUCCEED();
}

TEST_F (HttplibAppTest, RegisterPutRoute)
{
	HttplibApp app (default_config);

	app.put ("/users/<id>",
	         [] (Ctx &ctx)
	         {
	         });

	SUCCEED();
}

TEST_F (HttplibAppTest, RegisterPatchRoute)
{
	HttplibApp app (default_config);

	app.patch ("/users/<id>",
	           [] (Ctx &ctx)
	           {
	           });

	SUCCEED();
}

TEST_F (HttplibAppTest, RegisterDeleteRoute)
{
	HttplibApp app (default_config);

	app.del ("/users/<id>",
	         [] (Ctx &ctx)
	         {
	         });

	SUCCEED();
}

TEST_F (HttplibAppTest, RegisterOptionsRoute)
{
	HttplibApp app (default_config);

	app.options ("/api",
	             [] (Ctx &ctx)
	             {
	             });

	SUCCEED();
}

TEST_F (HttplibAppTest, RegisterAnyRoute)
{
	HttplibApp app (default_config);

	app.any ("/wildcard",
	         [] (Ctx &ctx)
	         {
	         });

	SUCCEED();
}

TEST_F (HttplibAppTest, RegisterMultipleRoutes)
{
	HttplibApp app (default_config);

	app.get ("/users",
	         [] (Ctx &ctx)
	         {
	         });
	app.post ("/users",
	          [] (Ctx &ctx)
	          {
	          });
	app.get ("/posts",
	         [] (Ctx &ctx)
	         {
	         });

	SUCCEED();
}

TEST_F (HttplibAppTest, ChainedRouteRegistration)
{
	HttplibApp app (default_config);

	app.get ("/a",
	         [] (Ctx &ctx)
	         {
	         })
	    .post ("/b",
	           [] (Ctx &ctx)
	           {
	           })
	    .put ("/c",
	          [] (Ctx &ctx)
	          {
	          });

	SUCCEED();
}

// ============================================================================
// Middleware Tests
// ============================================================================

TEST_F (HttplibAppTest, UseGlobalMiddleware)
{
	HttplibApp app (default_config);

	bool middleware_called = false;
	app.use (
	    [&] (Ctx &ctx, Next next)
	    {
		    middleware_called = true;
		    next();
	    });

	SUCCEED();
}

TEST_F (HttplibAppTest, UseMultipleGlobalMiddlewares)
{
	HttplibApp app (default_config);

	app.use (
	    [] (Ctx &ctx, Next next)
	    {
		    next();
	    });
	app.use (
	    [] (Ctx &ctx, Next next)
	    {
		    next();
	    });
	app.use (
	    [] (Ctx &ctx, Next next)
	    {
		    next();
	    });

	SUCCEED();
}

TEST_F (HttplibAppTest, RouteSpecificMiddleware)
{
	HttplibApp app (default_config);

	std::vector<Middleware> mws;
	mws.push_back (
	    [] (Ctx &ctx, Next next)
	    {
		    next();
	    });

	app.get (
	    "/protected",
	    [] (Ctx &ctx)
	    {
	    },
	    mws);

	SUCCEED();
}

// ============================================================================
// Config Tests
// ============================================================================

TEST_F (HttplibAppTest, GetConfig)
{
	HttplibApp app (default_config);

	const auto &cfg = app.config();

	EXPECT_EQ (cfg.host, "127.0.0.1");
	EXPECT_EQ (cfg.port, 9999);
}

TEST_F (HttplibAppTest, ModifyConfig)
{
	HttplibApp app;

	app.config().host = "192.168.1.1";
	app.config().port = 5000;

	EXPECT_EQ (app.config().host, "192.168.1.1");
	EXPECT_EQ (app.config().port, 5000);
}

// ============================================================================
// Path Normalization Tests (métodos privados - test indirecto)
// ============================================================================

TEST_F (HttplibAppTest, RouteWithTrailingSlash)
{
	HttplibApp app (default_config);
	app.config().normalize_trailing_slash = true;

	app.get ("/users/",
	         [] (Ctx &ctx)
	         {
	         });

	SUCCEED();
}

TEST_F (HttplibAppTest, RouteWithoutTrailingSlash)
{
	HttplibApp app (default_config);

	app.get ("/users",
	         [] (Ctx &ctx)
	         {
	         });

	SUCCEED();
}

TEST_F (HttplibAppTest, RouteWithParameters)
{
	HttplibApp app (default_config);

	app.get ("/users/<id>/posts/<postId>",
	         [] (Ctx &ctx)
	         {
	         });

	SUCCEED();
}
