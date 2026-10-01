#include <iostream>
#include <string>
#include "HttplibApp/Route.h"

class Ctx : public ipb::http::ICtx
{
	public:
		std::string id;
		void setParam (std::string_view name, std::string_view value) override
		{
			if (name == "id")
			{
				id = value;
			}
		}
};

int main ()
{
	ipb::http::Router router;
	router.add (ipb::http::HttpMethod::GET, "/users/<id:int>",
	            [] (ipb::http::ICtx &)
	            {
	            });

	Ctx ctx;
	const bool found = router.match (ipb::http::HttpMethod::GET, "/users/42", ctx).has_value() && ctx.id == "42";

	std::cout << "HttplibApp package works: " << (found ? "route found" : "ROUTE NOT FOUND") << std::endl;
	return found ? 0 : 1;
}
