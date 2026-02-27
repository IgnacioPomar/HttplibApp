
#ifdef _DEBUG
#	define END_LIB_STD "d.lib"
#else
#	define END_LIB_STD ".lib"
#endif

#pragma comment(lib, "HttplibApp" END_LIB_STD)
#pragma comment(lib, "gtest" END_LIB_STD)
#pragma comment(lib, "gtest_main" END_LIB_STD)
