from conan import ConanFile
from conan.tools.build import check_min_cppstd
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout


class HttplibAppConan(ConanFile):
    name = "httplibapp"
    version = "0.1.0"
    license = "Unlicense"
    description = "Extension for cpp-httplib focused on web services: routing and middlewares"

    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "build_tests": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "build_tests": False,
        # TLS only with wolfSSL (no OpenSSL). The cpp-httplib recipe requires opensslall
        "cpp-httplib/*:with_wolfssl": True,
        "wolfssl/*:opensslextra": True,
        "wolfssl/*:opensslall": True,
    }

    exports_sources = "CMakeLists.txt", "include/*", "src/*", "test/*"

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def validate(self):
        check_min_cppstd(self, 20)

    def requirements(self):
        # cpp-httplib is header-only: its code (and its wolfSSL calls) is compiled in the consumer,
        # which must get the headers and also link wolfSSL, even if HttplibApp is a shared library
        self.requires("cpp-httplib/0.56.0", transitive_headers=True, transitive_libs=True)

    def build_requirements(self):
        if self.options.build_tests:
            self.test_requires("catch2/3.16.0")

    def layout(self):
        cmake_layout(self)
        # Editable mode: consumers use the headers straight from the source tree
        self.cpp.source.includedirs = ["include"]
        self.cpp.build.libdirs = ["."]

    def generate(self):
        CMakeDeps(self).generate()
        tc = CMakeToolchain(self)
        tc.cache_variables["HTTPLIBAPP_BUILD_TESTS"] = bool(self.options.build_tests)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        if self.options.build_tests:
            cmake.test()

    def package(self):
        CMake(self).install()

    def package_info(self):
        self.cpp_info.libs = ["HttplibApp"]
        self.cpp_info.set_property("cmake_file_name", "HttplibApp")
        self.cpp_info.set_property("cmake_target_name", "HttplibApp::HttplibApp")
        self.cpp_info.requires = ["cpp-httplib::cpp-httplib"]
        if self.options.shared:
            self.cpp_info.defines = ["HAPP_DLL"]
