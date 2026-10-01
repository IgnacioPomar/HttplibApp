import os
import re

from conan import ConanFile
from conan.errors import ConanException
from conan.tools.build import check_min_cppstd
from conan.tools.cmake import CMake, CMakeDeps, CMakeToolchain, cmake_layout
from conan.tools.files import load


class HttplibAppConan(ConanFile):
    name = "httplibapp"
    license = "Unlicense"
    description = "Extension for cpp-httplib focused on web services: routing and middlewares"

    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "build_tests": [True, False],
        # TLS backend of cpp-httplib (HTTPS). With "none" the server is plain HTTP
        "tls": ["none", "wolfssl", "openssl"],
    }
    default_options = {
        "shared": True,
        "fPIC": True,
        "build_tests": False,
        "tls": "none",
    }

    exports = "VERSION"
    exports_sources = "VERSION", "CMakeLists.txt", "cmake/*", "include/*", "src/*", "test/*"

    def set_version(self):
        # Single source of truth: the VERSION file (also read by CMakeLists.txt and the CI)
        version = load(self, os.path.join(self.recipe_folder, "VERSION")).strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise ConanException(f"VERSION must be MAJOR.MINOR.PATCH, not '{version}'")
        if self.version and self.version != version:
            raise ConanException(f"--version={self.version} does not match the VERSION file ({version})")
        self.version = version

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")
        self.options["cpp-httplib"].with_wolfssl = self.options.tls == "wolfssl"
        self.options["cpp-httplib"].with_openssl = self.options.tls == "openssl"
        if self.options.tls == "wolfssl":
            # Required by the cpp-httplib recipe
            self.options["wolfssl"].opensslextra = True
            self.options["wolfssl"].opensslall = True

    def package_id(self):
        # Building the tests does not change the packaged library
        del self.info.options.build_tests

    def validate(self):
        check_min_cppstd(self, 20)

    def requirements(self):
        # cpp-httplib is header-only: its code (and its TLS calls) is compiled in the consumer,
        # which must get the headers and also link the TLS library, even if HttplibApp is a shared library
        self.requires("cpp-httplib/0.56.0", transitive_headers=True, transitive_libs=True)
        # Crypto for JWT (not exposed in the public headers)
        self.requires("botan/3.13.0")

    def build_requirements(self):
        if self.options.build_tests:
            self.test_requires("catch2/3.16.0")

    def layout(self):
        cmake_layout(self)
        # Editable mode: consumers use the headers straight from the source tree
        self.cpp.source.includedirs = ["include"]
        self.cpp.build.includedirs = ["include"]    # Generated export and version headers
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
        self.cpp_info.requires = ["cpp-httplib::cpp-httplib", "botan::botan"]
