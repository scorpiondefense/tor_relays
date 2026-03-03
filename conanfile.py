import os

from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout
from conan.tools.files import copy


class TorRelaysConan(ConanFile):
    name = "tor-relays"
    version = "1.0.0"
    description = "Tor relay node implementation"
    license = "Proprietary"
    url = "https://github.com/scorpiondefense/tor_relays"
    settings = "os", "compiler", "build_type", "arch"

    def export_sources(self):
        copy(self, "CMakeLists.txt", src=self.recipe_folder, dst=self.export_sources_folder)
        copy(self, "cmake/*", src=self.recipe_folder, dst=self.export_sources_folder)
        copy(self, "src/*", src=self.recipe_folder, dst=self.export_sources_folder)
        copy(self, "include/*", src=self.recipe_folder, dst=self.export_sources_folder)
        copy(self, "tests/*", src=self.recipe_folder, dst=self.export_sources_folder)
        # Include obfs4_cpp dependency sources alongside tor_relays
        obfs4_src = os.path.join(self.recipe_folder, "..", "obfs4_cpp")
        if os.path.exists(obfs4_src):
            copy(self, "*", src=obfs4_src, dst=os.path.join(self.export_sources_folder, "obfs4_cpp"))

    # Migrated from conanfile.txt
    def requirements(self):
        self.requires("openssl/3.2.1")
        self.requires("boost/1.84.0")
        self.requires("catch2/3.5.2", test=True)
        self.requires("spdlog/1.13.0")
        self.requires("toml11/3.8.1")

    def configure(self):
        self.options["openssl/*"].shared = False
        self.options["boost/*"].shared = False
        # Only need headers (Asio) — disable all compiled libraries
        self.options["boost/*"].header_only = True

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.variables["BUILD_TESTING"] = False
        tc.generate()
        deps = CMakeDeps(self)
        deps.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["tor_lib"]
        self.cpp_info.set_property("cmake_file_name", "tor_relay")
        self.cpp_info.set_property("cmake_target_name", "tor::tor_lib")
        self.cpp_info.requires = [
            "openssl::openssl",
            "boost::headers",
            "spdlog::spdlog",
            "toml11::toml11",
        ]
