#include <catch2/catch_all.hpp>
#include "tor/crypto/tls.hpp"
#include "tor/crypto/keys.hpp"

using namespace tor::crypto;

TEST_CASE("TLS context creation", "[tls][integration]") {
    SECTION("Create client context") {
        TlsContext ctx;
        auto result = ctx.init_client();
        REQUIRE(result.has_value());
        CHECK(ctx.is_initialized());
    }

    SECTION("Generate self-signed certificate") {
        auto key_result = Ed25519SecretKey::generate();
        REQUIRE(key_result.has_value());

        auto cert_result = TlsContext::generate_self_signed_cert(*key_result);
        REQUIRE(cert_result.has_value());

        auto& [cert_pem, key_pem] = *cert_result;
        CHECK(!cert_pem.empty());
        CHECK(!key_pem.empty());

        // Certificate should be PEM format
        std::string cert_str(cert_pem.begin(), cert_pem.end());
        CHECK(cert_str.find("-----BEGIN CERTIFICATE-----") != std::string::npos);
    }

    SECTION("Create server context with generated cert") {
        auto key_result = Ed25519SecretKey::generate();
        REQUIRE(key_result.has_value());

        auto cert_result = TlsContext::generate_self_signed_cert(*key_result);
        REQUIRE(cert_result.has_value());

        TlsContext ctx;
        auto init_result = ctx.init_server(
            cert_result->first, cert_result->second);
        REQUIRE(init_result.has_value());
        CHECK(ctx.is_initialized());
    }
}

TEST_CASE("Memory BIO", "[tls][integration]") {
    SECTION("Write and read") {
        MemoryBio bio;

        std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
        auto write_result = bio.write(data);
        REQUIRE(write_result.has_value());
        CHECK(*write_result == data.size());

        CHECK(bio.pending() == data.size());

        std::vector<uint8_t> buffer(data.size());
        auto read_result = bio.read(buffer);
        REQUIRE(read_result.has_value());
        CHECK(*read_result == data.size());
        CHECK(buffer == data);
    }

    SECTION("Partial read") {
        MemoryBio bio;

        std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
        (void)bio.write(data);

        std::vector<uint8_t> buffer(2);
        auto read_result = bio.read(buffer);
        REQUIRE(read_result.has_value());
        CHECK(*read_result == 2);

        CHECK(bio.pending() == 3);
    }
}

TEST_CASE("TLS version settings", "[tls][integration]") {
    SECTION("Set minimum TLS 1.2") {
        TlsContext ctx;
        (void)ctx.init_client();
        ctx.set_min_version(TlsVersion::TLS_1_2);
        CHECK(ctx.is_initialized());
    }

    SECTION("Set minimum TLS 1.3") {
        TlsContext ctx;
        (void)ctx.init_client();
        ctx.set_min_version(TlsVersion::TLS_1_3);
        CHECK(ctx.is_initialized());
    }
}

// Note: Full TLS handshake tests require actual socket connections
// or more sophisticated mocking. These tests verify the API works.
