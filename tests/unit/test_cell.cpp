#include <catch2/catch_all.hpp>
#include "tor/core/cell.hpp"
#include "../fixtures/cell_fixtures.hpp"

using namespace tor::core;
using namespace tor::test::fixtures;

TEST_CASE("Cell parsing - Fixed cell", "[cell][parsing][unit]") {
    SECTION("Valid PADDING cell") {
        auto raw = raw_padding_cell();
        auto result = Cell::parse(raw);

        REQUIRE(result.has_value());
        CHECK(result->circuit_id == 0);
        CHECK(result->command == CellCommand::PADDING);
    }

    SECTION("Valid CREATE2 cell roundtrip") {
        auto original = create2_ntor_cell();
        auto serialized = original.serialize();
        auto parsed = Cell::parse(serialized);

        REQUIRE(parsed.has_value());
        CHECK(parsed->circuit_id == original.circuit_id);
        CHECK(parsed->command == original.command);
        CHECK(parsed->payload == original.payload);
    }

    SECTION("Reject truncated cell") {
        auto truncated = truncated_cell();
        auto result = Cell::parse(truncated);

        REQUIRE(!result.has_value());
        CHECK(result.error() == CellError::TruncatedCell);
    }

    SECTION("Variable-length command in fixed cell fails") {
        std::array<uint8_t, CELL_LEN> data{};
        data[4] = static_cast<uint8_t>(CellCommand::VERSIONS);

        auto result = Cell::parse(data);
        REQUIRE(!result.has_value());
        CHECK(result.error() == CellError::InvalidCommand);
    }
}

TEST_CASE("Cell parsing - Variable cell", "[cell][parsing][unit]") {
    SECTION("Valid VERSIONS cell") {
        auto original = versions_cell();
        auto serialized = original.serialize();
        auto parsed = VariableCell::parse(serialized);

        REQUIRE(parsed.has_value());
        CHECK(parsed->circuit_id == 0);
        CHECK(parsed->command == CellCommand::VERSIONS);
        CHECK(parsed->payload.size() == 4);  // Two 16-bit versions
    }

    SECTION("VERSIONS cell contains correct versions") {
        auto cell = versions_cell();

        // Parse version numbers from payload
        REQUIRE(cell.payload.size() == 4);
        uint16_t v1 = (static_cast<uint16_t>(cell.payload[0]) << 8) | cell.payload[1];
        uint16_t v2 = (static_cast<uint16_t>(cell.payload[2]) << 8) | cell.payload[3];

        CHECK(v1 == 4);
        CHECK(v2 == 5);
    }

    SECTION("Reject truncated variable cell header") {
        std::vector<uint8_t> truncated(5, 0);  // Less than VAR_CELL_HEADER_LEN
        auto result = VariableCell::parse(truncated);

        REQUIRE(!result.has_value());
        CHECK(result.error() == CellError::TruncatedCell);
    }

    SECTION("Reject truncated variable cell payload") {
        std::vector<uint8_t> data(VAR_CELL_HEADER_LEN, 0);
        // Set length to 100 but don't provide payload
        data[5] = 0x00;
        data[6] = 0x64;  // 100 bytes

        auto result = VariableCell::parse(data);
        REQUIRE(!result.has_value());
        CHECK(result.error() == CellError::TruncatedCell);
    }
}

TEST_CASE("Cell serialization - Fixed cell", "[cell][serialization][unit]") {
    SECTION("PADDING cell serialization") {
        auto cell = Cell::padding(0x12345678);
        auto serialized = cell.serialize();

        CHECK(serialized.size() == CELL_LEN);

        // Check circuit ID (big-endian)
        CHECK(serialized[0] == 0x12);
        CHECK(serialized[1] == 0x34);
        CHECK(serialized[2] == 0x56);
        CHECK(serialized[3] == 0x78);

        // Check command
        CHECK(serialized[4] == 0x00);  // PADDING
    }

    SECTION("DESTROY cell serialization") {
        auto cell = Cell::destroy(0xAABBCCDD, DestroyReason::PROTOCOL);
        auto serialized = cell.serialize();

        CHECK(serialized[0] == 0xAA);
        CHECK(serialized[1] == 0xBB);
        CHECK(serialized[2] == 0xCC);
        CHECK(serialized[3] == 0xDD);
        CHECK(serialized[4] == static_cast<uint8_t>(CellCommand::DESTROY));
        CHECK(serialized[5] == static_cast<uint8_t>(DestroyReason::PROTOCOL));
    }
}

TEST_CASE("RelayCell parsing and serialization", "[cell][relay][unit]") {
    SECTION("DATA relay cell roundtrip") {
        std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
        auto original = RelayCell::make_data(42, data);
        auto serialized = original.serialize();
        auto parsed = RelayCell::parse(serialized);

        REQUIRE(parsed.has_value());
        CHECK(parsed->command == RelayCommand::DATA);
        CHECK(parsed->stream_id == 42);
        CHECK(parsed->data == data);
    }

    SECTION("BEGIN relay cell") {
        auto cell = RelayCell::begin(100, "example.com", 443);

        CHECK(cell.command == RelayCommand::BEGIN);
        CHECK(cell.stream_id == 100);

        // Data should be "example.com:443\0"
        std::string expected = "example.com:443";
        expected.push_back('\0');
        CHECK(cell.data.size() == expected.size());
    }

    SECTION("END relay cell") {
        auto cell = RelayCell::end(50, EndReason::DONE);

        CHECK(cell.command == RelayCommand::END);
        CHECK(cell.stream_id == 50);
        CHECK(cell.data.size() == 1);
        CHECK(cell.data[0] == static_cast<uint8_t>(EndReason::DONE));
    }

    SECTION("SENDME relay cell") {
        auto cell = RelayCell::sendme(0);  // Circuit-level SENDME

        CHECK(cell.command == RelayCommand::SENDME);
        CHECK(cell.stream_id == 0);
    }
}

TEST_CASE("Create2Data parsing and serialization", "[cell][create2][unit]") {
    SECTION("ntor handshake type") {
        Create2Data create;
        create.handshake_type = HandshakeType::NTOR;
        create.handshake_data.resize(84);  // ntor client handshake size

        auto serialized = create.serialize();

        // Check handshake type
        CHECK(serialized[0] == 0x00);
        CHECK(serialized[1] == 0x02);  // NTOR

        // Check length
        CHECK(serialized[2] == 0x00);
        CHECK(serialized[3] == 0x54);  // 84

        // Parse back
        auto parsed = Create2Data::parse(serialized);
        REQUIRE(parsed.has_value());
        CHECK(parsed->handshake_type == HandshakeType::NTOR);
        CHECK(parsed->handshake_data.size() == 84);
    }
}

TEST_CASE("NetInfoData parsing and serialization", "[cell][netinfo][unit]") {
    SECTION("NetInfo roundtrip") {
        auto original = netinfo_data();
        auto serialized = original.serialize();
        auto parsed = NetInfoData::parse(serialized);

        REQUIRE(parsed.has_value());
        CHECK(parsed->timestamp == original.timestamp);
        CHECK(parsed->other_address == original.other_address);
        CHECK(parsed->my_addresses.size() == original.my_addresses.size());
    }

    SECTION("IPv4 address encoding") {
        NetInfoData data;
        data.timestamp = 0;
        data.other_address = {192, 168, 1, 1};

        auto serialized = data.serialize();

        // Check address type (should be IPv4 = 4)
        CHECK(serialized[4] == static_cast<uint8_t>(AddressType::IPV4));
        // Check address length
        CHECK(serialized[5] == 4);
        // Check address bytes
        CHECK(serialized[6] == 192);
        CHECK(serialized[7] == 168);
        CHECK(serialized[8] == 1);
        CHECK(serialized[9] == 1);
    }
}

TEST_CASE("Cell command utilities", "[cell][utility][unit]") {
    SECTION("is_variable_length") {
        CHECK(Cell::is_variable_length(CellCommand::VERSIONS));
        CHECK(Cell::is_variable_length(CellCommand::CERTS));
        CHECK(Cell::is_variable_length(CellCommand::AUTH_CHALLENGE));
        CHECK(Cell::is_variable_length(CellCommand::AUTHENTICATE));
        CHECK(Cell::is_variable_length(CellCommand::VPADDING));

        CHECK_FALSE(Cell::is_variable_length(CellCommand::PADDING));
        CHECK_FALSE(Cell::is_variable_length(CellCommand::CREATE));
        CHECK_FALSE(Cell::is_variable_length(CellCommand::RELAY));
        CHECK_FALSE(Cell::is_variable_length(CellCommand::DESTROY));
    }

    SECTION("cell_command_name") {
        CHECK(std::string(cell_command_name(CellCommand::PADDING)) == "PADDING");
        CHECK(std::string(cell_command_name(CellCommand::CREATE2)) == "CREATE2");
        CHECK(std::string(cell_command_name(CellCommand::RELAY)) == "RELAY");
        CHECK(std::string(cell_command_name(CellCommand::VERSIONS)) == "VERSIONS");
    }

    SECTION("relay_command_name") {
        CHECK(std::string(relay_command_name(RelayCommand::BEGIN)) == "BEGIN");
        CHECK(std::string(relay_command_name(RelayCommand::DATA)) == "DATA");
        CHECK(std::string(relay_command_name(RelayCommand::END)) == "END");
        CHECK(std::string(relay_command_name(RelayCommand::EXTEND2)) == "EXTEND2");
    }
}
