#include "tor/directory/authority.hpp"
#include <sstream>

namespace tor::directory {

// Get default directory authorities (based on Tor's hardcoded authorities)
std::vector<DirectoryAuthority> get_default_authorities() {
    std::vector<DirectoryAuthority> authorities;

    // Note: These are placeholder authority entries. Real Tor uses hardcoded
    // authorities from the C source. For a production relay, these should be
    // updated with actual authority information.

    DirectoryAuthority moria1;
    moria1.nickname = "moria1";
    moria1.address = "128.31.0.34";
    moria1.dir_port = 9131;
    moria1.or_port = 9101;
    moria1.is_v3_authority = true;
    moria1.is_bridge_authority = false;
    authorities.push_back(moria1);

    DirectoryAuthority tor26;
    tor26.nickname = "tor26";
    tor26.address = "86.59.21.38";
    tor26.dir_port = 80;
    tor26.or_port = 443;
    tor26.is_v3_authority = true;
    tor26.is_bridge_authority = false;
    authorities.push_back(tor26);

    DirectoryAuthority dizum;
    dizum.nickname = "dizum";
    dizum.address = "45.66.33.45";
    dizum.dir_port = 80;
    dizum.or_port = 443;
    dizum.is_v3_authority = true;
    dizum.is_bridge_authority = false;
    authorities.push_back(dizum);

    DirectoryAuthority gabelmoo;
    gabelmoo.nickname = "gabelmoo";
    gabelmoo.address = "131.188.40.189";
    gabelmoo.dir_port = 80;
    gabelmoo.or_port = 443;
    gabelmoo.is_v3_authority = true;
    gabelmoo.is_bridge_authority = false;
    authorities.push_back(gabelmoo);

    DirectoryAuthority dannenberg;
    dannenberg.nickname = "dannenberg";
    dannenberg.address = "193.23.244.244";
    dannenberg.dir_port = 80;
    dannenberg.or_port = 443;
    dannenberg.is_v3_authority = true;
    dannenberg.is_bridge_authority = false;
    authorities.push_back(dannenberg);

    DirectoryAuthority maatuska;
    maatuska.nickname = "maatuska";
    maatuska.address = "171.25.193.9";
    maatuska.dir_port = 443;
    maatuska.or_port = 80;
    maatuska.is_v3_authority = true;
    maatuska.is_bridge_authority = false;
    authorities.push_back(maatuska);

    DirectoryAuthority longclaw;
    longclaw.nickname = "longclaw";
    longclaw.address = "199.58.81.140";
    longclaw.dir_port = 80;
    longclaw.or_port = 443;
    longclaw.is_v3_authority = true;
    longclaw.is_bridge_authority = false;
    authorities.push_back(longclaw);

    DirectoryAuthority bastet;
    bastet.nickname = "bastet";
    bastet.address = "204.13.164.118";
    bastet.dir_port = 80;
    bastet.or_port = 443;
    bastet.is_v3_authority = true;
    bastet.is_bridge_authority = false;
    authorities.push_back(bastet);

    return authorities;
}

// Get bridge authorities
std::vector<DirectoryAuthority> get_bridge_authorities() {
    std::vector<DirectoryAuthority> authorities;

    // Bridge authority (Serge)
    DirectoryAuthority serge;
    serge.nickname = "Serge";
    serge.address = "66.111.2.131";
    serge.dir_port = 9030;
    serge.or_port = 9001;
    serge.is_v3_authority = true;
    serge.is_bridge_authority = true;
    authorities.push_back(serge);

    return authorities;
}

// DirectoryAuthority helpers
std::string DirectoryAuthority::dir_url() const {
    std::ostringstream oss;
    oss << "http://" << address << ":" << dir_port;
    return oss.str();
}

// DirResponse helpers
std::string DirResponse::body_string() const {
    return std::string(body.begin(), body.end());
}

// Utility function implementations
std::string authority_error_message(AuthorityError err) {
    switch (err) {
        case AuthorityError::ConnectionFailed: return "Connection failed";
        case AuthorityError::RequestFailed: return "Request failed";
        case AuthorityError::ResponseParseError: return "Response parse error";
        case AuthorityError::NotFound: return "Not found";
        case AuthorityError::Timeout: return "Request timeout";
        case AuthorityError::RateLimited: return "Rate limited";
        case AuthorityError::ServerError: return "Server error";
        default: return "Unknown authority error";
    }
}

}  // namespace tor::directory
