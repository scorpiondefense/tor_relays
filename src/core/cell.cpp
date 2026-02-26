#include "tor/core/cell.hpp"

namespace tor::core {

const char* cell_command_name(CellCommand cmd) {
    switch (cmd) {
        case CellCommand::PADDING:           return "PADDING";
        case CellCommand::CREATE:            return "CREATE";
        case CellCommand::CREATED:           return "CREATED";
        case CellCommand::RELAY:             return "RELAY";
        case CellCommand::DESTROY:           return "DESTROY";
        case CellCommand::CREATE_FAST:       return "CREATE_FAST";
        case CellCommand::CREATED_FAST:      return "CREATED_FAST";
        case CellCommand::VERSIONS:          return "VERSIONS";
        case CellCommand::NETINFO:           return "NETINFO";
        case CellCommand::RELAY_EARLY:       return "RELAY_EARLY";
        case CellCommand::CREATE2:           return "CREATE2";
        case CellCommand::CREATED2:          return "CREATED2";
        case CellCommand::PADDING_NEGOTIATE: return "PADDING_NEGOTIATE";
        case CellCommand::VPADDING:          return "VPADDING";
        case CellCommand::CERTS:             return "CERTS";
        case CellCommand::AUTH_CHALLENGE:    return "AUTH_CHALLENGE";
        case CellCommand::AUTHENTICATE:      return "AUTHENTICATE";
        case CellCommand::AUTHORIZE:         return "AUTHORIZE";
        default:                             return "UNKNOWN";
    }
}

const char* relay_command_name(RelayCommand cmd) {
    switch (cmd) {
        case RelayCommand::BEGIN:             return "RELAY_BEGIN";
        case RelayCommand::DATA:              return "RELAY_DATA";
        case RelayCommand::END:               return "RELAY_END";
        case RelayCommand::CONNECTED:         return "RELAY_CONNECTED";
        case RelayCommand::SENDME:            return "RELAY_SENDME";
        case RelayCommand::EXTEND:            return "RELAY_EXTEND";
        case RelayCommand::EXTENDED:          return "RELAY_EXTENDED";
        case RelayCommand::TRUNCATE:          return "RELAY_TRUNCATE";
        case RelayCommand::TRUNCATED:         return "RELAY_TRUNCATED";
        case RelayCommand::DROP:              return "RELAY_DROP";
        case RelayCommand::RESOLVE:           return "RELAY_RESOLVE";
        case RelayCommand::RESOLVED:          return "RELAY_RESOLVED";
        case RelayCommand::BEGIN_DIR:         return "RELAY_BEGIN_DIR";
        case RelayCommand::EXTEND2:           return "RELAY_EXTEND2";
        case RelayCommand::EXTENDED2:         return "RELAY_EXTENDED2";
        case RelayCommand::ESTABLISH_INTRO:   return "RELAY_ESTABLISH_INTRO";
        case RelayCommand::ESTABLISH_RENDEZVOUS: return "RELAY_ESTABLISH_RENDEZVOUS";
        case RelayCommand::INTRODUCE1:        return "RELAY_INTRODUCE1";
        case RelayCommand::INTRODUCE2:        return "RELAY_INTRODUCE2";
        case RelayCommand::RENDEZVOUS1:       return "RELAY_RENDEZVOUS1";
        case RelayCommand::RENDEZVOUS2:       return "RELAY_RENDEZVOUS2";
        case RelayCommand::INTRO_ESTABLISHED: return "RELAY_INTRO_ESTABLISHED";
        case RelayCommand::RENDEZVOUS_ESTABLISHED: return "RELAY_RENDEZVOUS_ESTABLISHED";
        case RelayCommand::INTRODUCE_ACK:     return "RELAY_INTRODUCE_ACK";
        default:                              return "RELAY_UNKNOWN";
    }
}

const char* end_reason_name(EndReason reason) {
    switch (reason) {
        case EndReason::MISC:            return "MISC";
        case EndReason::RESOLVEFAILED:   return "RESOLVEFAILED";
        case EndReason::CONNECTREFUSED:  return "CONNECTREFUSED";
        case EndReason::EXITPOLICY:      return "EXITPOLICY";
        case EndReason::DESTROY:         return "DESTROY";
        case EndReason::DONE:            return "DONE";
        case EndReason::TIMEOUT:         return "TIMEOUT";
        case EndReason::NOROUTE:         return "NOROUTE";
        case EndReason::HIBERNATING:     return "HIBERNATING";
        case EndReason::INTERNAL:        return "INTERNAL";
        case EndReason::RESOURCELIMIT:   return "RESOURCELIMIT";
        case EndReason::CONNRESET:       return "CONNRESET";
        case EndReason::TORPROTOCOL:     return "TORPROTOCOL";
        case EndReason::NOTDIRECTORY:    return "NOTDIRECTORY";
        default:                         return "UNKNOWN";
    }
}

const char* destroy_reason_name(DestroyReason reason) {
    switch (reason) {
        case DestroyReason::NONE:            return "NONE";
        case DestroyReason::PROTOCOL:        return "PROTOCOL";
        case DestroyReason::INTERNAL:        return "INTERNAL";
        case DestroyReason::REQUESTED:       return "REQUESTED";
        case DestroyReason::HIBERNATING:     return "HIBERNATING";
        case DestroyReason::RESOURCELIMIT:   return "RESOURCELIMIT";
        case DestroyReason::CONNECTFAILED:   return "CONNECTFAILED";
        case DestroyReason::OR_IDENTITY:     return "OR_IDENTITY";
        case DestroyReason::CHANNEL_CLOSED:  return "CHANNEL_CLOSED";
        case DestroyReason::FINISHED:        return "FINISHED";
        case DestroyReason::TIMEOUT:         return "TIMEOUT";
        case DestroyReason::DESTROYED:       return "DESTROYED";
        case DestroyReason::NOSUCHSERVICE:   return "NOSUCHSERVICE";
        default:                             return "UNKNOWN";
    }
}

}  // namespace tor::core
