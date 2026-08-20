// Windows Filtering Platform (WFP) user-mode enforcement engine.
//
// Architecture:
//   - Uses FWPM_SESSION_FLAG_DYNAMIC → all filters auto-removed on process exit.
//   - Layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4 (outbound connection authorisation).
//     This fires when any process on the machine initiates a TCP/UDP connection.
//     Already-established connections are NOT terminated; they continue until
//     closed naturally. New connection attempts to blocked IPs/ports are refused.
//   - A single sublayer is created at session open time.
//   - Thread safety: all WFP API calls are serialised through filter_mutex_.
//
// Byte-order note:
//   src_ip_num / dest_ip_num in PacketParser come from memcpy() of wire bytes on
//   x86 (little-endian), which produces the same uint32_t value as inet_addr().
//   WFP's FWPM_CONDITION_IP_REMOTE_ADDRESS with FWP_UINT32 expects the IP in
//   the same representation (network byte order stored as uint32).  No swap needed.

#include "wfp_enforcement.h"
#include <sstream>
#include <iostream>
#include <algorithm>

#ifdef _WIN32
// Pull in the full Windows headers ONLY in this .cpp
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <initguid.h>
#include <windows.h>
#include <winsock2.h>
#include <fwpmu.h>

// Standard WFP layer & condition GUID definitions for MinGW compiler compatibility
// {c3b700a6-19cd-4fc0-8873-763d6205b403}
DEFINE_GUID(K_FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    0xc3b700a6, 0x19cd, 0x4fc0, 0x88, 0x73, 0x76, 0x3d, 0x62, 0x05, 0xb4, 0x03);

// {c35a36e6-0974-48f5-9143-496d1d25cba1}
DEFINE_GUID(K_FWPM_CONDITION_IP_REMOTE_ADDRESS,
    0xc35a36e6, 0x0974, 0x48f5, 0x91, 0x43, 0x49, 0x6d, 0x1d, 0x25, 0xcb, 0xa1);

// {12c40c34-9330-4296-8f12-ed867e3fc1d0}
DEFINE_GUID(K_FWPM_CONDITION_IP_REMOTE_PORT,
    0x12c40c34, 0x9330, 0x4296, 0x8f, 0x12, 0xed, 0x86, 0x7e, 0x3f, 0xc1, 0xd0);

#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif

#ifndef FWPM_PROVIDER_FLAG_PERSISTENT
#define FWPM_PROVIDER_FLAG_PERSISTENT 0x00000001
#endif

#endif



namespace DPI {

// ── GUID constants (fixed, stable across runs) ───────────────────────────────
#ifdef _WIN32
// {44504b54-0001-0000-8000-000000000001}  "DeepPacket-Provider"
static const ::GUID kProviderGuid = {
    0x44504b54, 0x0001, 0x0000,
    {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
};
// {44504b54-0001-0000-8000-000000000002}  "DeepPacket-Sublayer"
static const ::GUID kSublayerGuid = {
    0x44504b54, 0x0001, 0x0000,
    {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
};
#endif

// ── Helpers ──────────────────────────────────────────────────────────────────
#ifdef _WIN32
std::string WfpEnforcement::ipToString(uint32_t ip) {
    // ip is in the same byte order as inet_addr / network bytes stored on x86.
    // Extract each octet: byte0 is LSB on little-endian → first octet.
    std::ostringstream ss;
    ss << (ip & 0xFF)       << '.'
       << ((ip >> 8)  & 0xFF) << '.'
       << ((ip >> 16) & 0xFF) << '.'
       << ((ip >> 24) & 0xFF);
    return ss.str();
}
#endif

// ── Lifecycle ────────────────────────────────────────────────────────────────
WfpEnforcement::WfpEnforcement() = default;

WfpEnforcement::~WfpEnforcement() {
    shutdown();
}

bool WfpEnforcement::initialize() {
#ifndef _WIN32
    status_ = WfpStatus::UNAVAILABLE;
    status_detail_ = "Non-Windows platform; WFP not available.";
    std::cout << "[WFP] Platform not supported. Running in monitor-only mode.\n";
    return false;
#else
    std::lock_guard<std::mutex> lock(filter_mutex_);
    if (engine_handle_) return true; // already open

    // ── Open WFP engine with dynamic session ────────────────────────────────
    // FWPM_SESSION_FLAG_DYNAMIC: all our filters are auto-removed when this
    // handle is closed (including on process crash). Fail-safe by design.
    FWPM_SESSION0 session = {};
    session.flags         = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name        = const_cast<wchar_t*>(L"DeepPacketAnalyzer");
    session.displayData.description = const_cast<wchar_t*>(L"DeepPacket DPI engine enforcement session");

    DWORD result = FwpmEngineOpen0(
        nullptr,            // local machine
        RPC_C_AUTHN_WINNT,  // Windows authentication
        nullptr,            // default credentials
        &session,
        &engine_handle_
    );

    if (result == ERROR_ACCESS_DENIED) {
        status_       = WfpStatus::NO_ADMIN;
        status_detail_ = "Access denied. Run PacketInspector as Administrator to enable WFP enforcement.";
        engine_handle_ = nullptr;
        std::cerr << "[WFP] ERROR: " << status_detail_ << "\n";
        return false;
    }
    if (result != ERROR_SUCCESS) {
        status_        = WfpStatus::ERROR_OTHER;
        status_detail_ = "FwpmEngineOpen0 failed with code " + std::to_string(result);
        engine_handle_ = nullptr;
        std::cerr << "[WFP] ERROR: " << status_detail_ << "\n";
        return false;
    }

    // ── Begin transaction to install provider + sublayer ────────────────────
    result = FwpmTransactionBegin0(engine_handle_, 0);
    if (result == ERROR_ACCESS_DENIED || result == 5) {
        FwpmEngineClose0(engine_handle_);
        engine_handle_ = nullptr;
        status_        = WfpStatus::NO_ADMIN;
        status_detail_ = "Access denied during transaction. Run as Administrator to enable WFP kernel filters.";
        std::cerr << "[WFP] ERROR: " << status_detail_ << "\n";
        return false;
    }
    if (result != ERROR_SUCCESS) {
        FwpmEngineClose0(engine_handle_);
        engine_handle_ = nullptr;
        status_        = WfpStatus::ERROR_OTHER;
        status_detail_ = "FwpmTransactionBegin0 failed: " + std::to_string(result);
        return false;
    }


    // Provider (identifies our software in WFP management tools)
    FWPM_PROVIDER0 provider = {};
    provider.providerKey             = kProviderGuid;
    provider.displayData.name        = const_cast<wchar_t*>(L"DeepPacket Analyzer");
    provider.displayData.description = const_cast<wchar_t*>(L"Real-time DPI and enforcement engine");
    provider.flags                   = FWPM_PROVIDER_FLAG_PERSISTENT; // survive reboots (optional)

    // Ignore ERROR_ALREADY_EXISTS — the dynamic session may have cleaned it up
    // from a previous run, but the static provider key may still exist.
    result = FwpmProviderAdd0(engine_handle_, &provider, nullptr);
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        FwpmTransactionAbort0(engine_handle_);
        FwpmEngineClose0(engine_handle_);
        engine_handle_ = nullptr;
        status_        = WfpStatus::ERROR_OTHER;
        status_detail_ = "FwpmProviderAdd0 failed: " + std::to_string(result);
        return false;
    }

    // Sublayer — our enforcement channel; weight 0x1000 (above default, below firewall)
    FWPM_SUBLAYER0 sublayer = {};
    sublayer.subLayerKey             = kSublayerGuid;
    sublayer.displayData.name        = const_cast<wchar_t*>(L"DeepPacket Enforcement Sublayer");
    sublayer.displayData.description = const_cast<wchar_t*>(L"Outbound connection blocking filters");
    sublayer.providerKey             = const_cast<GUID*>(&kProviderGuid);
    sublayer.weight                  = 0x1000;

    result = FwpmSubLayerAdd0(engine_handle_, &sublayer, nullptr);
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        FwpmTransactionAbort0(engine_handle_);
        FwpmEngineClose0(engine_handle_);
        engine_handle_ = nullptr;
        status_        = WfpStatus::ERROR_OTHER;
        status_detail_ = "FwpmSubLayerAdd0 failed: " + std::to_string(result);
        return false;
    }

    result = FwpmTransactionCommit0(engine_handle_);
    if (result != ERROR_SUCCESS) {
        FwpmTransactionAbort0(engine_handle_);
        FwpmEngineClose0(engine_handle_);
        engine_handle_ = nullptr;
        status_        = WfpStatus::ERROR_OTHER;
        status_detail_ = "FwpmTransactionCommit0 failed: " + std::to_string(result);
        return false;
    }

    // Store the GUID copy in our member (for filter add calls)
    sublayer_key_ = kSublayerGuid;
    provider_key_ = kProviderGuid;

    status_        = WfpStatus::ACTIVE;
    status_detail_ = "Active";
    std::cout << "[WFP] Enforcement engine active. Layer: ALE_AUTH_CONNECT_V4 (outbound).\n";
    std::cout << "[WFP] Note: DYNAMIC session — all filters auto-removed on process exit.\n";
    return true;
#endif
}

void WfpEnforcement::shutdown() {
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(filter_mutex_);
    if (engine_handle_) {
        // With FWPM_SESSION_FLAG_DYNAMIC, closing the handle removes all our filters.
        FwpmEngineClose0(engine_handle_);
        engine_handle_ = nullptr;
        ip_filters_.clear();
        explicit_blocked_ips_.clear();
        port_filter_ids_.clear();
        blocked_domain_rules_.clear();
        domain_ips_.clear();
        status_        = WfpStatus::NOT_INITIALIZED;
        status_detail_ = "";
        std::cout << "[WFP] Enforcement engine shut down. All WFP filters removed.\n";
    }
#endif
}


bool WfpEnforcement::isActive() const {
    return status_ == WfpStatus::ACTIVE;
}

std::string WfpEnforcement::getStatusString() const {
    switch (status_) {
        case WfpStatus::NOT_INITIALIZED: return "NOT INITIALIZED";
        case WfpStatus::ACTIVE:          return "ACTIVE";
        case WfpStatus::NO_ADMIN:        return "NO ADMIN (run as Administrator)";
        case WfpStatus::UNAVAILABLE:     return "UNAVAILABLE (non-Windows)";
        case WfpStatus::ERROR_OTHER:     return "ERROR: " + status_detail_;
    }
    return "UNKNOWN";
}

// ── Private: install a WFP filter for one remote IP ─────────────────────────
#ifdef _WIN32
bool WfpEnforcement::installIPFilter_locked(uint32_t ip, UINT64& filter_id_out) {
    if (!engine_handle_) return false;

    FWPM_FILTER_CONDITION0 cond = {};
    cond.fieldKey                    = K_FWPM_CONDITION_IP_REMOTE_ADDRESS;
    cond.matchType                   = FWP_MATCH_EQUAL;
    cond.conditionValue.type         = FWP_UINT32;
    cond.conditionValue.uint32       = ip;  // same byte order as inet_addr on x86

    FWPM_FILTER0 filter = {};
    filter.layerKey          = K_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey       = sublayer_key_;
    filter.weight.type       = FWP_EMPTY; // auto-weight within sublayer
    filter.numFilterConditions = 1;
    filter.filterCondition   = &cond;
    filter.action.type       = FWP_ACTION_BLOCK;
    filter.displayData.name  = const_cast<wchar_t*>(L"DeepPacket-IP-Block");

    DWORD r = FwpmFilterAdd0(engine_handle_, &filter, nullptr, &filter_id_out);
    if (r != ERROR_SUCCESS) {
        std::cerr << "[WFP] FwpmFilterAdd0 (IP) failed: " << r
                  << " for " << ipToString(ip) << "\n";
        return false;
    }
    return true;
}

bool WfpEnforcement::installPortFilter_locked(uint16_t port, UINT64& filter_id_out) {
    if (!engine_handle_) return false;

    FWPM_FILTER_CONDITION0 cond = {};
    cond.fieldKey               = K_FWPM_CONDITION_IP_REMOTE_PORT;
    cond.matchType              = FWP_MATCH_EQUAL;
    cond.conditionValue.type    = FWP_UINT16;
    cond.conditionValue.uint16  = port;  // host byte order for port

    FWPM_FILTER0 filter = {};
    filter.layerKey             = K_FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey          = sublayer_key_;
    filter.weight.type          = FWP_EMPTY;
    filter.numFilterConditions  = 1;
    filter.filterCondition      = &cond;
    filter.action.type          = FWP_ACTION_BLOCK;
    filter.displayData.name     = const_cast<wchar_t*>(L"DeepPacket-Port-Block");


    DWORD r = FwpmFilterAdd0(engine_handle_, &filter, nullptr, &filter_id_out);
    if (r != ERROR_SUCCESS) {
        std::cerr << "[WFP] FwpmFilterAdd0 (Port) failed: " << r
                  << " for port " << port << "\n";
        return false;
    }
    return true;
}

bool WfpEnforcement::removeFilter_locked(UINT64 filter_id) {
    if (!engine_handle_) return false;
    DWORD r = FwpmFilterDeleteById0(engine_handle_, filter_id);
    if (r != ERROR_SUCCESS && r != FWP_E_FILTER_NOT_FOUND) {
        std::cerr << "[WFP] FwpmFilterDeleteById0 failed: " << r << "\n";
        return false;
    }
    return true;
}
#endif

// ── Reference Counting Helpers ───────────────────────────────────────────────
#ifdef _WIN32
bool WfpEnforcement::addIPFilterRef_locked(uint32_t ip) {
    if (!engine_handle_) return false;
    auto it = ip_filters_.find(ip);
    if (it != ip_filters_.end()) {
        it->second.ref_count++;
        return true;
    }
    UINT64 fid = 0;
    if (!installIPFilter_locked(ip, fid)) return false;
    ip_filters_[ip] = { fid, 1 };
    std::cout << "[WFP] Blocked IP: " << ipToString(ip) << " (filter id=" << fid << ")\n";
    return true;
}

bool WfpEnforcement::releaseIPFilterRef_locked(uint32_t ip) {
    if (!engine_handle_) return false;
    auto it = ip_filters_.find(ip);
    if (it == ip_filters_.end()) return true;

    it->second.ref_count--;
    if (it->second.ref_count <= 0) {
        removeFilter_locked(it->second.filter_id);
        ip_filters_.erase(it);
        std::cout << "[WFP] Unblocked IP: " << ipToString(ip) << " (all references released)\n";
    } else {
        std::cout << "[WFP] Reduced reference for IP: " << ipToString(ip) << " (remaining=" << it->second.ref_count << ")\n";
    }
    return true;
}
#endif

// ── Domain Wildcard Matching ──────────────────────────────────────────────────
bool WfpEnforcement::domainMatches(const std::string& domain, const std::string& pattern) {
    if (domain.empty() || pattern.empty()) return false;
    
    std::string d = domain;
    std::string p = pattern;
    std::transform(d.begin(), d.end(), d.begin(), [](unsigned char c){ return std::tolower(c); });
    std::transform(p.begin(), p.end(), p.begin(), [](unsigned char c){ return std::tolower(c); });

    // Exact match
    if (d == p) return true;

    // Pattern: *.example.com
    if (p.size() >= 2 && p[0] == '*' && p[1] == '.') {
        std::string suffix = p.substr(1); // .example.com
        if (d.size() >= suffix.size() &&
            d.compare(d.size() - suffix.size(), suffix.size(), suffix) == 0) {
            return true;
        }
        // Also match bare domain: example.com matches *.example.com
        if (d == p.substr(2)) {
            return true;
        }
    }

    // Pattern: example.com (matches subdomain www.example.com too if exact suffix)
    if (p.size() < d.size() && d[d.size() - p.size() - 1] == '.' &&
        d.compare(d.size() - p.size(), p.size(), p) == 0) {
        return true;
    }

    return false;
}

// ── IP blocking ───────────────────────────────────────────────────────────────
bool WfpEnforcement::blockIP(uint32_t ip) {
#ifndef _WIN32
    return false;
#else
    std::lock_guard<std::mutex> lock(filter_mutex_);
    if (!isActive()) return false;

    if (explicit_blocked_ips_.count(ip)) return true; // already explicitly blocked
    explicit_blocked_ips_.insert(ip);
    return addIPFilterRef_locked(ip);
#endif
}

bool WfpEnforcement::unblockIP(uint32_t ip) {
#ifndef _WIN32
    return false;
#else
    std::lock_guard<std::mutex> lock(filter_mutex_);
    if (!explicit_blocked_ips_.count(ip)) return true; // not explicitly blocked
    explicit_blocked_ips_.erase(ip);
    return releaseIPFilterRef_locked(ip);
#endif
}

bool WfpEnforcement::isIPBlocked(uint32_t ip) const {
#ifndef _WIN32
    return false;
#else
    std::lock_guard<std::mutex> lock(filter_mutex_);
    return ip_filters_.count(ip) > 0;
#endif
}

std::vector<uint32_t> WfpEnforcement::getBlockedIPs() const {
    std::vector<uint32_t> result;
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(filter_mutex_);
    for (const auto& kv : ip_filters_) result.push_back(kv.first);
#endif
    return result;
}

// ── Port blocking ─────────────────────────────────────────────────────────────
bool WfpEnforcement::blockPort(uint16_t port) {
#ifndef _WIN32
    return false;
#else
    std::lock_guard<std::mutex> lock(filter_mutex_);
    if (!isActive()) return false;
    if (port_filter_ids_.count(port)) return true;

    UINT64 fid = 0;
    if (!installPortFilter_locked(port, fid)) return false;
    port_filter_ids_[port] = fid;
    std::cout << "[WFP] Blocked port: " << port << " (filter id=" << fid << ")\n";
    return true;
#endif
}

bool WfpEnforcement::unblockPort(uint16_t port) {
#ifndef _WIN32
    return false;
#else
    std::lock_guard<std::mutex> lock(filter_mutex_);
    auto it = port_filter_ids_.find(port);
    if (it == port_filter_ids_.end()) return true;
    removeFilter_locked(it->second);
    port_filter_ids_.erase(it);
    std::cout << "[WFP] Unblocked port: " << port << "\n";
    return true;
#endif
}

bool WfpEnforcement::isPortBlocked(uint16_t port) const {
#ifndef _WIN32
    return false;
#else
    std::lock_guard<std::mutex> lock(filter_mutex_);
    return port_filter_ids_.count(port) > 0;
#endif
}

// ── Domain blocking ───────────────────────────────────────────────────────────
bool WfpEnforcement::blockDomain(const std::string& domain,
                                  const std::vector<uint32_t>& known_ips) {
#ifndef _WIN32
    return false;
#else
    if (!isActive()) return false;

    std::lock_guard<std::mutex> lock(filter_mutex_);

    // Always emit the established-connection advisory notice.
    std::cout << "\n[WFP] *** Blocking domain: " << domain << " ***\n";
    std::cout << "[WFP] NOTE: Already-established connections to this domain will\n";
    std::cout << "[WFP]       continue until closed. New connections are blocked NOW.\n";
    std::cout << "[WFP]       To fully cut off: close existing browser tabs for " << domain << ".\n\n";

    blocked_domain_rules_.insert(domain);
    auto& ip_set = domain_ips_[domain];

    size_t installed = 0;
    for (uint32_t ip : known_ips) {
        if (ip == 0) continue;
        if (ip_set.count(ip)) continue; // already tracked for this domain

        ip_set.insert(ip);
        if (addIPFilterRef_locked(ip)) {
            installed++;
        }
    }

    std::cout << "[WFP] Domain '" << domain << "': " << installed
              << " WFP filters active across " << ip_set.size() << " known IP(s).\n";
    return true;
#endif
}

bool WfpEnforcement::unblockDomain(const std::string& domain) {
#ifndef _WIN32
    return false;
#else
    std::lock_guard<std::mutex> lock(filter_mutex_);

    blocked_domain_rules_.erase(domain);
    auto dit = domain_ips_.find(domain);
    if (dit == domain_ips_.end()) return true;

    for (uint32_t ip : dit->second) {
        releaseIPFilterRef_locked(ip);
    }
    domain_ips_.erase(dit);

    std::cout << "[WFP] Unblocked domain rule: " << domain << "\n";
    return true;
#endif
}

bool WfpEnforcement::isDomainBlocked(const std::string& domain) const {
#ifndef _WIN32
    return false;
#else
    std::lock_guard<std::mutex> lock(filter_mutex_);
    for (const auto& pattern : blocked_domain_rules_) {
        if (domainMatches(domain, pattern)) return true;
    }
    return false;
#endif
}

// Called by ConnectionTracker whenever a DNS response maps domain → ip.
// If that domain matches any blocked domain rule, install/ref an IP filter immediately.
void WfpEnforcement::onNewDnsMapping(const std::string& domain, uint32_t ip) {
#ifndef _WIN32
    (void)domain; (void)ip;
#else
    if (ip == 0 || domain.empty()) return;
    std::lock_guard<std::mutex> lock(filter_mutex_);
    if (!isActive()) return;

    for (const auto& rule : blocked_domain_rules_) {
        if (domainMatches(domain, rule)) {
            auto& ip_set = domain_ips_[rule];
            if (ip_set.count(ip) == 0) {
                ip_set.insert(ip);
                addIPFilterRef_locked(ip);
                std::cout << "[WFP] Domain match: " << domain << " matched rule " << rule
                          << " -> WFP filter added for " << ipToString(ip) << "\n";
            }
        }
    }
#endif
}

// ── Clear all ─────────────────────────────────────────────────────────────────
bool WfpEnforcement::clearAll() {
#ifndef _WIN32
    return false;
#else
    std::lock_guard<std::mutex> lock(filter_mutex_);
    if (!engine_handle_) return true;

    // Remove all IP filters
    for (auto& kv : ip_filters_) {
        removeFilter_locked(kv.second.filter_id);
    }
    ip_filters_.clear();
    explicit_blocked_ips_.clear();

    // Remove all port filters
    for (auto& kv : port_filter_ids_) {
        removeFilter_locked(kv.second);
    }
    port_filter_ids_.clear();

    domain_ips_.clear();
    blocked_domain_rules_.clear();

    std::cout << "[WFP] All WFP filters cleared.\n";
    return true;
#endif
}

// ── Dashboard state ────────────────────────────────────────────────────────────
WfpEnforcement::State WfpEnforcement::getState() const {
    State s;
    s.status        = status_;
    s.status_string = getStatusString();
#ifdef _WIN32
    std::lock_guard<std::mutex> lock(filter_mutex_);
    s.active_ip_filters    = ip_filters_.size();
    s.active_port_filters  = port_filter_ids_.size();
    s.active_domain_rules  = blocked_domain_rules_.size();
    s.total_active_filters = ip_filters_.size() + port_filter_ids_.size();
#else
    s.active_ip_filters   = 0;
    s.active_port_filters = 0;
    s.active_domain_rules = 0;
    s.total_active_filters= 0;
#endif
    return s;
}

std::string WfpEnforcement::getStateJson() const {
    State s = getState();
    std::ostringstream js;
    js << "\"wfp\": {"
       << "\"active\": " << (s.status == WfpStatus::ACTIVE ? "true" : "false") << ", "
       << "\"status\": \"" << s.status_string << "\", "
       << "\"ip_filters\": " << s.active_ip_filters << ", "
       << "\"port_filters\": " << s.active_port_filters << ", "
       << "\"domain_rules\": " << s.active_domain_rules << ", "
       << "\"total_filters\": " << s.total_active_filters
       << "}";
    return js.str();
}

} // namespace DPI

