#ifndef WFP_ENFORCEMENT_H
#define WFP_ENFORCEMENT_H

// Windows Filtering Platform (WFP) user-mode enforcement layer.
//
// Design contract:
//  - Uses a DYNAMIC WFP session: if this process dies, ALL installed filters
//    are automatically removed by Windows — networking is never permanently blocked.
//  - Independent of Npcap/pcap. Blocks at the ALE (Application Layer Enforcement)
//    layer BEFORE the application receives the packet.
//  - Thread-safe: all public methods are guarded by an internal mutex.
//  - Fail-open: if WFP is unavailable or not initialised, every method is a no-op
//    and the rest of the pipeline continues working in monitor-only mode.

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

// ── Forward-declare Windows types so this header compiles without pulling in
//    <windows.h> in every translation unit that only needs the interface. ──────
#ifdef _WIN32
    typedef void* HANDLE;
    typedef unsigned long long UINT64;
    // GUID defined inline to avoid <guiddef.h> cascade
    #ifndef GUID_DEFINED
    #define GUID_DEFINED
    typedef struct _GUID {
        unsigned long  Data1;
        unsigned short Data2;
        unsigned short Data3;
        unsigned char  Data4[8];
    } GUID;
    #endif
#endif

namespace DPI {

// ────────────────────────────────────────────────────────────────────────────
// Status
// ────────────────────────────────────────────────────────────────────────────
enum class WfpStatus {
    NOT_INITIALIZED,   // initialize() not yet called
    ACTIVE,            // WFP session open and filters are being installed
    NO_ADMIN,          // Process lacks administrator privileges
    UNAVAILABLE,       // WFP API not present (non-Windows build)
    ERROR_OTHER        // Unexpected WFP error
};

// ────────────────────────────────────────────────────────────────────────────
// Main class
// ────────────────────────────────────────────────────────────────────────────
class WfpEnforcement {
public:
    WfpEnforcement();
    ~WfpEnforcement();

    // Non-copyable, non-movable (owns OS handle)
    WfpEnforcement(const WfpEnforcement&) = delete;
    WfpEnforcement& operator=(const WfpEnforcement&) = delete;

    // ── Lifecycle ───────────────────────────────────────────────────────────

    // Open the WFP engine and create a dynamic sublayer.
    // Must be called once before any block/unblock methods.
    // Returns true on success. Logs reason on failure.
    bool initialize();

    // Close the WFP engine handle. All dynamically-installed filters are
    // removed automatically by Windows. Safe to call multiple times.
    void shutdown();

    bool isActive() const;
    WfpStatus getStatus() const { return status_; }
    std::string getStatusString() const;

    // ── IP-level enforcement ─────────────────────────────────────────────────
    // Installs a WFP filter that blocks all outbound connections to `ip`.
    // `ip` must be in the same byte order as PacketParser stores it (memcpy
    // from network bytes on x86 — equivalent to inet_addr() return value).
    bool blockIP(uint32_t ip);
    bool unblockIP(uint32_t ip);
    bool isIPBlocked(uint32_t ip) const;
    std::vector<uint32_t> getBlockedIPs() const;

    // ── Port-level enforcement ───────────────────────────────────────────────
    // Blocks all outbound connections to the given destination port.
    bool blockPort(uint16_t port);
    bool unblockPort(uint16_t port);
    bool isPortBlocked(uint16_t port) const;

    // ── Domain-level enforcement ─────────────────────────────────────────────
    // Domain blocking works by installing IP-level filters for every IP
    // currently associated with `domain` (from the DNS cache / connection map).
    // When new DNS resolutions arrive for a blocked domain, call
    // onNewDnsMapping() to install an additional filter automatically.
    //
    // Note printed to stdout when this is called:
    //   "Established connections may require reconnection before the block
    //    takes full effect. New connection attempts are blocked immediately."
    bool blockDomain(const std::string& domain, const std::vector<uint32_t>& known_ips);
    bool unblockDomain(const std::string& domain);
    bool isDomainBlocked(const std::string& domain) const;

    // Called by ConnectionTracker::learnDnsMapping() whenever DNS resolves a
    // new IP for any domain. If that domain has a block rule, installs a filter.
    void onNewDnsMapping(const std::string& domain, uint32_t ip);

    // Remove all WFP filters installed by this engine (but keep session open).
    bool clearAll();

    // ── Dashboard / JSON reporting ───────────────────────────────────────────
    struct State {
        WfpStatus status;
        std::string status_string;
        size_t active_ip_filters;
        size_t active_port_filters;
        size_t active_domain_rules;
        size_t total_active_filters;
    };
    State getState() const;

    // Returns a compact JSON fragment for dashboard output.json
    std::string getStateJson() const;

    // ── Wildcard domain matching helper ─────────────────────────────────────
    static bool domainMatches(const std::string& domain, const std::string& pattern);

private:
#ifdef _WIN32
    HANDLE engine_handle_ = nullptr;
    GUID   sublayer_key_  = {};
    GUID   provider_key_  = {};

    // ── Reference-counted Filter Tracking ────────────────────────────────────
    // ip_filters_: maps IP -> { filter_id, ref_count }
    struct IPFilterEntry {
        UINT64 filter_id = 0;
        int    ref_count = 0;
    };
    mutable std::mutex filter_mutex_;
    std::unordered_map<uint32_t, IPFilterEntry> ip_filters_;
    std::unordered_set<uint32_t>                explicit_blocked_ips_;
    std::unordered_map<uint16_t, UINT64>        port_filter_ids_;
    
    // domain -> set of resolved IPs currently associated with that domain
    std::unordered_map<std::string, std::unordered_set<uint32_t>> domain_ips_;
    // active blocked domain rules (including wildcard patterns like "*.example.com")
    std::unordered_set<std::string>             blocked_domain_rules_;

    // ── Private helpers ──────────────────────────────────────────────────────
    bool addIPFilterRef_locked(uint32_t ip);
    bool releaseIPFilterRef_locked(uint32_t ip);
    bool installIPFilter_locked(uint32_t ip, UINT64& filter_id_out);
    bool removeFilter_locked(UINT64 filter_id);
    bool installPortFilter_locked(uint16_t port, UINT64& filter_id_out);
    static std::string ipToString(uint32_t ip);
#endif
    WfpStatus   status_        = WfpStatus::NOT_INITIALIZED;
    std::string status_detail_;
};


} // namespace DPI

#endif // WFP_ENFORCEMENT_H
