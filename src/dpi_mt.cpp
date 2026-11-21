// =============================================================================
// High-Performance Multi-threaded Deep Packet Inspection (DPI) Engine
// Architecture: Reader -> Load Balancers (Hash Affinity) -> Fast Path Workers -> Output
// Features: L7 SNI extraction, HTTP Host extraction, DNS Query extraction,
//           CIDR subnet matching, Port filtering, Real-time Throughput Telemetry,
//           and JSON metrics export.
// =============================================================================

#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <optional>
#include <cctype>

#include "pcap_reader.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "types.h"

using namespace PacketAnalyzer;
using namespace DPI;

// =============================================================================
// Thread-Safe Bounded Queue
// =============================================================================
template<typename T>
class TSQueue {
public:
    TSQueue(size_t max_size = 20000) : max_size_(max_size), shutdown_(false) {}
    
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
        if (shutdown_) return;
        queue_.push(std::move(item));
        not_empty_.notify_one();
    }
    
    std::optional<T> pop(int timeout_ms = 100) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!not_empty_.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                                [this] { return !queue_.empty() || shutdown_; })) {
            return std::nullopt;
        }
        if (queue_.empty()) return std::nullopt;
        
        T item = std::move(queue_.front());
        queue_.pop();
        not_full_.notify_one();
        return item;
    }
    
    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            shutdown_ = true;
        }
        not_empty_.notify_all();
        not_full_.notify_all();
    }
    
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

private:
    size_t max_size_;
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    bool shutdown_;
};

// =============================================================================
// Packet Data Structure
// =============================================================================
struct Packet {
    uint32_t id = 0;
    uint32_t ts_sec = 0;
    uint32_t ts_usec = 0;
    FiveTuple tuple;
    std::vector<uint8_t> data;
    uint8_t tcp_flags = 0;
    size_t payload_offset = 0;
    size_t payload_length = 0;
};

// =============================================================================
// Flow Entry (Connection State)
// =============================================================================
struct FlowEntry {
    FiveTuple tuple;
    AppType app_type = AppType::UNKNOWN;
    std::string sni;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    bool classified = false;
    bool blocked = false;
};

// =============================================================================
// CIDR Subnet Rule Representation
// =============================================================================
struct CIDRSubnet {
    uint32_t network_be; // Big-endian network address
    uint32_t mask_be;    // Big-endian subnet mask
    std::string cidr_str;

    bool matches(uint32_t ip_le) const {
        // Convert little-endian IP from parser to big-endian
        uint32_t ip_be = ((ip_le & 0xFF) << 24) |
                         (((ip_le >> 8) & 0xFF) << 16) |
                         (((ip_le >> 16) & 0xFF) << 8) |
                         ((ip_le >> 24) & 0xFF);
        return (ip_be & mask_be) == (network_be & mask_be);
    }
};

// =============================================================================
// Advanced Policy & Rule Engine
// =============================================================================
class Rules {
public:
    void blockIP(const std::string& ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(parseIP_LE(ip));
        std::cout << "[Rules] Blocked IP: " << ip << "\n";
    }

    bool blockCIDR(const std::string& cidr) {
        size_t slash = cidr.find('/');
        if (slash == std::string::npos) return false;

        std::string ip_part = cidr.substr(0, slash);
        int prefix = std::stoi(cidr.substr(slash + 1));
        if (prefix < 0 || prefix > 32) return false;

        uint32_t ip_be = parseIP_BE(ip_part);
        uint32_t mask_be = prefix == 0 ? 0 : (~0U << (32 - prefix));

        std::lock_guard<std::mutex> lock(mutex_);
        blocked_cidrs_.push_back({ip_be, mask_be, cidr});
        std::cout << "[Rules] Blocked Subnet: " << cidr << "\n";
        return true;
    }

    void blockApp(const std::string& app) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(AppType::APP_COUNT); i++) {
            if (appTypeToString(static_cast<AppType>(i)) == app) {
                blocked_apps_.insert(static_cast<AppType>(i));
                std::cout << "[Rules] Blocked App: " << app << "\n";
                return;
            }
        }
        std::cerr << "[Rules] Unknown Application: " << app << "\n";
    }

    void blockDomain(const std::string& domain) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string d = domain;
        std::transform(d.begin(), d.end(), d.begin(), [](unsigned char c) { return std::tolower(c); });
        blocked_domains_.push_back(d);
        std::cout << "[Rules] Blocked Domain Pattern: " << domain << "\n";
    }

    void blockPort(uint16_t port) {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ports_.insert(port);
        std::cout << "[Rules] Blocked Port: " << port << "\n";
    }

    bool loadFromFile(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            std::cerr << "[Rules] Error: Could not open rules file: " << path << "\n";
            return false;
        }

        std::string line;
        int count = 0;
        while (std::getline(file, line)) {
            // Trim whitespace
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);

            if (line.empty() || line[0] == '#') continue;

            std::istringstream iss(line);
            std::string action, val;
            if (iss >> action >> val) {
                if (action == "block-ip") { blockIP(val); count++; }
                else if (action == "block-cidr") { blockCIDR(val); count++; }
                else if (action == "block-app") { blockApp(val); count++; }
                else if (action == "block-domain") { blockDomain(val); count++; }
                else if (action == "block-port") { blockPort(static_cast<uint16_t>(std::stoi(val))); count++; }
            }
        }
        std::cout << "[Rules] Loaded " << count << " rules from " << path << "\n";
        return true;
    }

    bool isBlocked(uint32_t src_ip_le, AppType app, const std::string& sni, uint16_t dst_port) const {
        std::lock_guard<std::mutex> lock(mutex_);

        // 1. Port blocking
        if (blocked_ports_.count(dst_port)) return true;

        // 2. Direct IP blocking
        if (blocked_ips_.count(src_ip_le)) return true;

        // 3. CIDR Subnet blocking
        for (const auto& subnet : blocked_cidrs_) {
            if (subnet.matches(src_ip_le)) return true;
        }

        // 4. Application blocking
        if (blocked_apps_.count(app)) return true;

        // 5. Domain pattern matching (exact and wildcard)
        if (!sni.empty()) {
            std::string lower_sni = sni;
            std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                           [](unsigned char c) { return std::tolower(c); });

            for (const auto& pattern : blocked_domains_) {
                if (matchesDomainPattern(lower_sni, pattern)) return true;
            }
        }

        return false;
    }

private:
    static bool matchesDomainPattern(const std::string& host, const std::string& pattern) {
        if (pattern.empty()) return false;
        if (pattern[0] == '*') {
            std::string suffix = pattern.substr(1); // e.g. .facebook.com
            if (host.length() >= suffix.length()) {
                if (host.compare(host.length() - suffix.length(), suffix.length(), suffix) == 0) {
                    return true;
                }
            }
            if (!suffix.empty() && suffix[0] == '.') {
                std::string base = suffix.substr(1);
                if (host == base) return true;
            }
            return false;
        }

        if (host == pattern) return true;
        if (host.length() > pattern.length() + 1) {
            size_t pos = host.length() - pattern.length();
            if (host[pos - 1] == '.' && host.compare(pos, pattern.length(), pattern) == 0) {
                return true;
            }
        }
        return false;
    }

    static uint32_t parseIP_LE(const std::string& ip) {
        uint32_t result = 0;
        int octet = 0, shift = 0;
        for (char c : ip) {
            if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
            else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
        }
        return result | (octet << shift);
    }

    static uint32_t parseIP_BE(const std::string& ip) {
        uint32_t b0 = 0, b1 = 0, b2 = 0, b3 = 0;
        char dot;
        std::istringstream iss(ip);
        iss >> b0 >> dot >> b1 >> dot >> b2 >> dot >> b3;
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

    mutable std::mutex mutex_;
    std::unordered_set<uint32_t> blocked_ips_;
    std::vector<CIDRSubnet> blocked_cidrs_;
    std::unordered_set<AppType> blocked_apps_;
    std::vector<std::string> blocked_domains_;
    std::unordered_set<uint16_t> blocked_ports_;
};

// =============================================================================
// Telemetry & Statistics
// =============================================================================
struct Stats {
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<uint64_t> forwarded{0};
    std::atomic<uint64_t> dropped{0};
    std::atomic<uint64_t> tcp_packets{0};
    std::atomic<uint64_t> udp_packets{0};
    std::atomic<uint64_t> dns_packets{0};

    // Packet size distribution
    std::atomic<uint64_t> size_under_64{0};
    std::atomic<uint64_t> size_64_511{0};
    std::atomic<uint64_t> size_512_1023{0};
    std::atomic<uint64_t> size_1024_1518{0};
    std::atomic<uint64_t> size_over_1518{0};

    std::chrono::high_resolution_clock::time_point start_time;
    std::chrono::high_resolution_clock::time_point end_time;

    std::mutex app_mutex;
    std::unordered_map<AppType, uint64_t> app_counts;
    std::unordered_map<AppType, uint64_t> app_bytes;
    std::unordered_map<std::string, AppType> detected_snis;
    std::unordered_set<std::string> dns_domains;

    void recordPacket(size_t len) {
        if (len < 64) size_under_64++;
        else if (len < 512) size_64_511++;
        else if (len < 1024) size_512_1023++;
        else if (len <= 1518) size_1024_1518++;
        else size_over_1518++;
    }

    void recordApp(AppType app, const std::string& sni, size_t bytes) {
        std::lock_guard<std::mutex> lock(app_mutex);
        app_counts[app]++;
        app_bytes[app] += bytes;
        if (!sni.empty()) {
            detected_snis[sni] = app;
        }
    }

    void recordDNSQuery(const std::string& domain) {
        std::lock_guard<std::mutex> lock(app_mutex);
        dns_domains.insert(domain);
    }
};

// =============================================================================
// Fast Path Worker Thread
// =============================================================================
class FastPath {
public:
    FastPath(int id, Rules* rules, Stats* stats, TSQueue<Packet>* output_queue)
        : id_(id), rules_(rules), stats_(stats), output_queue_(output_queue) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&FastPath::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    uint64_t processed() const { return processed_; }
    size_t flowCount() const { return flows_.size(); }

private:
    int id_;
    Rules* rules_;
    Stats* stats_;
    TSQueue<Packet>* output_queue_;
    TSQueue<Packet> input_queue_;
    std::unordered_map<FiveTuple, FlowEntry, DPI::FiveTupleHash> flows_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> processed_{0};
    
    void run() {
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            processed_++;
            Packet& pkt = *pkt_opt;
            stats_->recordPacket(pkt.data.size());
            
            FlowEntry& flow = flows_[pkt.tuple];
            if (flow.packets == 0) {
                flow.tuple = pkt.tuple;
            }
            flow.packets++;
            flow.bytes += pkt.data.size();
            
            if (!flow.classified) {
                classifyFlow(pkt, flow);
            }
            
            if (!flow.blocked) {
                flow.blocked = rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni, pkt.tuple.dst_port);
            }
            
            stats_->recordApp(flow.app_type, flow.sni, pkt.data.size());
            
            if (flow.blocked) {
                stats_->dropped++;
            } else {
                stats_->forwarded++;
                output_queue_->push(std::move(pkt));
            }
        }
    }
    
    void classifyFlow(Packet& pkt, FlowEntry& flow) {
        // 1. TLS SNI extraction for HTTPS (Port 443)
        if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto sni = SNIExtractor::extract(payload, pkt.payload_length);
            if (sni) {
                flow.sni = *sni;
                flow.app_type = sniToAppType(*sni);
                flow.classified = true;
                return;
            }
        }
        
        // 2. HTTP Host header extraction (Port 80)
        if (pkt.tuple.dst_port == 80 && pkt.payload_length > 10) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto host = HTTPHostExtractor::extract(payload, pkt.payload_length);
            if (host) {
                flow.sni = *host;
                flow.app_type = sniToAppType(*host);
                flow.classified = true;
                return;
            }
        }
        
        // 3. DNS Domain Query extraction (UDP/TCP Port 53)
        if ((pkt.tuple.dst_port == 53 || pkt.tuple.src_port == 53) && pkt.payload_length >= 12) {
            const uint8_t* payload = pkt.data.data() + pkt.payload_offset;
            auto query = DNSExtractor::extractQuery(payload, pkt.payload_length);
            if (query) {
                flow.sni = *query;
                flow.app_type = sniToAppType(*query);
                if (flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTPS) {
                    flow.app_type = AppType::DNS;
                }
                flow.classified = true;
                stats_->recordDNSQuery(*query);
                return;
            } else {
                flow.app_type = AppType::DNS;
                flow.classified = true;
                return;
            }
        }
        
        // Fallback port-based identification
        if (pkt.tuple.dst_port == 443) {
            flow.app_type = AppType::HTTPS;
        } else if (pkt.tuple.dst_port == 80) {
            flow.app_type = AppType::HTTP;
        }
    }
};

// =============================================================================
// Load Balancer (Flow-Affinity Hash Routing)
// =============================================================================
class LoadBalancer {
public:
    LoadBalancer(int id, std::vector<FastPath*> fps)
        : id_(id), fps_(std::move(fps)), num_fps_(fps_.size()) {}
    
    void start() {
        running_ = true;
        thread_ = std::thread(&LoadBalancer::run, this);
    }
    
    void stop() {
        running_ = false;
        input_queue_.shutdown();
        if (thread_.joinable()) thread_.join();
    }
    
    TSQueue<Packet>& queue() { return input_queue_; }
    uint64_t dispatched() const { return dispatched_; }

private:
    int id_;
    std::vector<FastPath*> fps_;
    size_t num_fps_;
    TSQueue<Packet> input_queue_;
    
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::atomic<uint64_t> dispatched_{0};
    
    void run() {
        DPI::FiveTupleHash hasher;
        while (running_) {
            auto pkt_opt = input_queue_.pop(100);
            if (!pkt_opt) continue;
            
            size_t hash = hasher(pkt_opt->tuple);
            size_t target_fp = hash % num_fps_;
            
            fps_[target_fp]->queue().push(std::move(*pkt_opt));
            dispatched_++;
        }
    }
};

// =============================================================================
// Top-Level DPI Orchestration Engine
// =============================================================================
class DPIEngine {
public:
    struct Config {
        int num_lbs = 2;
        int fps_per_lb = 2;
        std::string json_export_path;
    };
    
    DPIEngine(const Config& config) : config_(config) {
        int total_fps = config_.num_lbs * config_.fps_per_lb;
        
        std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║       DPI ENGINE - HIGH-PERFORMANCE TRAFFIC CLASSIFIER       ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Load Balancers: " << std::setw(2) << config_.num_lbs 
                  << "    FPs per LB: " << std::setw(2) << config_.fps_per_lb 
                  << "    Total Workers: " << std::setw(2) << total_fps << "     ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n\n";
        
        for (int i = 0; i < total_fps; i++) {
            fps_.push_back(std::make_unique<FastPath>(i, &rules_, &stats_, &output_queue_));
        }
        
        for (int lb = 0; lb < config_.num_lbs; lb++) {
            std::vector<FastPath*> lb_fps;
            int start = lb * config_.fps_per_lb;
            for (int i = 0; i < config_.fps_per_lb; i++) {
                lb_fps.push_back(fps_[start + i].get());
            }
            lbs_.push_back(std::make_unique<LoadBalancer>(lb, std::move(lb_fps)));
        }
    }
    
    void blockIP(const std::string& ip) { rules_.blockIP(ip); }
    void blockCIDR(const std::string& cidr) { rules_.blockCIDR(cidr); }
    void blockApp(const std::string& app) { rules_.blockApp(app); }
    void blockDomain(const std::string& domain) { rules_.blockDomain(domain); }
    void blockPort(uint16_t port) { rules_.blockPort(port); }
    bool loadRules(const std::string& path) { return rules_.loadFromFile(path); }
    
    bool process(const std::string& input_file, const std::string& output_file) {
        PcapReader reader;
        if (!reader.open(input_file)) {
            std::cerr << "Error: Cannot open PCAP input file: " << input_file << "\n";
            return false;
        }
        
        std::ofstream output(output_file, std::ios::binary);
        if (!output.is_open()) {
            std::cerr << "Error: Cannot open PCAP output file: " << output_file << "\n";
            return false;
        }
        
        // Write PCAP Global Header
        const auto& hdr = reader.getGlobalHeader();
        output.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
        
        // Start all worker threads
        for (auto& fp : fps_) fp->start();
        for (auto& lb : lbs_) lb->start();
        
        // Start dedicated PCAP Writer thread
        std::atomic<bool> output_running{true};
        std::thread output_thread([&]() {
            while (output_running || output_queue_.size() > 0) {
                auto pkt_opt = output_queue_.pop(50);
                if (!pkt_opt) continue;
                
                PcapPacketHeader phdr;
                phdr.ts_sec = pkt_opt->ts_sec;
                phdr.ts_usec = pkt_opt->ts_usec;
                phdr.incl_len = static_cast<uint32_t>(pkt_opt->data.size());
                phdr.orig_len = static_cast<uint32_t>(pkt_opt->data.size());
                
                output.write(reinterpret_cast<const char*>(&phdr), sizeof(phdr));
                output.write(reinterpret_cast<const char*>(pkt_opt->data.data()), pkt_opt->data.size());
            }
        });
        
        std::cout << "[Reader] Processing input packets...\n";
        stats_.start_time = std::chrono::high_resolution_clock::now();
        
        RawPacket raw;
        ParsedPacket parsed;
        uint32_t pkt_id = 0;
        DPI::FiveTupleHash hasher;
        
        while (reader.readNextPacket(raw)) {
            if (!PacketParser::parse(raw, parsed)) continue;
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) continue;
            
            Packet pkt;
            pkt.id = pkt_id++;
            pkt.ts_sec = raw.header.ts_sec;
            pkt.ts_usec = raw.header.ts_usec;
            pkt.tcp_flags = parsed.tcp_flags;
            pkt.data = std::move(raw.data);
            
            auto parseIP = [](const std::string& ip) -> uint32_t {
                uint32_t result = 0;
                int octet = 0, shift = 0;
                for (char c : ip) {
                    if (c == '.') { result |= (octet << shift); shift += 8; octet = 0; }
                    else if (c >= '0' && c <= '9') octet = octet * 10 + (c - '0');
                }
                return result | (octet << shift);
            };
            
            pkt.tuple.src_ip = parseIP(parsed.src_ip);
            pkt.tuple.dst_ip = parseIP(parsed.dest_ip);
            pkt.tuple.src_port = parsed.src_port;
            pkt.tuple.dst_port = parsed.dest_port;
            pkt.tuple.protocol = parsed.protocol;
            
            // Calculate payload offset
            pkt.payload_offset = 14;  // Ethernet header
            if (pkt.data.size() > 14) {
                uint8_t ip_ihl = pkt.data[14] & 0x0F;
                pkt.payload_offset += ip_ihl * 4;
                
                if (parsed.has_tcp && pkt.payload_offset + 12 < pkt.data.size()) {
                    uint8_t tcp_off = (pkt.data[pkt.payload_offset + 12] >> 4) & 0x0F;
                    pkt.payload_offset += tcp_off * 4;
                } else if (parsed.has_udp) {
                    pkt.payload_offset += 8;
                }
                
                if (pkt.payload_offset < pkt.data.size()) {
                    pkt.payload_length = pkt.data.size() - pkt.payload_offset;
                } else {
                    pkt.payload_length = 0;
                }
            }
            
            stats_.total_packets++;
            stats_.total_bytes += pkt.data.size();
            if (parsed.has_tcp) stats_.tcp_packets++;
            else if (parsed.has_udp) {
                stats_.udp_packets++;
                if (parsed.dest_port == 53 || parsed.src_port == 53) stats_.dns_packets++;
            }
            
            // Dispatch to Load Balancer via flow hash
            size_t lb_idx = hasher(pkt.tuple) % lbs_.size();
            lbs_[lb_idx]->queue().push(std::move(pkt));
        }
        
        std::cout << "[Reader] Completed parsing " << pkt_id << " packets.\n";
        reader.close();
        
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        
        for (auto& lb : lbs_) lb->stop();
        for (auto& fp : fps_) fp->stop();
        
        stats_.end_time = std::chrono::high_resolution_clock::now();
        
        output_running = false;
        output_queue_.shutdown();
        output_thread.join();
        output.close();
        
        printReport();
        
        if (!config_.json_export_path.empty()) {
            exportJSON(config_.json_export_path);
        }
        
        return true;
    }

private:
    void printReport() {
        std::chrono::duration<double, std::milli> duration = stats_.end_time - stats_.start_time;
        double elapsed_sec = duration.count() / 1000.0;
        if (elapsed_sec <= 0.0) elapsed_sec = 0.0001;
        
        uint64_t total_pkts = stats_.total_packets.load();
        uint64_t total_bytes = stats_.total_bytes.load();
        double pps = total_pkts / elapsed_sec;
        double mbps = (total_bytes * 8.0) / (elapsed_sec * 1000000.0);
        
        size_t total_flows = 0;
        for (const auto& fp : fps_) {
            total_flows += fp->flowCount();
        }
        
        std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                 SYSTEM PERFORMANCE TELEMETRY                 ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Wall-Clock Elapsed Time:  " << std::setw(10) << std::fixed << std::setprecision(2) << duration.count() << " ms                         ║\n";
        std::cout << "║ Packet Processing Rate:   " << std::setw(10) << std::fixed << std::setprecision(0) << pps << " packets/sec                ║\n";
        std::cout << "║ Network Data Throughput:  " << std::setw(10) << std::fixed << std::setprecision(2) << mbps << " Mbps                       ║\n";
        std::cout << "║ Concurrent Active Flows:  " << std::setw(10) << total_flows << " flows                      ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Total Packets Processed:  " << std::setw(10) << total_pkts << "                           ║\n";
        std::cout << "║ Total Payload Volume:     " << std::setw(10) << total_bytes << " bytes                     ║\n";
        std::cout << "║ TCP Transport Packets:    " << std::setw(10) << stats_.tcp_packets.load() << "                           ║\n";
        std::cout << "║ UDP Transport Packets:    " << std::setw(10) << stats_.udp_packets.load() << "                           ║\n";
        std::cout << "║ DNS Protocol Queries:     " << std::setw(10) << stats_.dns_packets.load() << "                           ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ Forwarded to Internet:    " << std::setw(10) << stats_.forwarded.load() << "                           ║\n";
        std::cout << "║ Dropped / Blocked:        " << std::setw(10) << stats_.dropped.load() << "                           ║\n";
        
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ WORKER LOAD DISTRIBUTION                                     ║\n";
        for (size_t i = 0; i < lbs_.size(); i++) {
            std::cout << "║   LB" << i << " Dispatched:         " << std::setw(10) << lbs_[i]->dispatched() << " packets                   ║\n";
        }
        for (size_t i = 0; i < fps_.size(); i++) {
            std::cout << "║   FP" << i << " Processed:          " << std::setw(10) << fps_[i]->processed() << " packets (" << std::setw(2) << fps_[i]->flowCount() << " flows)       ║\n";
        }
        
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ PACKET SIZE HISTOGRAM                                        ║\n";
        std::cout << "║   < 64 Bytes:             " << std::setw(10) << stats_.size_under_64.load() << "                           ║\n";
        std::cout << "║   64 - 511 Bytes:         " << std::setw(10) << stats_.size_64_511.load() << "                           ║\n";
        std::cout << "║   512 - 1023 Bytes:       " << std::setw(10) << stats_.size_512_1023.load() << "                           ║\n";
        std::cout << "║   1024 - 1518 Bytes:      " << std::setw(10) << stats_.size_1024_1518.load() << "                           ║\n";
        std::cout << "║   > 1518 Bytes (Jumbo):   " << std::setw(10) << stats_.size_over_1518.load() << "                           ║\n";
        
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ APPLICATION TRAFFIC BREAKDOWN                                ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        
        std::lock_guard<std::mutex> lock(stats_.app_mutex);
        std::vector<std::pair<AppType, uint64_t>> sorted_apps(stats_.app_counts.begin(), stats_.app_counts.end());
        std::sort(sorted_apps.begin(), sorted_apps.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        
        for (const auto& [app, count] : sorted_apps) {
            double pkt_pct = total_pkts > 0 ? (100.0 * count / total_pkts) : 0;
            uint64_t bytes = stats_.app_bytes[app];
            double byte_pct = total_bytes > 0 ? (100.0 * bytes / total_bytes) : 0;
            int bar_len = static_cast<int>(pkt_pct / 5);
            std::string bar(bar_len, '#');
            
            std::cout << "║ " << std::setw(13) << std::left << appTypeToString(app)
                      << std::setw(5) << std::right << count << " pkts (" << std::setw(4) << std::fixed << std::setprecision(1) << pkt_pct << "%) "
                      << std::setw(6) << bytes << "B (" << std::setw(4) << byte_pct << "%) "
                      << std::setw(11) << std::left << bar << " ║\n";
        }
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
        
        if (!stats_.detected_snis.empty()) {
            std::cout << "\n[L7 Identified Domains & Hostnames]\n";
            for (const auto& [sni, app] : stats_.detected_snis) {
                std::cout << "  - " << std::setw(32) << std::left << sni << " -> " << appTypeToString(app) << "\n";
            }
        }
        
        if (!stats_.dns_domains.empty()) {
            std::cout << "\n[DNS Queries Resolved]\n";
            for (const auto& domain : stats_.dns_domains) {
                std::cout << "  - " << domain << "\n";
            }
        }
    }

    void exportJSON(const std::string& path) {
        std::ofstream file(path);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open JSON file for export: " << path << "\n";
            return;
        }

        std::chrono::duration<double, std::milli> duration = stats_.end_time - stats_.start_time;
        double elapsed_sec = duration.count() / 1000.0;
        if (elapsed_sec <= 0.0) elapsed_sec = 0.0001;

        uint64_t total_pkts = stats_.total_packets.load();
        uint64_t total_bytes = stats_.total_bytes.load();
        double pps = total_pkts / elapsed_sec;
        double mbps = (total_bytes * 8.0) / (elapsed_sec * 1000000.0);

        size_t total_flows = 0;
        for (const auto& fp : fps_) total_flows += fp->flowCount();

        file << "{\n";
        file << "  \"system_telemetry\": {\n";
        file << "    \"elapsed_ms\": " << std::fixed << std::setprecision(2) << duration.count() << ",\n";
        file << "    \"packets_per_second\": " << std::fixed << std::setprecision(2) << pps << ",\n";
        file << "    \"throughput_mbps\": " << std::fixed << std::setprecision(2) << mbps << ",\n";
        file << "    \"concurrent_flows\": " << total_flows << ",\n";
        file << "    \"total_packets\": " << total_pkts << ",\n";
        file << "    \"total_bytes\": " << total_bytes << ",\n";
        file << "    \"forwarded\": " << stats_.forwarded.load() << ",\n";
        file << "    \"dropped\": " << stats_.dropped.load() << ",\n";
        file << "    \"tcp_packets\": " << stats_.tcp_packets.load() << ",\n";
        file << "    \"udp_packets\": " << stats_.udp_packets.load() << ",\n";
        file << "    \"dns_packets\": " << stats_.dns_packets.load() << "\n";
        file << "  },\n";

        file << "  \"packet_size_distribution\": {\n";
        file << "    \"under_64\": " << stats_.size_under_64.load() << ",\n";
        file << "    \"64_to_511\": " << stats_.size_64_511.load() << ",\n";
        file << "    \"512_to_1023\": " << stats_.size_512_1023.load() << ",\n";
        file << "    \"1024_to_1518\": " << stats_.size_1024_1518.load() << ",\n";
        file << "    \"over_1518_jumbo\": " << stats_.size_over_1518.load() << "\n";
        file << "  },\n";

        file << "  \"applications\": [\n";
        {
            std::lock_guard<std::mutex> lock(stats_.app_mutex);
            bool first = true;
            for (const auto& [app, count] : stats_.app_counts) {
                if (!first) file << ",\n";
                first = false;
                double pkt_pct = total_pkts > 0 ? (100.0 * count / total_pkts) : 0;
                uint64_t bytes = stats_.app_bytes[app];
                double byte_pct = total_bytes > 0 ? (100.0 * bytes / total_bytes) : 0;
                file << "    {\n";
                file << "      \"name\": \"" << appTypeToString(app) << "\",\n";
                file << "      \"packet_count\": " << count << ",\n";
                file << "      \"packet_percent\": " << std::fixed << std::setprecision(1) << pkt_pct << ",\n";
                file << "      \"bytes\": " << bytes << ",\n";
                file << "      \"byte_percent\": " << std::fixed << std::setprecision(1) << byte_pct << "\n";
                file << "    }";
            }
        }
        file << "\n  ],\n";

        file << "  \"detected_domains\": [\n";
        {
            std::lock_guard<std::mutex> lock(stats_.app_mutex);
            bool first = true;
            for (const auto& [sni, app] : stats_.detected_snis) {
                if (!first) file << ",\n";
                first = false;
                file << "    {\"domain\": \"" << sni << "\", \"application\": \"" << appTypeToString(app) << "\"}";
            }
        }
        file << "\n  ]\n";
        file << "}\n";

        std::cout << "[DPIEngine] Telemetry exported to JSON: " << path << "\n";
    }

    Config config_;
    Rules rules_;
    Stats stats_;
    TSQueue<Packet> output_queue_;
    std::vector<std::unique_ptr<FastPath>> fps_;
    std::vector<std::unique_ptr<LoadBalancer>> lbs_;
};

// =============================================================================
// CLI Entry Point
// =============================================================================
void printUsage(const char* prog) {
    std::cout << R"(
High-Performance Deep Packet Inspection (DPI) & Traffic Classifier v2.5
======================================================================
Usage: )" << prog << R"( <input.pcap> <output.pcap> [options]

Security & Policy Filtering:
  --block-app <app>       Block application (YouTube, Facebook, Netflix, TikTok, etc.)
  --block-domain <dom>    Block domain or wildcard pattern (e.g., *.doubleclick.net, facebook.com)
  --block-ip <ip>         Block single source IPv4 address (e.g., 192.168.1.50)
  --block-cidr <subnet>   Block entire CIDR IPv4 subnet (e.g., 10.0.0.0/8, 192.168.1.0/24)
  --block-port <port>     Block destination TCP/UDP port (e.g., 8080)
  --rules <file>          Load rules from a configuration file

Performance & Architecture Tuning:
  --lbs <n>               Number of load balancer threads (default: 2)
  --fps <n>               Fast Path worker threads per LB (default: 2)

Telemetry & Output:
  --export-json <file>    Export structured performance & flow analytics to JSON

Examples:
  )" << prog << R"( input.pcap filtered.pcap --block-app YouTube
  )" << prog << R"( input.pcap filtered.pcap --block-cidr 10.0.0.0/8 --block-domain *.tiktok.com
  )" << prog << R"( input.pcap filtered.pcap --rules security_rules.conf --export-json metrics.json
)";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string input = argv[1];
    std::string output = argv[2];
    
    DPIEngine::Config cfg;
    std::vector<std::string> block_ips, block_cidrs, block_apps, block_domains;
    std::vector<uint16_t> block_ports;
    std::string rules_file;
    
    for (int i = 3; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--block-ip" && i + 1 < argc) block_ips.push_back(argv[++i]);
        else if (arg == "--block-cidr" && i + 1 < argc) block_cidrs.push_back(argv[++i]);
        else if (arg == "--block-app" && i + 1 < argc) block_apps.push_back(argv[++i]);
        else if (arg == "--block-domain" && i + 1 < argc) block_domains.push_back(argv[++i]);
        else if (arg == "--block-port" && i + 1 < argc) block_ports.push_back(static_cast<uint16_t>(std::stoi(argv[++i])));
        else if (arg == "--rules" && i + 1 < argc) rules_file = argv[++i];
        else if (arg == "--export-json" && i + 1 < argc) cfg.json_export_path = argv[++i];
        else if (arg == "--lbs" && i + 1 < argc) cfg.num_lbs = std::stoi(argv[++i]);
        else if (arg == "--fps" && i + 1 < argc) cfg.fps_per_lb = std::stoi(argv[++i]);
    }
    
    DPIEngine engine(cfg);
    
    if (!rules_file.empty()) {
        engine.loadRules(rules_file);
    }
    for (const auto& ip : block_ips) engine.blockIP(ip);
    for (const auto& cidr : block_cidrs) engine.blockCIDR(cidr);
    for (const auto& app : block_apps) engine.blockApp(app);
    for (const auto& dom : block_domains) engine.blockDomain(dom);
    for (uint16_t port : block_ports) engine.blockPort(port);
    
    if (!engine.process(input, output)) {
        return 1;
    }
    
    std::cout << "[DPIEngine] Clean filtered PCAP written to: " << output << "\n";
    return 0;
}
