#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses (Little Endian to human-readable dotted-decimal)
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

// Domain matching helper: checks exact match or valid subdomain match
static bool domainMatches(const std::string& host, const std::string& domain) {
    if (host == domain) return true;
    if (domain.empty()) return false;
    if (host.length() > domain.length() + 1) {
        size_t pos = host.length() - domain.length();
        if (host[pos - 1] == '.' && host.compare(pos, domain.length(), domain) == 0) {
            return true;
        }
    }
    return false;
}

// Map SNI/domain to application type with exact domain boundary checking
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert to lowercase for matching
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    // YouTube (checked before general Google services)
    if (domainMatches(lower_sni, "youtube.com") ||
        domainMatches(lower_sni, "youtu.be") ||
        domainMatches(lower_sni, "ytimg.com") ||
        lower_sni.find("yt3.ggpht") != std::string::npos) {
        return AppType::YOUTUBE;
    }

    // Google Services
    if (domainMatches(lower_sni, "google.com") ||
        domainMatches(lower_sni, "gstatic.com") ||
        domainMatches(lower_sni, "googleapis.com") ||
        domainMatches(lower_sni, "ggpht.com") ||
        domainMatches(lower_sni, "gvt1.com") ||
        lower_sni.find("google.") != std::string::npos) {
        return AppType::GOOGLE;
    }

    // Facebook / Meta
    if (domainMatches(lower_sni, "facebook.com") ||
        domainMatches(lower_sni, "fbcdn.net") ||
        domainMatches(lower_sni, "fb.com") ||
        domainMatches(lower_sni, "fbsbx.com") ||
        domainMatches(lower_sni, "meta.com")) {
        return AppType::FACEBOOK;
    }
    
    // Instagram (Meta)
    if (domainMatches(lower_sni, "instagram.com") ||
        domainMatches(lower_sni, "cdninstagram.com")) {
        return AppType::INSTAGRAM;
    }
    
    // WhatsApp (Meta)
    if (domainMatches(lower_sni, "whatsapp.com") ||
        domainMatches(lower_sni, "whatsapp.net") ||
        domainMatches(lower_sni, "wa.me")) {
        return AppType::WHATSAPP;
    }
    
    // Netflix
    if (domainMatches(lower_sni, "netflix.com") ||
        domainMatches(lower_sni, "nflxvideo.net") ||
        domainMatches(lower_sni, "nflximg.net") ||
        lower_sni.find("netflix") != std::string::npos) {
        return AppType::NETFLIX;
    }

    // Microsoft
    if (domainMatches(lower_sni, "microsoft.com") ||
        domainMatches(lower_sni, "msn.com") ||
        domainMatches(lower_sni, "office.com") ||
        domainMatches(lower_sni, "azure.com") ||
        domainMatches(lower_sni, "live.com") ||
        domainMatches(lower_sni, "outlook.com") ||
        domainMatches(lower_sni, "bing.com") ||
        lower_sni.find("microsoft") != std::string::npos) {
        return AppType::MICROSOFT;
    }

    // Twitter / X (strict domain boundary check so 't.co' and 'x.com' don't match 'microsoft.com' or 'netflix.com')
    if (domainMatches(lower_sni, "twitter.com") ||
        domainMatches(lower_sni, "twimg.com") ||
        domainMatches(lower_sni, "x.com") ||
        domainMatches(lower_sni, "t.co")) {
        return AppType::TWITTER;
    }
    
    // Amazon
    if (domainMatches(lower_sni, "amazon.com") ||
        domainMatches(lower_sni, "amazonaws.com") ||
        domainMatches(lower_sni, "cloudfront.net") ||
        lower_sni.find("amazon.") != std::string::npos) {
        return AppType::AMAZON;
    }
    
    // Apple
    if (domainMatches(lower_sni, "apple.com") ||
        domainMatches(lower_sni, "icloud.com") ||
        domainMatches(lower_sni, "mzstatic.com") ||
        domainMatches(lower_sni, "itunes.apple.com")) {
        return AppType::APPLE;
    }
    
    // Telegram
    if (domainMatches(lower_sni, "telegram.org") ||
        domainMatches(lower_sni, "t.me") ||
        lower_sni.find("telegram") != std::string::npos) {
        return AppType::TELEGRAM;
    }
    
    // TikTok
    if (domainMatches(lower_sni, "tiktok.com") ||
        domainMatches(lower_sni, "tiktokcdn.com") ||
        domainMatches(lower_sni, "musical.ly") ||
        domainMatches(lower_sni, "byteoversea.com") ||
        lower_sni.find("tiktok") != std::string::npos) {
        return AppType::TIKTOK;
    }
    
    // Spotify
    if (domainMatches(lower_sni, "spotify.com") ||
        domainMatches(lower_sni, "scdn.co") ||
        lower_sni.find("spotify") != std::string::npos) {
        return AppType::SPOTIFY;
    }
    
    // Zoom
    if (domainMatches(lower_sni, "zoom.us") ||
        lower_sni.find("zoom") != std::string::npos) {
        return AppType::ZOOM;
    }
    
    // Discord
    if (domainMatches(lower_sni, "discord.com") ||
        domainMatches(lower_sni, "discordapp.com") ||
        domainMatches(lower_sni, "discord.gg")) {
        return AppType::DISCORD;
    }
    
    // GitHub
    if (domainMatches(lower_sni, "github.com") ||
        domainMatches(lower_sni, "githubusercontent.com") ||
        domainMatches(lower_sni, "github.io")) {
        return AppType::GITHUB;
    }
    
    // Cloudflare
    if (domainMatches(lower_sni, "cloudflare.com") ||
        domainMatches(lower_sni, "cloudflare-dns.com")) {
        return AppType::CLOUDFLARE;
    }
    
    // If SNI is present but not recognized in known catalog, still mark as HTTPS
    return AppType::HTTPS;
}

} // namespace DPI
