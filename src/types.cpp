#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses
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
        case AppType::UNKNOWN:       return "Unknown";
        case AppType::HTTP:          return "HTTP";
        case AppType::HTTPS:         return "HTTPS";
        case AppType::DNS:           return "DNS";
        case AppType::TLS:           return "TLS";
        case AppType::QUIC:          return "QUIC";
        
        // Search & Big Tech
        case AppType::GOOGLE:        return "Google";
        case AppType::MICROSOFT:     return "Microsoft";
        case AppType::APPLE:         return "Apple";
        case AppType::AMAZON:        return "Amazon";
        case AppType::CLOUDFLARE:    return "Cloudflare";
        
        // Social & Messaging
        case AppType::FACEBOOK:      return "Facebook";
        case AppType::INSTAGRAM:     return "Instagram";
        case AppType::WHATSAPP:      return "WhatsApp";
        case AppType::TWITTER:       return "Twitter/X";
        case AppType::TELEGRAM:      return "Telegram";
        case AppType::TIKTOK:        return "TikTok";
        case AppType::DISCORD:       return "Discord";
        case AppType::REDDIT:        return "Reddit";
        case AppType::LINKEDIN:      return "LinkedIn";
        case AppType::SNAPCHAT:      return "Snapchat";
        case AppType::PINTEREST:     return "Pinterest";
        
        // Video & Streaming & Media
        case AppType::YOUTUBE:       return "YouTube";
        case AppType::NETFLIX:       return "Netflix";
        case AppType::SPOTIFY:       return "Spotify";
        case AppType::TWITCH:        return "Twitch";
        case AppType::DISNEYPLUS:    return "Disney+";
        case AppType::HULU:          return "Hulu";
        case AppType::SOUNDCLOUD:    return "SoundCloud";
        
        // AI, Productivity & Collaboration
        case AppType::OPENAI:        return "ChatGPT/OpenAI";
        case AppType::NOTION:        return "Notion";
        case AppType::ZOOM:          return "Zoom";
        case AppType::SLACK:         return "Slack";
        case AppType::TEAMS:         return "Microsoft Teams";
        case AppType::CANVA:         return "Canva";
        case AppType::FIGMA:         return "Figma";
        case AppType::TRELLO:        return "Trello";
        
        // Developer & Tech / Learning
        case AppType::GITHUB:        return "GitHub";
        case AppType::GITLAB:        return "GitLab";
        case AppType::BITBUCKET:     return "Bitbucket";
        case AppType::STACKOVERFLOW: return "StackOverflow";
        case AppType::LEETCODE:      return "LeetCode";
        case AppType::WIKIPEDIA:     return "Wikipedia";
        case AppType::MEDIUM:        return "Medium";
        case AppType::NPM:           return "npm Registry";
        case AppType::DOCKER:        return "Docker";
        case AppType::HUGGINGFACE:   return "Hugging Face";
        case AppType::KAGGLE:        return "Kaggle";
        case AppType::GEEKSFORGEEKS: return "GeeksforGeeks";
        case AppType::CODECHEF:      return "CodeChef";
        case AppType::HACKERRANK:    return "HackerRank";
        
        // Gaming & Entertainment
        case AppType::STEAM:         return "Steam";
        case AppType::ROBLOX:        return "Roblox";
        case AppType::EPICGAMES:     return "Epic Games";
        case AppType::RIOTGAMES:     return "Riot Games";
        
        // E-Commerce & Services
        case AppType::EBAY:          return "eBay";
        case AppType::ALIEXPRESS:    return "AliExpress";
        case AppType::PAYPAL:        return "PayPal";
        case AppType::UBER:          return "Uber";
        
        default:                     return "Unknown";
    }
}

// Map SNI/domain to application type
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert to lowercase for matching
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    // Check for known patterns
    
    // ── YouTube (Checked before general Google to capture googlevideo/yt3.ggpht) ──
    if (lower_sni.find("youtube") != std::string::npos ||
        lower_sni.find("googlevideo") != std::string::npos ||
        lower_sni.find("ytimg") != std::string::npos ||
        lower_sni.find("youtu.be") != std::string::npos ||
        lower_sni.find("yt3.ggpht") != std::string::npos) {
        return AppType::YOUTUBE;
    }
    
    // ── Google ──
    if (lower_sni.find("google") != std::string::npos ||
        lower_sni.find("gstatic") != std::string::npos ||
        lower_sni.find("googleapis") != std::string::npos ||
        lower_sni.find("ggpht") != std::string::npos ||
        lower_sni.find("gvt1") != std::string::npos ||
        lower_sni.find("1e100.net") != std::string::npos) {
        return AppType::GOOGLE;
    }
    
    // ── Facebook/Meta ──
    if (lower_sni.find("facebook") != std::string::npos ||
        lower_sni.find("fbcdn") != std::string::npos ||
        lower_sni.find("fb.com") != std::string::npos ||
        lower_sni.find("fbsbx") != std::string::npos ||
        lower_sni.find("meta.com") != std::string::npos) {
        return AppType::FACEBOOK;
    }
    
    // ── Instagram ──
    if (lower_sni.find("instagram") != std::string::npos ||
        lower_sni.find("cdninstagram") != std::string::npos) {
        return AppType::INSTAGRAM;
    }
    
    // ── WhatsApp ──
    if (lower_sni.find("whatsapp") != std::string::npos ||
        lower_sni.find("wa.me") != std::string::npos) {
        return AppType::WHATSAPP;
    }
    
    // ── Twitter/X ──
    if (lower_sni.find("twitter") != std::string::npos ||
        lower_sni.find("twimg") != std::string::npos ||
        lower_sni.find("x.com") != std::string::npos ||
        lower_sni.find("t.co") != std::string::npos) {
        return AppType::TWITTER;
    }
    
    // ── Snapchat ──
    if (lower_sni.find("snapchat") != std::string::npos ||
        lower_sni.find("sc-cdn") != std::string::npos) {
        return AppType::SNAPCHAT;
    }
    
    // ── Pinterest ──
    if (lower_sni.find("pinterest") != std::string::npos ||
        lower_sni.find("pinimg") != std::string::npos) {
        return AppType::PINTEREST;
    }
    
    // ── Netflix ──
    if (lower_sni.find("netflix") != std::string::npos ||
        lower_sni.find("nflxvideo") != std::string::npos ||
        lower_sni.find("nflximg") != std::string::npos ||
        lower_sni.find("nflxext") != std::string::npos) {
        return AppType::NETFLIX;
    }
    
    // ── Disney+ & Hulu ──
    if (lower_sni.find("disneyplus") != std::string::npos ||
        lower_sni.find("bamgrid") != std::string::npos) {
        return AppType::DISNEYPLUS;
    }
    if (lower_sni.find("hulu") != std::string::npos) {
        return AppType::HULU;
    }
    
    // ── Amazon & AWS ──
    if (lower_sni.find("amazon") != std::string::npos ||
        lower_sni.find("amazonaws") != std::string::npos ||
        lower_sni.find("cloudfront") != std::string::npos ||
        lower_sni.find("aws") != std::string::npos ||
        lower_sni.find("media-amazon") != std::string::npos) {
        return AppType::AMAZON;
    }
    
    // ── Microsoft Teams (check before general Microsoft) ──
    if (lower_sni.find("teams.microsoft.com") != std::string::npos ||
        lower_sni.find("teams.live.com") != std::string::npos) {
        return AppType::TEAMS;
    }
    
    // ── Microsoft ──
    if (lower_sni.find("microsoft") != std::string::npos ||
        lower_sni.find("msn.com") != std::string::npos ||
        lower_sni.find("office") != std::string::npos ||
        lower_sni.find("azure") != std::string::npos ||
        lower_sni.find("live.com") != std::string::npos ||
        lower_sni.find("outlook") != std::string::npos ||
        lower_sni.find("bing") != std::string::npos ||
        lower_sni.find("windows") != std::string::npos) {
        return AppType::MICROSOFT;
    }
    
    // ── Apple ──
    if (lower_sni.find("apple") != std::string::npos ||
        lower_sni.find("icloud") != std::string::npos ||
        lower_sni.find("mzstatic") != std::string::npos ||
        lower_sni.find("itunes") != std::string::npos ||
        lower_sni.find("aaplimg") != std::string::npos) {
        return AppType::APPLE;
    }
    
    // ── Telegram ──
    if (lower_sni.find("telegram") != std::string::npos ||
        lower_sni.find("t.me") != std::string::npos) {
        return AppType::TELEGRAM;
    }
    
    // ── TikTok ──
    if (lower_sni.find("tiktok") != std::string::npos ||
        lower_sni.find("tiktokcdn") != std::string::npos ||
        lower_sni.find("musical.ly") != std::string::npos ||
        lower_sni.find("bytedance") != std::string::npos ||
        lower_sni.find("byteoversea") != std::string::npos) {
        return AppType::TIKTOK;
    }
    
    // ── Spotify ──
    if (lower_sni.find("spotify") != std::string::npos ||
        lower_sni.find("scdn.co") != std::string::npos ||
        lower_sni.find("spoti.fi") != std::string::npos) {
        return AppType::SPOTIFY;
    }
    
    // ── Twitch ──
    if (lower_sni.find("twitch") != std::string::npos ||
        lower_sni.find("ttvnw.net") != std::string::npos ||
        lower_sni.find("jtvnw.net") != std::string::npos) {
        return AppType::TWITCH;
    }
    
    // ── SoundCloud ──
    if (lower_sni.find("soundcloud") != std::string::npos ||
        lower_sni.find("sndcdn") != std::string::npos) {
        return AppType::SOUNDCLOUD;
    }
    
    // ── Zoom ──
    if (lower_sni.find("zoom.us") != std::string::npos ||
        lower_sni.find("zoomgov") != std::string::npos ||
        lower_sni.find("zoom") != std::string::npos) {
        return AppType::ZOOM;
    }
    
    // ── Slack ──
    if (lower_sni.find("slack") != std::string::npos ||
        lower_sni.find("slack-edge") != std::string::npos ||
        lower_sni.find("slack-msgs") != std::string::npos) {
        return AppType::SLACK;
    }
    
    // ── Discord ──
    if (lower_sni.find("discord") != std::string::npos ||
        lower_sni.find("discordapp") != std::string::npos ||
        lower_sni.find("discordstatus") != std::string::npos) {
        return AppType::DISCORD;
    }
    
    // ── GitHub ──
    if (lower_sni.find("github") != std::string::npos ||
        lower_sni.find("githubusercontent") != std::string::npos ||
        lower_sni.find("github.io") != std::string::npos ||
        lower_sni.find("ghcr.io") != std::string::npos) {
        return AppType::GITHUB;
    }
    
    // ── GitLab ──
    if (lower_sni.find("gitlab") != std::string::npos) {
        return AppType::GITLAB;
    }
    
    // ── Bitbucket ──
    if (lower_sni.find("bitbucket") != std::string::npos) {
        return AppType::BITBUCKET;
    }
    
    // ── Cloudflare ──
    if (lower_sni.find("cloudflare") != std::string::npos ||
        lower_sni.find("cf-") != std::string::npos ||
        lower_sni.find("cdnjs") != std::string::npos) {
        return AppType::CLOUDFLARE;
    }
    
    // ── Wikipedia / Wikimedia ──
    if (lower_sni.find("wikipedia") != std::string::npos ||
        lower_sni.find("wikimedia") != std::string::npos ||
        lower_sni.find("wikidata") != std::string::npos) {
        return AppType::WIKIPEDIA;
    }
    
    // ── Reddit ──
    if (lower_sni.find("reddit") != std::string::npos ||
        lower_sni.find("redd.it") != std::string::npos ||
        lower_sni.find("redditmedia") != std::string::npos) {
        return AppType::REDDIT;
    }
    
    // ── OpenAI / ChatGPT ──
    if (lower_sni.find("openai") != std::string::npos ||
        lower_sni.find("chatgpt") != std::string::npos ||
        lower_sni.find("oaistatic") != std::string::npos ||
        lower_sni.find("oaiusercontent") != std::string::npos) {
        return AppType::OPENAI;
    }
    
    // ── Notion ──
    if (lower_sni.find("notion") != std::string::npos ||
        lower_sni.find("notion.so") != std::string::npos ||
        lower_sni.find("notion.site") != std::string::npos) {
        return AppType::NOTION;
    }
    
    // ── Canva / Figma / Trello ──
    if (lower_sni.find("canva") != std::string::npos) {
        return AppType::CANVA;
    }
    if (lower_sni.find("figma") != std::string::npos) {
        return AppType::FIGMA;
    }
    if (lower_sni.find("trello") != std::string::npos) {
        return AppType::TRELLO;
    }
    
    // ── LeetCode ──
    if (lower_sni.find("leetcode") != std::string::npos) {
        return AppType::LEETCODE;
    }
    
    // ── GeeksforGeeks / CodeChef / HackerRank ──
    if (lower_sni.find("geeksforgeeks") != std::string::npos ||
        lower_sni.find("gfg") != std::string::npos) {
        return AppType::GEEKSFORGEEKS;
    }
    if (lower_sni.find("codechef") != std::string::npos) {
        return AppType::CODECHEF;
    }
    if (lower_sni.find("hackerrank") != std::string::npos) {
        return AppType::HACKERRANK;
    }
    
    // ── LinkedIn ──
    if (lower_sni.find("linkedin") != std::string::npos ||
        lower_sni.find("licdn") != std::string::npos) {
        return AppType::LINKEDIN;
    }
    
    // ── StackOverflow ──
    if (lower_sni.find("stackoverflow") != std::string::npos ||
        lower_sni.find("stackexchange") != std::string::npos ||
        lower_sni.find("sstatic.net") != std::string::npos) {
        return AppType::STACKOVERFLOW;
    }
    
    // ── Medium ──
    if (lower_sni.find("medium.com") != std::string::npos) {
        return AppType::MEDIUM;
    }
    
    // ── NPM & Docker ──
    if (lower_sni.find("npmjs") != std::string::npos ||
        lower_sni.find("npmjs.org") != std::string::npos) {
        return AppType::NPM;
    }
    if (lower_sni.find("docker") != std::string::npos ||
        lower_sni.find("dockerhub") != std::string::npos) {
        return AppType::DOCKER;
    }
    
    // ── Hugging Face & Kaggle (AI / Data Science) ──
    if (lower_sni.find("huggingface") != std::string::npos ||
        lower_sni.find("hf.co") != std::string::npos) {
        return AppType::HUGGINGFACE;
    }
    if (lower_sni.find("kaggle") != std::string::npos) {
        return AppType::KAGGLE;
    }
    
    // ── Gaming (Steam, Roblox, Epic Games, Riot Games) ──
    if (lower_sni.find("steampowered") != std::string::npos ||
        lower_sni.find("steamcommunity") != std::string::npos ||
        lower_sni.find("steamstatic") != std::string::npos ||
        lower_sni.find("valvesoftware") != std::string::npos) {
        return AppType::STEAM;
    }
    if (lower_sni.find("roblox") != std::string::npos ||
        lower_sni.find("rbxcdn") != std::string::npos) {
        return AppType::ROBLOX;
    }
    if (lower_sni.find("epicgames") != std::string::npos ||
        lower_sni.find("unrealengine") != std::string::npos) {
        return AppType::EPICGAMES;
    }
    if (lower_sni.find("riotgames") != std::string::npos ||
        lower_sni.find("leagueoflegends") != std::string::npos ||
        lower_sni.find("valortant") != std::string::npos ||
        lower_sni.find("valorant") != std::string::npos) {
        return AppType::RIOTGAMES;
    }
    
    // ── E-Commerce & FinTech (eBay, AliExpress, PayPal, Uber) ──
    if (lower_sni.find("ebay") != std::string::npos) {
        return AppType::EBAY;
    }
    if (lower_sni.find("aliexpress") != std::string::npos ||
        lower_sni.find("alibaba") != std::string::npos) {
        return AppType::ALIEXPRESS;
    }
    if (lower_sni.find("paypal") != std::string::npos) {
        return AppType::PAYPAL;
    }
    if (lower_sni.find("uber") != std::string::npos) {
        return AppType::UBER;
    }
    
    // If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType::HTTPS;
}

} // namespace DPI
