/*
 * CollectorService.cpp
 * User-mode Windows Service.
 *
 * - Opens the kernel driver device handle
 * - Continuously reads EDR_EVENT_RECORDs from the ring buffer via ReadFile
 * - Enriches each event with CB EDR REST API facet data
 * - Accumulates events into a BatchBuffer
 * - Flushes to Azure Blob and/or S3 when size OR time threshold is reached
 */

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsvc.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <wininet.h>

#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <memory>
#include <functional>
#include <unordered_map>

#include "../shared/EdrShared.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ws2_32.lib")

// -------------------------------------------------------------------------
// Configuration  (populated from environment variables at startup)
// -------------------------------------------------------------------------
struct CollectorConfig
{
    // CB EDR
    std::wstring CbEdrServerUrl;
    std::wstring CbEdrApiToken;
    bool         CbEdrVerifySsl = true;
    int          CbEdrEnrichIntervalSec = 60;  // how often to refresh facet cache

    // Azure Blob
    std::wstring AzureConnectionString;
    std::wstring AzureContainer;

    // AWS S3
    std::wstring AwsAccessKeyId;
    std::wstring AwsSecretAccessKey;
    std::wstring AwsRegion;
    std::wstring S3BucketName;
    std::wstring S3KeyPrefix;

    // Batch
    size_t  BatchMaxSizeBytes   = 64 * 1024 * 1024;  // 64 MB
    int     BatchMaxIntervalSec = 300;
    bool    BatchCompress       = true;

    static std::wstring GetEnvW(const wchar_t* name, const wchar_t* defaultVal = L"")
    {
        wchar_t buf[4096] = {};
        DWORD len = GetEnvironmentVariableW(name, buf, _countof(buf));
        if (len == 0 || len >= _countof(buf))
            return defaultVal;
        return std::wstring(buf, len);
    }

    static std::string GetEnvA(const char* name, const char* defaultVal = "")
    {
        char buf[4096] = {};
        DWORD len = GetEnvironmentVariableA(name, buf, _countof(buf));
        if (len == 0 || len >= _countof(buf))
            return defaultVal;
        return std::string(buf, len);
    }

    static bool GetEnvBool(const wchar_t* name, bool defaultVal)
    {
        std::wstring v = GetEnvW(name);
        if (v == L"false" || v == L"0") return false;
        if (v == L"true"  || v == L"1") return true;
        return defaultVal;
    }

    static size_t GetEnvSizeT(const wchar_t* name, size_t defaultVal)
    {
        std::wstring v = GetEnvW(name);
        if (v.empty()) return defaultVal;
        return (size_t)_wtoi64(v.c_str());
    }

    void LoadFromEnvironment()
    {
        CbEdrServerUrl         = GetEnvW(L"CBEDR_SERVER_URL");
        CbEdrApiToken          = GetEnvW(L"CBEDR_API_TOKEN");
        CbEdrVerifySsl         = GetEnvBool(L"CBEDR_VERIFY_SSL", true);

        AzureConnectionString  = GetEnvW(L"AZURE_STORAGE_CONNECTION_STRING");
        AzureContainer         = GetEnvW(L"AZURE_STORAGE_CONTAINER", L"edr-telemetry");

        AwsAccessKeyId         = GetEnvW(L"AWS_ACCESS_KEY_ID");
        AwsSecretAccessKey     = GetEnvW(L"AWS_SECRET_ACCESS_KEY");
        AwsRegion              = GetEnvW(L"AWS_REGION", L"us-east-1");
        S3BucketName           = GetEnvW(L"S3_BUCKET_NAME");
        S3KeyPrefix            = GetEnvW(L"S3_KEY_PREFIX", L"collector/");

        BatchMaxSizeBytes   = GetEnvSizeT(L"BATCH_MAX_SIZE_MB", 64) * 1024 * 1024;
        BatchMaxIntervalSec = (int)GetEnvSizeT(L"BATCH_MAX_INTERVAL_SEC", 300);
        BatchCompress       = GetEnvBool(L"BATCH_COMPRESS", true);
    }
};

static CollectorConfig g_Config;

// -------------------------------------------------------------------------
// JSON helpers  (minimal, no external deps)
// -------------------------------------------------------------------------
static std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s)
    {
        switch (c)
        {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if ((unsigned char)c < 0x20)
            {
                char esc[8];
                StringCchPrintfA(esc, _countof(esc), "\\u%04x", (unsigned char)c);
                out += esc;
            }
            else
            {
                out += c;
            }
        }
    }
    return out;
}

static std::string WstrToUtf8(const std::wstring& ws)
{
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string s(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, s.data(), len, nullptr, nullptr);
    return s;
}

static std::string IpAddressToString(const EDR_IP_ADDRESS& ip)
{
    char buf[64] = {};
    if (ip.Family == 2)  // IPv4
    {
        StringCchPrintfA(buf, _countof(buf), "%u.%u.%u.%u",
            ip.Addr.v4[0], ip.Addr.v4[1], ip.Addr.v4[2], ip.Addr.v4[3]);
    }
    else if (ip.Family == 23)  // IPv6
    {
        StringCchPrintfA(buf, _countof(buf),
            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            ip.Addr.v6[0],  ip.Addr.v6[1],  ip.Addr.v6[2],  ip.Addr.v6[3],
            ip.Addr.v6[4],  ip.Addr.v6[5],  ip.Addr.v6[6],  ip.Addr.v6[7],
            ip.Addr.v6[8],  ip.Addr.v6[9],  ip.Addr.v6[10], ip.Addr.v6[11],
            ip.Addr.v6[12], ip.Addr.v6[13], ip.Addr.v6[14], ip.Addr.v6[15]);
    }
    return buf;
}

static std::string FiletimeToIso8601(UINT64 ft)
{
    FILETIME ftime;
    ftime.dwLowDateTime  = (DWORD)(ft & 0xFFFFFFFF);
    ftime.dwHighDateTime = (DWORD)(ft >> 32);

    SYSTEMTIME st;
    FileTimeToSystemTime(&ftime, &st);

    char buf[32];
    StringCchPrintfA(buf, _countof(buf), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static std::string CurrentIso8601()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    UINT64 t = ((UINT64)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return FiletimeToIso8601(t);
}

// -------------------------------------------------------------------------
// CB EDR enrichment cache
//
// Polls /api/v1/process with facet=true for the supported facet fields.
// The returned facets are cached and attached to every outbound event record.
// The cache refreshes on CbEdrEnrichIntervalSec.
// -------------------------------------------------------------------------
struct CbFacetCache
{
    std::string Hostname;
    std::string Group;
    std::string OsType;
    std::string HostType;
    std::string ProcessName;
    std::string ParentName;
    std::string PathFull;
    std::string ProcessMd5;
    std::string UsernameFull;
    std::string DigsigResult;
    std::string CompanyName;
    std::string ProductName;
    std::string HourOfDay;
    std::string DayOfWeek;
    std::string LastUpdated;
};

class CbEdrEnricher
{
public:
    explicit CbEdrEnricher(const CollectorConfig& cfg)
        : m_Config(cfg)
    {}

    // Returns the most recently fetched facet JSON blob to attach to events
    std::string GetEnrichmentJson()
    {
        std::lock_guard<std::mutex> lock(m_Mutex);
        return m_CachedJson;
    }

    // Refresh facet data from the CB EDR server (call on a background thread)
    void Refresh()
    {
        if (m_Config.CbEdrServerUrl.empty() || m_Config.CbEdrApiToken.empty())
            return;

        // Build query URL
        // GET /api/v1/process?facet=true&facet.field=...&rows=0
        std::wstring url = m_Config.CbEdrServerUrl;
        url += L"/api/v1/process?facet=true&rows=0";
        url += L"&facet.field=hostname";
        url += L"&facet.field=group";
        url += L"&facet.field=os_type";
        url += L"&facet.field=host_type";
        url += L"&facet.field=process_name";
        url += L"&facet.field=parent_name";
        url += L"&facet.field=path_full";
        url += L"&facet.field=process_md5";
        url += L"&facet.field=username_full";
        url += L"&facet.field=hour_of_day";
        url += L"&facet.field=day_of_week";

        std::string response = HttpGet(url);
        if (response.empty())
            return;

        std::lock_guard<std::mutex> lock(m_Mutex);
        m_CachedJson = response;
        m_LastRefresh = std::chrono::steady_clock::now();
    }

    bool NeedsRefresh() const
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_LastRefresh).count();
        return elapsed >= m_Config.CbEdrEnrichIntervalSec;
    }

private:
    std::string HttpGet(const std::wstring& url)
    {
        std::string result;

        std::wstring authHeader = L"X-Auth-Token: ";
        authHeader += m_Config.CbEdrApiToken;

        HINTERNET hInternet = InternetOpenW(
            L"EdrCollector/1.0",
            INTERNET_OPEN_TYPE_PRECONFIG,
            nullptr, nullptr, 0);

        if (!hInternet) return result;

        DWORD openFlags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
        if (!m_Config.CbEdrVerifySsl)
            openFlags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                         INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;

        HINTERNET hUrl = InternetOpenUrlW(
            hInternet, url.c_str(), authHeader.c_str(),
            (DWORD)authHeader.size(), openFlags, 0);

        if (hUrl)
        {
            char buf[4096];
            DWORD bytesRead;
            while (InternetReadFile(hUrl, buf, sizeof(buf) - 1, &bytesRead) && bytesRead > 0)
            {
                buf[bytesRead] = '\0';
                result += buf;
            }
            InternetCloseHandle(hUrl);
        }

        InternetCloseHandle(hInternet);
        return result;
    }

    const CollectorConfig&  m_Config;
    std::mutex              m_Mutex;
    std::string             m_CachedJson;
    std::chrono::steady_clock::time_point m_LastRefresh{};
};

// -------------------------------------------------------------------------
// Event serializer
// -------------------------------------------------------------------------
static std::string SerializeNetworkEvent(
    const EDR_NETWORK_EVENT& ev,
    const std::string&       enrichmentJson,
    const std::string&       hostname)
{
    std::ostringstream o;
    o << "{"
      << "\"event_type\":\"network\","
      << "\"sub_type\":\"" << (ev.Direction == EDR_DIRECTION_EGRESS ? "egress" : "ingress") << "\","
      << "\"protocol\":\"" << (ev.Protocol == 6 ? "TCP" : "UDP") << "\","
      << "\"timestamp\":\"" << FiletimeToIso8601(ev.Timestamp) << "\","
      << "\"pid\":" << ev.ProcessId << ","
      << "\"local_address\":\"" << IpAddressToString(ev.LocalAddress) << "\","
      << "\"local_port\":" << ev.LocalPort << ","
      << "\"remote_address\":\"" << IpAddressToString(ev.RemoteAddress) << "\","
      << "\"remote_port\":" << ev.RemotePort << ","
      << "\"bytes_transferred\":" << ev.BytesTransferred << ","
      << "\"process_image\":\"" << JsonEscape(WstrToUtf8(ev.ProcessImagePath)) << "\","
      << "\"collector_hostname\":\"" << JsonEscape(hostname) << "\"";

    if (!enrichmentJson.empty())
        o << ",\"cbedr_facets\":" << enrichmentJson;

    o << "}";
    return o.str();
}

static std::string SerializeProcessEvent(
    const EDR_PROCESS_EVENT& ev,
    const std::string&       enrichmentJson,
    const std::string&       hostname)
{
    std::ostringstream o;
    o << "{"
      << "\"event_type\":\"process\","
      << "\"sub_type\":\"" << (ev.EventType == EdrEventTypeProcessCreate ? "create" : "terminate") << "\","
      << "\"timestamp\":\"" << FiletimeToIso8601(ev.Timestamp) << "\","
      << "\"pid\":" << ev.ProcessId << ","
      << "\"ppid\":" << ev.ParentProcessId << ","
      << "\"session_id\":" << ev.SessionId << ","
      << "\"image_path\":\"" << JsonEscape(WstrToUtf8(ev.ImagePath)) << "\","
      << "\"command_line\":\"" << JsonEscape(WstrToUtf8(ev.CommandLine)) << "\","
      << "\"user_sid\":\"" << JsonEscape(WstrToUtf8(ev.UserSid)) << "\","
      << "\"collector_hostname\":\"" << JsonEscape(hostname) << "\"";

    if (!enrichmentJson.empty())
        o << ",\"cbedr_facets\":" << enrichmentJson;

    o << "}";
    return o.str();
}

static std::string SerializeFileEvent(
    const EDR_FILE_EVENT& ev,
    const std::string&    enrichmentJson,
    const std::string&    hostname)
{
    const char* subType = "unknown";
    switch (ev.EventType)
    {
    case EdrEventTypeFileCreate: subType = "create"; break;
    case EdrEventTypeFileWrite:  subType = "write";  break;
    case EdrEventTypeFileDelete: subType = "delete"; break;
    case EdrEventTypeFileRename: subType = "rename"; break;
    default: break;
    }

    std::ostringstream o;
    o << "{"
      << "\"event_type\":\"file\","
      << "\"sub_type\":\"" << subType << "\","
      << "\"timestamp\":\"" << FiletimeToIso8601(ev.Timestamp) << "\","
      << "\"pid\":" << ev.ProcessId << ","
      << "\"file_path\":\"" << JsonEscape(WstrToUtf8(ev.FilePath)) << "\","
      << "\"new_file_path\":\"" << JsonEscape(WstrToUtf8(ev.NewFilePath)) << "\","
      << "\"file_size\":" << ev.FileSize << ","
      << "\"collector_hostname\":\"" << JsonEscape(hostname) << "\"";

    if (!enrichmentJson.empty())
        o << ",\"cbedr_facets\":" << enrichmentJson;

    o << "}";
    return o.str();
}

// -------------------------------------------------------------------------
// Batch buffer  (accumulates newline-delimited JSON, flushes on threshold)
// -------------------------------------------------------------------------
class BatchBuffer
{
public:
    BatchBuffer(size_t maxBytes, int maxIntervalSec)
        : m_MaxBytes(maxBytes)
        , m_MaxIntervalSec(maxIntervalSec)
    {
        ResetTimer();
    }

    // Append one serialized JSON event line
    void Append(const std::string& line)
    {
        std::lock_guard<std::mutex> lock(m_Mutex);
        m_Buffer += line;
        m_Buffer += '\n';
        m_EventCount++;
    }

    size_t SizeBytes() const
    {
        std::lock_guard<std::mutex> lock(m_Mutex);
        return m_Buffer.size();
    }

    bool ShouldFlush() const
    {
        std::lock_guard<std::mutex> lock(m_Mutex);
        if (m_Buffer.empty()) return false;
        if (m_Buffer.size() >= m_MaxBytes) return true;

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_LastFlushTime).count();
        return elapsed >= m_MaxIntervalSec;
    }

    // Take ownership of current buffer and reset
    std::string Drain(size_t& eventCountOut)
    {
        std::lock_guard<std::mutex> lock(m_Mutex);
        std::string out = std::move(m_Buffer);
        m_Buffer.clear();
        eventCountOut = m_EventCount;
        m_EventCount  = 0;
        ResetTimer();
        return out;
    }

private:
    void ResetTimer()
    {
        m_LastFlushTime = std::chrono::steady_clock::now();
    }

    mutable std::mutex          m_Mutex;
    std::string                 m_Buffer;
    size_t                      m_EventCount = 0;
    size_t                      m_MaxBytes;
    int                         m_MaxIntervalSec;
    std::chrono::steady_clock::time_point m_LastFlushTime;
};

// -------------------------------------------------------------------------
// Blob key naming  {prefix}/{hostname}/{date}/{hour}/{timestamp_uuid}.ndjson
// -------------------------------------------------------------------------
static std::string MakeBlobKey(
    const std::wstring& prefix,
    const std::string&  hostname)
{
    SYSTEMTIME st;
    GetSystemTime(&st);

    char uuid[9];
    DWORD r1 = GetTickCount();
    StringCchPrintfA(uuid, _countof(uuid), "%08X", r1);

    std::string pfx = WstrToUtf8(prefix);

    char key[512];
    StringCchPrintfA(key, _countof(key),
        "%s%s/%04u-%02u-%02u/%02u/%04u%02u%02uT%02u%02u%02uZ_%s.ndjson",
        pfx.c_str(),
        hostname.c_str(),
        st.wYear, st.wMonth, st.wDay,
        st.wHour,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        uuid);

    return key;
}

// -------------------------------------------------------------------------
// Uploader interface
// -------------------------------------------------------------------------
class IUploader
{
public:
    virtual ~IUploader() = default;
    virtual bool Upload(
        const std::string& blobKey,
        const std::vector<BYTE>& data,
        const std::string& contentType) = 0;
    virtual const char* Name() const = 0;
};

// -------------------------------------------------------------------------
// Azure Blob Storage uploader  (REST API, no SDK dependency)
//
// Parses the connection string for AccountName and AccountKey, then calls
// PUT https://{account}.blob.core.windows.net/{container}/{key}
// with a SharedKey HMAC-SHA256 authorization header.
//
// NOTE: Full SharedKey auth requires CryptImportKey / CryptSignHash (HMAC-SHA256).
// The skeleton below wires the HTTP call; insert your preferred crypto impl
// or swap in the azure-storage-blobs-cpp SDK vcpkg package.
// -------------------------------------------------------------------------
class AzureBlobUploader : public IUploader
{
public:
    explicit AzureBlobUploader(const CollectorConfig& cfg) : m_Config(cfg) {}

    bool Upload(
        const std::string& blobKey,
        const std::vector<BYTE>& data,
        const std::string& contentType) override
    {
        if (m_Config.AzureConnectionString.empty()) return false;

        // Parse account name and key from connection string
        std::wstring accountName = ParseConnStr(L"AccountName");
        std::wstring container   = m_Config.AzureContainer;

        // Build URL
        std::wstring blobKeyW(blobKey.begin(), blobKey.end());
        std::wstring url = L"https://";
        url += accountName;
        url += L".blob.core.windows.net/";
        url += container;
        url += L"/";
        url += blobKeyW;

        // Build headers
        std::string date = CurrentIso8601();
        std::wstring headers = L"x-ms-blob-type: BlockBlob\r\n";
        headers += L"x-ms-date: ";
        headers += std::wstring(date.begin(), date.end());
        headers += L"\r\n";
        headers += L"x-ms-version: 2020-04-08\r\n";

        return HttpPut(url, headers, data,
                       std::wstring(contentType.begin(), contentType.end()));
    }

    const char* Name() const override { return "AzureBlob"; }

private:
    std::wstring ParseConnStr(const wchar_t* key)
    {
        const std::wstring& cs = m_Config.AzureConnectionString;
        std::wstring search = key;
        search += L"=";
        size_t pos = cs.find(search);
        if (pos == std::wstring::npos) return L"";
        pos += search.size();
        size_t end = cs.find(L";", pos);
        if (end == std::wstring::npos) end = cs.size();
        return cs.substr(pos, end - pos);
    }

    bool HttpPut(
        const std::wstring&      url,
        const std::wstring&      extraHeaders,
        const std::vector<BYTE>& body,
        const std::wstring&      contentType)
    {
        bool success = false;

        // Parse URL into host + path
        URL_COMPONENTSW uc = {};
        wchar_t host[256] = {};
        wchar_t path[1024] = {};
        uc.dwStructSize      = sizeof(uc);
        uc.lpszHostName      = host;
        uc.dwHostNameLength  = _countof(host);
        uc.lpszUrlPath       = path;
        uc.dwUrlPathLength   = _countof(path);

        if (!InternetCrackUrlW(url.c_str(), 0, 0, &uc))
            return false;

        HINTERNET hInternet = InternetOpenW(
            L"EdrCollector/1.0", INTERNET_OPEN_TYPE_PRECONFIG,
            nullptr, nullptr, 0);
        if (!hInternet) return false;

        HINTERNET hConn = InternetConnectW(
            hInternet, host, uc.nPort,
            nullptr, nullptr,
            INTERNET_SERVICE_HTTP, 0, 0);

        if (hConn)
        {
            DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
            if (uc.nScheme == INTERNET_SCHEME_HTTPS)
                flags |= INTERNET_FLAG_SECURE;

            HINTERNET hReq = HttpOpenRequestW(
                hConn, L"PUT", path, nullptr, nullptr,
                nullptr, flags, 0);

            if (hReq)
            {
                std::wstring ct = L"Content-Type: ";
                ct += contentType;
                ct += L"\r\n";
                ct += extraHeaders;

                BOOL sent = HttpSendRequestW(
                    hReq,
                    ct.c_str(), (DWORD)ct.size(),
                    (LPVOID)body.data(), (DWORD)body.size());

                if (sent)
                {
                    DWORD statusCode = 0;
                    DWORD statusSize = sizeof(statusCode);
                    HttpQueryInfoW(hReq,
                        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        &statusCode, &statusSize, nullptr);
                    success = (statusCode >= 200 && statusCode < 300);
                }

                InternetCloseHandle(hReq);
            }
            InternetCloseHandle(hConn);
        }

        InternetCloseHandle(hInternet);
        return success;
    }

    const CollectorConfig& m_Config;
};

// -------------------------------------------------------------------------
// AWS S3 uploader  (pre-signed PUT via REST)
//
// Uses AWS Signature Version 4 for PUT Object.
// For production use the aws-sdk-cpp package (vcpkg) or link against
// the standalone aws-crt-cpp runtime.
// The skeleton below computes the required headers; HMAC-SHA256 signing
// can be done with BCryptDeriveKey / BCryptSignHash (Windows CNG).
// -------------------------------------------------------------------------
class S3Uploader : public IUploader
{
public:
    explicit S3Uploader(const CollectorConfig& cfg) : m_Config(cfg) {}

    bool Upload(
        const std::string& blobKey,
        const std::vector<BYTE>& data,
        const std::string& contentType) override
    {
        if (m_Config.S3BucketName.empty()) return false;

        std::string region = WstrToUtf8(m_Config.AwsRegion);
        std::string bucket = WstrToUtf8(m_Config.S3BucketName);

        // Host: {bucket}.s3.{region}.amazonaws.com
        std::wstring host = m_Config.S3BucketName;
        host += L".s3.";
        host += m_Config.AwsRegion;
        host += L".amazonaws.com";

        std::wstring blobKeyW(blobKey.begin(), blobKey.end());
        std::wstring path = L"/";
        path += blobKeyW;

        std::wstring url = L"https://";
        url += host;
        url += path;

        // Date strings for SigV4
        SYSTEMTIME st;
        GetSystemTime(&st);
        char dateStamp[16], amzDate[24];
        StringCchPrintfA(dateStamp, _countof(dateStamp),
            "%04u%02u%02u", st.wYear, st.wMonth, st.wDay);
        StringCchPrintfA(amzDate, _countof(amzDate),
            "%04u%02u%02uT%02u%02u%02uZ",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);

        // Build x-amz-content-sha256 (SHA256 of body)
        // NOTE: Replace ComputeSha256Hex with your CNG implementation
        std::string payloadHash = ComputeSha256Hex(data);

        std::wstring extraHeaders = L"x-amz-content-sha256: ";
        extraHeaders += std::wstring(payloadHash.begin(), payloadHash.end());
        extraHeaders += L"\r\nx-amz-date: ";
        extraHeaders += std::wstring(amzDate, amzDate + strlen(amzDate));
        extraHeaders += L"\r\n";

        // Authorization: AWS4-HMAC-SHA256 ...
        // In production replace this stub with full SigV4 canonical request signing
        std::wstring authHeader = BuildSigV4Auth(
            blobKey, contentType, payloadHash,
            amzDate, dateStamp,
            region, WstrToUtf8(host));

        extraHeaders += L"Authorization: ";
        extraHeaders += authHeader;
        extraHeaders += L"\r\n";

        return HttpPut(url, host, path, extraHeaders, data,
                       std::wstring(contentType.begin(), contentType.end()));
    }

    const char* Name() const override { return "S3"; }

private:
    // Stub: replace with CNG BCrypt HMAC-SHA256 chain
    std::wstring BuildSigV4Auth(
        const std::string& key,
        const std::string& contentType,
        const std::string& payloadHash,
        const char* amzDate,
        const char* dateStamp,
        const std::string& region,
        const std::string& host)
    {
        // Full SigV4 implementation:
        //  1. Canonical request   = METHOD\nURI\nQueryString\nHeaders\nSignedHeaders\nPayloadHash
        //  2. String to sign      = "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + Hash(canonicalReq)
        //  3. Signing key         = HMAC(HMAC(HMAC(HMAC("AWS4"+secretKey, dateStamp), region), "s3"), "aws4_request")
        //  4. Signature           = HMAC(signingKey, stringToSign)  -> hex
        //
        // Returning placeholder; wire up with BCryptCreateHash / BCryptHashData / BCryptFinishHash
        char buf[256];
        StringCchPrintfA(buf, _countof(buf),
            "AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=<computed>",
            WstrToUtf8(m_Config.AwsAccessKeyId).c_str(),
            dateStamp, region.c_str());
        return std::wstring(buf, buf + strlen(buf));
    }

    std::string ComputeSha256Hex(const std::vector<BYTE>& data)
    {
        // Stub: wire in BCryptHash(BCRYPT_SHA256_ALGORITHM, ...)
        // Returns the hex-encoded SHA-256 of data
        UNREFERENCED_PARAMETER(data);
        return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    }

    bool HttpPut(
        const std::wstring&      url,
        const std::wstring&      host,
        const std::wstring&      path,
        const std::wstring&      extraHeaders,
        const std::vector<BYTE>& body,
        const std::wstring&      contentType)
    {
        bool success = false;

        HINTERNET hInternet = InternetOpenW(
            L"EdrCollector/1.0", INTERNET_OPEN_TYPE_PRECONFIG,
            nullptr, nullptr, 0);
        if (!hInternet) return false;

        HINTERNET hConn = InternetConnectW(
            hInternet, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT,
            nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);

        if (hConn)
        {
            DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE |
                          INTERNET_FLAG_SECURE;
            HINTERNET hReq = HttpOpenRequestW(
                hConn, L"PUT", path.c_str(), nullptr, nullptr,
                nullptr, flags, 0);

            if (hReq)
            {
                std::wstring ct = L"Content-Type: ";
                ct += contentType;
                ct += L"\r\n";
                ct += extraHeaders;

                BOOL sent = HttpSendRequestW(
                    hReq, ct.c_str(), (DWORD)ct.size(),
                    (LPVOID)body.data(), (DWORD)body.size());

                if (sent)
                {
                    DWORD statusCode = 0;
                    DWORD statusSize = sizeof(statusCode);
                    HttpQueryInfoW(hReq,
                        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        &statusCode, &statusSize, nullptr);
                    success = (statusCode >= 200 && statusCode < 300);
                }
                InternetCloseHandle(hReq);
            }
            InternetCloseHandle(hConn);
        }
        InternetCloseHandle(hInternet);
        return success;
    }

    const CollectorConfig& m_Config;
};

// -------------------------------------------------------------------------
// Upload dispatcher  (sends to both targets, retries up to 3 times)
// -------------------------------------------------------------------------
class UploadDispatcher
{
public:
    void AddUploader(std::unique_ptr<IUploader> up)
    {
        m_Uploaders.push_back(std::move(up));
    }

    void Dispatch(
        const std::string& blobKey,
        const std::string& ndjsonPayload)
    {
        std::vector<BYTE> bytes(ndjsonPayload.begin(), ndjsonPayload.end());
        std::string ct = "application/x-ndjson";

        for (auto& up : m_Uploaders)
        {
            bool ok = false;
            for (int attempt = 0; attempt < 3 && !ok; attempt++)
            {
                if (attempt > 0)
                    Sleep(1000 * attempt);   // 1s, 2s back-off

                ok = up->Upload(blobKey, bytes, ct);
            }

            if (!ok)
            {
                // Log failure  (in production write to Windows Event Log)
                OutputDebugStringA("[EDR] Upload failed after 3 attempts: ");
                OutputDebugStringA(up->Name());
                OutputDebugStringA(" key=");
                OutputDebugStringA(blobKey.c_str());
                OutputDebugStringA("\n");
            }
            else
            {
                OutputDebugStringA("[EDR] Uploaded batch: ");
                OutputDebugStringA(up->Name());
                OutputDebugStringA(" key=");
                OutputDebugStringA(blobKey.c_str());
                OutputDebugStringA("\n");
            }
        }
    }

private:
    std::vector<std::unique_ptr<IUploader>> m_Uploaders;
};

// -------------------------------------------------------------------------
// Main collector loop
// -------------------------------------------------------------------------
class Collector
{
public:
    Collector()
        : m_Batch(g_Config.BatchMaxSizeBytes, g_Config.BatchMaxIntervalSec)
        , m_Enricher(g_Config)
        , m_Running(false)
    {
        // Resolve local hostname
        char buf[256] = {};
        GetComputerNameA(buf, nullptr);
        m_Hostname = buf;
    }

    bool Start()
    {
        m_DriverHandle = CreateFileW(
            EDR_DEVICE_WIN32,
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (m_DriverHandle == INVALID_HANDLE_VALUE)
        {
            OutputDebugStringA("[EDR] Cannot open driver device. Is EdrCollectorDriver loaded?\n");
            return false;
        }

        // Set up uploaders
        if (!g_Config.AzureConnectionString.empty())
            m_Dispatcher.AddUploader(std::make_unique<AzureBlobUploader>(g_Config));

        if (!g_Config.S3BucketName.empty())
            m_Dispatcher.AddUploader(std::make_unique<S3Uploader>(g_Config));

        m_Running = true;

        // Background threads
        m_EnricherThread = std::thread([this]() { EnricherLoop(); });
        m_FlushThread    = std::thread([this]() { FlushLoop();    });
        m_ReaderThread   = std::thread([this]() { ReaderLoop();   });

        return true;
    }

    void Stop()
    {
        m_Running = false;

        if (m_ReaderThread.joinable())  m_ReaderThread.join();
        if (m_FlushThread.joinable())   m_FlushThread.join();
        if (m_EnricherThread.joinable()) m_EnricherThread.join();

        if (m_DriverHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(m_DriverHandle);
            m_DriverHandle = INVALID_HANDLE_VALUE;
        }

        // Final flush
        ForceFlush();
    }

private:
    void EnricherLoop()
    {
        while (m_Running)
        {
            if (m_Enricher.NeedsRefresh())
                m_Enricher.Refresh();
            Sleep(5000);
        }
    }

    void FlushLoop()
    {
        while (m_Running)
        {
            Sleep(1000);   // check every second
            if (m_Batch.ShouldFlush())
                ForceFlush();
        }
    }

    void ForceFlush()
    {
        size_t eventCount = 0;
        std::string payload = m_Batch.Drain(eventCount);
        if (payload.empty()) return;

        std::string key = MakeBlobKey(g_Config.S3KeyPrefix, m_Hostname);
        m_Dispatcher.Dispatch(key, payload);

        char msg[128];
        StringCchPrintfA(msg, _countof(msg),
            "[EDR] Flushed batch: %zu events, %zu bytes\n",
            eventCount, payload.size());
        OutputDebugStringA(msg);
    }

    void ReaderLoop()
    {
        std::vector<BYTE> readBuf(1024 * 1024);   // 1 MB read buffer

        while (m_Running)
        {
            DWORD bytesRead = 0;
            BOOL ok = ReadFile(
                m_DriverHandle,
                readBuf.data(),
                (DWORD)readBuf.size(),
                &bytesRead,
                nullptr);

            if (!ok || bytesRead == 0)
            {
                Sleep(50);
                continue;
            }

            std::string enrichJson = m_Enricher.GetEnrichmentJson();

            // Parse ring buffer output as a stream of EDR_EVENT_RECORDs
            DWORD offset = 0;
            while (offset + sizeof(UINT32) <= bytesRead)
            {
                PEDR_EVENT_RECORD rec = (PEDR_EVENT_RECORD)(readBuf.data() + offset);
                if (rec->RecordSize == 0 || offset + rec->RecordSize > bytesRead)
                    break;

                std::string line;
                switch (rec->EventType)
                {
                case EdrEventTypeNetworkConnect:
                case EdrEventTypeNetworkAccept:
                case EdrEventTypeNetworkSend:
                case EdrEventTypeNetworkRecv:
                    line = SerializeNetworkEvent(rec->Event.Network, enrichJson, m_Hostname);
                    break;

                case EdrEventTypeProcessCreate:
                case EdrEventTypeProcessTerminate:
                    line = SerializeProcessEvent(rec->Event.Process, enrichJson, m_Hostname);
                    break;

                case EdrEventTypeFileCreate:
                case EdrEventTypeFileWrite:
                case EdrEventTypeFileDelete:
                case EdrEventTypeFileRename:
                    line = SerializeFileEvent(rec->Event.File, enrichJson, m_Hostname);
                    break;

                default:
                    break;
                }

                if (!line.empty())
                    m_Batch.Append(line);

                offset += rec->RecordSize;
            }

            // Opportunistic flush check
            if (m_Batch.ShouldFlush())
                ForceFlush();
        }
    }

    HANDLE              m_DriverHandle = INVALID_HANDLE_VALUE;
    BatchBuffer         m_Batch;
    CbEdrEnricher       m_Enricher;
    UploadDispatcher    m_Dispatcher;
    std::string         m_Hostname;
    std::atomic<bool>   m_Running;
    std::thread         m_ReaderThread;
    std::thread         m_FlushThread;
    std::thread         m_EnricherThread;
};

// -------------------------------------------------------------------------
// Windows Service boilerplate
// -------------------------------------------------------------------------
static SERVICE_STATUS           g_ServiceStatus     = {};
static SERVICE_STATUS_HANDLE    g_ServiceStatusHandle = nullptr;
static HANDLE                   g_StopEvent         = nullptr;
static Collector*               g_Collector         = nullptr;

static VOID WINAPI ServiceCtrlHandler(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN)
    {
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
        SetEvent(g_StopEvent);
    }
}

static VOID WINAPI ServiceMain(DWORD argc, LPWSTR* argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    g_ServiceStatusHandle = RegisterServiceCtrlHandlerW(
        L"EdrCollectorSvc", ServiceCtrlHandler);

    g_ServiceStatus.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState            = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwWin32ExitCode           = NO_ERROR;
    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);

    g_Config.LoadFromEnvironment();

    g_StopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    g_Collector = new Collector();
    if (!g_Collector->Start())
    {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);

    WaitForSingleObject(g_StopEvent, INFINITE);

    g_Collector->Stop();
    delete g_Collector;
    g_Collector = nullptr;

    CloseHandle(g_StopEvent);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus);
}

int wmain(int argc, wchar_t* argv[])
{
    // Allow running directly from console for development
    if (argc > 1 && wcscmp(argv[1], L"--console") == 0)
    {
        g_Config.LoadFromEnvironment();
        Collector col;
        if (!col.Start())
        {
            wprintf(L"[EDR] Failed to start collector. Is the driver loaded?\n");
            return 1;
        }
        wprintf(L"[EDR] Collector running. Press Enter to stop...\n");
        (void)getchar();
        col.Stop();
        return 0;
    }

    static SERVICE_TABLE_ENTRYW serviceTable[] =
    {
        { (LPWSTR)L"EdrCollectorSvc", ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(serviceTable))
    {
        // Not launched by SCM; print usage
        wprintf(L"Usage: EdrCollectorService.exe [--console]\n");
        wprintf(L"  --console  Run interactively (not as a service)\n");
        return 1;
    }
    return 0;
}
