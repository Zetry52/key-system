#include <Windows.h>
#include <winhttp.h>

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#pragma comment(lib, "winhttp.lib")

namespace {
constexpr wchar_t kServerHost[] = L"127.0.0.1";
constexpr int kServerPort = 8080;
constexpr wchar_t kValidatePath[] = L"/api/validate";
constexpr char kProductName[] = "loader";

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size, nullptr, nullptr);
    return result;
}

std::string EscapeJson(const std::string& value) {
    std::ostringstream out;
    for (unsigned char c : value) {
        switch (c) {
        case '\"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
            } else {
                out << static_cast<char>(c);
            }
            break;
        }
    }
    return out.str();
}

std::string GetMachineHwid() {
    DWORD serial = 0;
    if (!GetVolumeInformationW(L"C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        return "unknown-hwid";
    }

    std::ostringstream out;
    out << std::hex << std::uppercase << serial;
    return out.str();
}

std::string ExtractJsonString(const std::string& json, const std::string& key) {
    const std::string needle = "\"" + key + "\":";
    const size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return {};
    }

    size_t start = json.find('\"', pos + needle.size());
    if (start == std::string::npos) {
        return {};
    }
    ++start;

    std::string result;
    bool escaped = false;
    for (size_t i = start; i < json.size(); ++i) {
        const char ch = json[i];
        if (escaped) {
            result.push_back(ch);
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '\"') {
            return result;
        }
        result.push_back(ch);
    }
    return {};
}

bool ExtractJsonBool(const std::string& json, const std::string& key, bool defaultValue) {
    const std::string needle = "\"" + key + "\":";
    const size_t pos = json.find(needle);
    if (pos == std::string::npos) {
        return defaultValue;
    }

    const size_t valuePos = json.find_first_not_of(" \t\r\n", pos + needle.size());
    if (valuePos == std::string::npos) {
        return defaultValue;
    }

    if (json.compare(valuePos, 4, "true") == 0) {
        return true;
    }
    if (json.compare(valuePos, 5, "false") == 0) {
        return false;
    }
    return defaultValue;
}

std::string HttpPostJson(const std::string& body) {
    HINTERNET session = WinHttpOpen(L"KeySystemClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!session) {
        return {};
    }

    HINTERNET connect = WinHttpConnect(session, kServerHost, kServerPort, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return {};
    }

    HINTERNET request = WinHttpOpenRequest(connect,
        L"POST",
        kValidatePath,
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return {};
    }

    const wchar_t* headers = L"Content-Type: application/json\r\n";
    BOOL sent = WinHttpSendRequest(request,
        headers,
        -1L,
        (LPVOID)body.data(),
        static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()),
        0);
    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return {};
    }

    std::string response;
    DWORD available = 0;
    do {
        available = 0;
        if (!WinHttpQueryDataAvailable(request, &available) || available == 0) {
            break;
        }

        std::string chunk(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request, chunk.data(), available, &read)) {
            response.clear();
            break;
        }
        chunk.resize(read);
        response += chunk;
    } while (available > 0);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return response;
}
}

int main() {
    std::cout << "Enter license key: ";
    std::string licenseKey;
    std::getline(std::cin, licenseKey);

    if (licenseKey.empty()) {
        std::cout << "License key is required\n";
        return 1;
    }

    const std::string hwid = GetMachineHwid();
    const std::string payload =
        "{"
        "\"license_key\":\"" + EscapeJson(licenseKey) + "\","
        "\"hwid\":\"" + EscapeJson(hwid) + "\","
        "\"product\":\"" + EscapeJson(kProductName) + "\""
        "}";

    const std::string response = HttpPostJson(payload);
    if (response.empty()) {
        std::cout << "Server request failed\n";
        return 1;
    }

    const bool success = ExtractJsonBool(response, "success", false);
    const std::string message = ExtractJsonString(response, "message");
    if (!success) {
        std::cout << "License rejected: " << message << "\n";
        return 1;
    }

    const std::string name = ExtractJsonString(response, "name");
    const std::string expiresAt = ExtractJsonString(response, "expires_at");
    const std::string boundHwid = ExtractJsonString(response, "bound_hwid");

    std::cout << "License accepted\n";
    std::cout << "Name: " << name << "\n";
    std::cout << "Expires: " << expiresAt << "\n";
    std::cout << "HWID: " << boundHwid << "\n";
    return 0;
}
