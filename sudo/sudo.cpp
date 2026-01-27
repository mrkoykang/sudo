#include <iostream>
#include <fstream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <locale>
#include <codecvt>
#include <vector>
#include <algorithm>
#include <winsvc.h>
#include "json.hpp" // nlohmann/json single-header

using json = nlohmann::json;
using namespace std;

// Global debug flag
bool g_debug = false;

inline std::string ws2s(const std::wstring& ws) {
    return std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().to_bytes(ws);
}

// Debug print helper
#define DEBUG_OUT(msg) do { if (g_debug) { std::cout << "[DEBUG] " << msg << std::endl; } } while(0)

// Error logging macro for exceptions and errors
#define ERROR_OUT(msg) do { \
    std::cerr << "[ERROR] " << msg << std::endl; \
    if (g_debug) { std::cerr << "[DEBUG-ERROR] at " << __FILE__ << ":" << __LINE__ << std::endl; } \
} while(0)

// Check if the current process is running as administrator
bool IsRunAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    DEBUG_OUT("IsRunAsAdmin: " << (isAdmin ? "true" : "false"));
    return isAdmin;
}

// Find the PID of a process by name
DWORD FindProcessId(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    DEBUG_OUT("FindProcessId: " << ws2s(processName) << " -> " << pid);
    return pid;
}

// Start TrustedInstaller service if not running
bool StartTrustedInstallerService() {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return false;
    SC_HANDLE hService = OpenServiceW(hSCM, L"TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }

    SERVICE_STATUS_PROCESS ssp = {};
    DWORD bytesNeeded = 0;
    bool started = false;

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            DEBUG_OUT("TrustedInstaller service is stopped, starting...");
            if (StartServiceW(hService, 0, NULL)) {
                // Wait for the service to start
                for (int i = 0; i < 50; ++i) {
                    Sleep(100);
                    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
                        if (ssp.dwCurrentState == SERVICE_RUNNING) {
                            started = true;
                            break;
                        }
                    }
                }
            }
        } else if (ssp.dwCurrentState == SERVICE_RUNNING) {
            started = true;
        }
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    DEBUG_OUT("StartTrustedInstallerService: started=" << started);
    return started;
}

// Launch process with the token of the specified process
bool LaunchAsProcessToken(DWORD pid, const wstring& appPath, const wstring& args) {
    DEBUG_OUT("LaunchAsProcessToken: pid=" << pid << ", appPath=" << ws2s(appPath) << ", args=" << ws2s(args));
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        wcerr << L"OpenProcess failed." << endl;
        return false;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        wcerr << L"OpenProcessToken failed." << endl;
        CloseHandle(hProc);
        return false;
    }
    CloseHandle(hProc);

    HANDLE hDupToken = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        wcerr << L"DuplicateTokenEx failed." << endl;
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    wstring cmdLine = L"\"" + appPath + L"\"";
    if (!args.empty()) {
        cmdLine += L" ";
        cmdLine += args;
    }
    std::vector<wchar_t> cmdLineVec(cmdLine.begin(), cmdLine.end());
    cmdLineVec.push_back(0);

    DEBUG_OUT("CreateProcessWithTokenW: " << ws2s(appPath) << " " << ws2s(cmdLine));
    BOOL result = CreateProcessWithTokenW(
        hDupToken, 0, appPath.c_str(), cmdLineVec.data(),
        CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

    CloseHandle(hDupToken);
    if (result) {
        DEBUG_OUT("Process created: PID=" << pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    } else {
        wcerr << L"CreateProcessWithTokenW failed." << endl;
        return false;
    }
}

enum class RunMode {
    Admin,
    System,
    TrustedInstaller
};

enum class LaunchMode {
    Inline,
    CreateNewWindow,
    InputDisabled
};

struct SudoConfig {
    RunMode defaultPrivilege = RunMode::Admin;
    LaunchMode defaultMode = LaunchMode::Inline;
};

wstring GetConfigPath() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wstring path(exePath);
    size_t pos = path.find_last_of(L"\\/");
    if (pos != wstring::npos) path = path.substr(0, pos + 1);
    path += L"sudo_config.json";
    return path;
}

void SaveConfig(const SudoConfig& config);

SudoConfig LoadConfig() {
    SudoConfig config;
    // Set your requested defaults
    config.defaultPrivilege = RunMode::System;
    config.defaultMode = LaunchMode::CreateNewWindow;

    wstring configPath = GetConfigPath();
    bool needSave = false;
    json j;

    try {
        ifstream in(wstring_convert<codecvt_utf8_utf16<wchar_t>>().to_bytes(configPath));
        if (in) {
            try {
                in >> j;
            } catch (const json::parse_error& e) {
                ERROR_OUT("Failed to parse config file: " << e.what());
                needSave = true;
            }
            if (j.contains("default_privilege")) {
                try {
                    string priv = j["default_privilege"];
                    if (priv == "admin") config.defaultPrivilege = RunMode::Admin;
                    else if (priv == "system") config.defaultPrivilege = RunMode::System;
                    else if (priv == "ti") config.defaultPrivilege = RunMode::TrustedInstaller;
                    else {
                        ERROR_OUT("Invalid privilege value in config: " << priv);
                        needSave = true;
                    }
                } catch (const json::type_error& e) {
                    ERROR_OUT("Invalid privilege format in config: " << e.what());
                    needSave = true;
                }
            } else {
                DEBUG_OUT("No default_privilege found in config");
                needSave = true;
            }
            if (j.contains("default_mode")) {
                try {
                    string mode = j["default_mode"];
                    if (mode == "inline") config.defaultMode = LaunchMode::Inline;
                    else if (mode == "create_new_window") config.defaultMode = LaunchMode::CreateNewWindow;
                    else if (mode == "input_disabled") config.defaultMode = LaunchMode::InputDisabled;
                    else {
                        ERROR_OUT("Invalid mode value in config: " << mode);
                        needSave = true;
                    }
                } catch (const json::type_error& e) {
                    ERROR_OUT("Invalid mode format in config: " << e.what());
                    needSave = true;
                }
            } else {
                DEBUG_OUT("No default_mode found in config");
                needSave = true;
            }
        } else {
            DEBUG_OUT("Config file not found at: " << ws2s(configPath));
            needSave = true;
        }
    } catch (const std::exception& e) {
        ERROR_OUT("Failed to load config: " << e.what());
        needSave = true;
    }

    if (needSave) {
        try {
            SaveConfig(config);
            DEBUG_OUT("Config file created/reset to defaults");
        } catch (const std::exception& e) {
            ERROR_OUT("Failed to save config: " << e.what());
        }
    }
    
    DEBUG_OUT("Config loaded: defaultPrivilege=" << 
        (config.defaultPrivilege == RunMode::Admin ? "admin" : 
         config.defaultPrivilege == RunMode::System ? "system" : "ti") <<
        ", defaultMode=" << 
        (config.defaultMode == LaunchMode::Inline ? "inline" : 
         config.defaultMode == LaunchMode::CreateNewWindow ? "create_new_window" : "input_disabled"));
    return config;
}

void SaveConfig(const SudoConfig& config) {
    try {
        json j;
        switch (config.defaultPrivilege) {
        case RunMode::Admin: j["default_privilege"] = "admin"; break;
        case RunMode::System: j["default_privilege"] = "system"; break;
        case RunMode::TrustedInstaller: j["default_privilege"] = "ti"; break;
        }
        switch (config.defaultMode) {
        case LaunchMode::Inline: j["default_mode"] = "inline"; break;
        case LaunchMode::CreateNewWindow: j["default_mode"] = "create_new_window"; break;
        case LaunchMode::InputDisabled: j["default_mode"] = "input_disabled"; break;
        }
        wstring configPath = GetConfigPath();
        ofstream out(wstring_convert<codecvt_utf8_utf16<wchar_t>>().to_bytes(configPath));
        if (!out) {
            ERROR_OUT("Failed to open config file for writing: " << ws2s(configPath));
            return;
        }
        out << j.dump(4);
        if (out.fail()) {
            ERROR_OUT("Failed to write config data");
            return;
        }
        DEBUG_OUT("Config saved to: " << ws2s(configPath));
    } catch (const std::exception& e) {
        ERROR_OUT("Exception while saving config: " << e.what());
    }
}

void PrintHelp(const std::string& key = "general") {
    try {
        std::ifstream helpFile("help.json");
        if (!helpFile) {
            ERROR_OUT("Could not open help file");
            return;
        }
        
        json helpData;
        try {
            helpFile >> helpData;
        } catch (const json::parse_error& e) {
            ERROR_OUT("Failed to parse help file: " << e.what());
            return;
        }

        if (helpData.contains(key)) {
            try {
                std::cout << helpData[key].get<std::string>();
            } catch (const json::type_error& e) {
                ERROR_OUT("Invalid help data format for key '" << key << "': " << e.what());
            }
        } else {
            std::cout << "No help available for this command.\n";
        }
    } catch (const std::exception& e) {
        ERROR_OUT("Failed to process help request: " << e.what());
    }
}

int wmain(int argc, wchar_t* argv[]) {
    // Check for -d (debug) flag
    int argOffset = 1;
    if (argc >= 2 && (_wcsicmp(argv[1], L"-d") == 0)) {
        g_debug = true;
        DEBUG_OUT("Debug mode enabled.");
        argOffset = 2;
    }

    // Help command handling (support -d before help)
    if (argc >= argOffset + 1) {
        if (_wcsicmp(argv[argOffset], L"-h") == 0 || _wcsicmp(argv[argOffset], L"-?") == 0 || _wcsicmp(argv[argOffset], L"/?") == 0) {
            PrintHelp("general");
            return 0;
        }
        if (_wcsicmp(argv[argOffset], L"-c") == 0) {
            // sudo -d -c -h or sudo -d -c <rule> -h
            if (argc == argOffset + 2 && (_wcsicmp(argv[argOffset + 1], L"-h") == 0 || _wcsicmp(argv[argOffset + 1], L"-?") == 0 || _wcsicmp(argv[argOffset + 1], L"/?") == 0)) {
                PrintHelp("c");
                return 0;
            }
            if (argc == argOffset + 3 && (_wcsicmp(argv[argOffset + 2], L"-h") == 0 || _wcsicmp(argv[argOffset + 2], L"-?") == 0 || _wcsicmp(argv[argOffset + 2], L"/?") == 0)) {
                std::string rule = wstring_convert<codecvt_utf8_utf16<wchar_t>>().to_bytes(argv[argOffset + 1]);
                PrintHelp(rule);
                return 0;
            }
        }
    }

    // Config command handling (support -d before -c)
    if (argc >= argOffset + 1 && (_wcsicmp(argv[argOffset], L"-c") == 0)) {
        if (argc < argOffset + 3) {
            wcerr << L"Usage: sudo -c <rule> <value>" << endl;
            return 1;
        }
        SudoConfig config = LoadConfig();
        string rule = wstring_convert<codecvt_utf8_utf16<wchar_t>>().to_bytes(argv[argOffset + 1]);
        string value = wstring_convert<codecvt_utf8_utf16<wchar_t>>().to_bytes(argv[argOffset + 2]);
        bool ok = false;
        if (rule == "default_privilege") {
            if (value == "admin") { config.defaultPrivilege = RunMode::Admin; ok = true; }
            else if (value == "system") { config.defaultPrivilege = RunMode::System; ok = true; }
            else if (value == "ti") { config.defaultPrivilege = RunMode::TrustedInstaller; ok = true; }
        } else if (rule == "default_mode") {
            if (value == "inline") { config.defaultMode = LaunchMode::Inline; ok = true; }
            else if (value == "create_new_window") { config.defaultMode = LaunchMode::CreateNewWindow; ok = true; }
            else if (value == "input_disabled") { config.defaultMode = LaunchMode::InputDisabled; ok = true; }
        }
        if (!ok) {
            wcerr << L"Invalid rule or value." << endl;
            return 1;
        }
        SaveConfig(config);
        wcout << L"Config updated." << endl;
        return 0;
    }

    // Load config for defaults
    SudoConfig config = LoadConfig();

    // Parse mode
    RunMode mode = config.defaultPrivilege;
    int cmdStart = argOffset;
    if (argc >= argOffset + 2) {
        if (_wcsicmp(argv[argOffset], L"-a") == 0 || _wcsicmp(argv[argOffset], L"--admin") == 0) {
            mode = RunMode::Admin; cmdStart = argOffset + 1;
        } else if (_wcsicmp(argv[argOffset], L"-s") == 0 || _wcsicmp(argv[argOffset], L"--system") == 0) {
            mode = RunMode::System; cmdStart = argOffset + 1;
        } else if (_wcsicmp(argv[argOffset], L"-t") == 0 || _wcsicmp(argv[argOffset], L"--ti") == 0) {
            mode = RunMode::TrustedInstaller; cmdStart = argOffset + 1;
        }
    }

    if (argc <= cmdStart) {
        wcerr << L"Usage: sudo [-a|--admin|-s|--system|-t|--ti] <application> [arguments...]" << endl;
        return 1;
    }

    // Add path resolution for the application
    wchar_t fullPath[MAX_PATH];
    wstring appPath = argv[cmdStart];
    DWORD pathResult = SearchPathW(NULL, appPath.c_str(), L".exe", MAX_PATH, fullPath, NULL);
    if (pathResult > 0) {
        appPath = fullPath;
    }

    // Improve argument handling
    wstring args;
    for (int i = cmdStart + 1; i < argc; ++i) {
        if (!args.empty()) {
            args += L" ";
        }
        // Check if argument contains spaces
        if (wcschr(argv[i], L' ') != nullptr) {
            args += L"\"";
            args += argv[i];
            args += L"\"";
        } else {
            args += argv[i];
        }
    }

    LaunchMode launchMode = config.defaultMode;

    DEBUG_OUT("Mode: " << (mode == RunMode::Admin ? "admin" : (mode == RunMode::System ? "system" : "ti")));
    DEBUG_OUT("App: " << ws2s(appPath));
    DEBUG_OUT("Args: " << ws2s(args));
    DEBUG_OUT("LaunchMode: " << (launchMode == LaunchMode::Inline ? "inline" : (launchMode == LaunchMode::CreateNewWindow ? "create_new_window" : "input_disabled")));

    // Admin mode: relaunch as admin and run application directly
    if (mode == RunMode::Admin) {
        if (!IsRunAsAdmin()) {
            wchar_t exePath[MAX_PATH];
            GetModuleFileNameW(NULL, exePath, MAX_PATH);
            wstring params;
            for (int i = argOffset; i < argc; ++i) {
                params += L"\"";
                params += argv[i];
                params += L"\" ";
            }
            DEBUG_OUT("Relaunching self as admin: " << ws2s(exePath) << " " << ws2s(params));
            ShellExecuteW(NULL, L"runas", exePath, params.c_str(), NULL, SW_SHOW);
            return 0;
        }
        int result = (int)ShellExecuteW(NULL, L"runas", appPath.c_str(), args.empty() ? NULL : args.c_str(), NULL,
            launchMode == LaunchMode::CreateNewWindow ? SW_SHOWNORMAL : SW_SHOWDEFAULT);
        DEBUG_OUT("ShellExecuteW result: " << result);
        if (result <= 32) {
            wcerr << L"Application execution failed" << endl;
            return 1;
        }
        return 0;
    }

    // SYSTEM mode
    if (mode == RunMode::System) {
        if (!IsRunAsAdmin()) {
            wchar_t exePath[MAX_PATH];
            GetModuleFileNameW(NULL, exePath, MAX_PATH);
            wstring params;
            for (int i = argOffset; i < argc; ++i) {
                params += L"\"";
                params += argv[i];
                params += L"\" ";
            }
            DEBUG_OUT("Relaunching self as admin: " << ws2s(exePath) << " " << ws2s(params));
            ShellExecuteW(NULL, L"runas", exePath, params.c_str(), NULL, SW_SHOW);
            return 0;
        }
        DWORD sysPid = FindProcessId(L"winlogon.exe");
        if (sysPid == 0) {
            wcerr << L"Cannot find winlogon.exe process." << endl;
            return 1;
        }
        if (!LaunchAsProcessToken(sysPid, appPath, args)) {
            wcerr << L"Failed to launch as SYSTEM." << endl;
            return 1;
        }
        return 0;
    }

    // TrustedInstaller mode
    if (mode == RunMode::TrustedInstaller) {
        if (!IsRunAsAdmin()) {
            wchar_t exePath[MAX_PATH];
            GetModuleFileNameW(NULL, exePath, MAX_PATH);
            wstring params;
            for (int i = argOffset; i < argc; ++i) {
                params += L"\"";
                params += argv[i];
                params += L"\" ";
            }
            DEBUG_OUT("Relaunching self as admin: " << ws2s(exePath) << " " << ws2s(params));
            ShellExecuteW(NULL, L"runas", exePath, params.c_str(), NULL, SW_SHOW);
            return 0;
        }
        if (!StartTrustedInstallerService()) {
            wcerr << L"Failed to start TrustedInstaller service." << endl;
            return 1;
        }
        DWORD tiPid = FindProcessId(L"TrustedInstaller.exe");
        if (tiPid == 0) {
            wcerr << L"Cannot find TrustedInstaller.exe process." << endl;
            return 1;
        }
        if (!LaunchAsProcessToken(tiPid, appPath, args)) {
            wcerr << L"Failed to launch as TrustedInstaller." << endl;
            return 1;
        }
        return 0;
    }

    wcerr << L"Unknown mode." << endl;
    return 1;
}