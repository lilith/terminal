// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// UserSessionMatchProbe
//
// Cross-user CI helper for GH#15689. Reports whether the running process's
// token user SID matches the user logged into the current WTS session, then
// exits with one of:
//   0 == match     (token user equals session user)
//   1 == different (token user differs from session user - the GH#15689 case)
//   2 == unknown   (Session 0 / no interactive user / lookup failed)
//
// CI launches this twice on a Windows runner: once normally (expect 0), and
// once via psexec / CreateProcessAsUser as a freshly provisioned local user
// (expect 1). That asserts the runtime SID-comparison primitive works on real
// Windows; the production CanUwpDragDrop() in src/types/utils.cpp uses the
// exact same primitive in _classifySession().
//
// This tool deliberately has no dependency on the Terminal libs - it speaks
// raw Win32 so the build is trivial and the failure modes are easy to read.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wtsapi32.h>
#include <sddl.h>
#include <stdio.h>
#include <string>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "advapi32.lib")

namespace
{
    enum class Result
    {
        Match = 0,
        Different = 1,
        Unknown = 2,
    };

    void PrintSid(const wchar_t* label, PSID sid)
    {
        LPWSTR str = nullptr;
        if (sid && ConvertSidToStringSidW(sid, &str))
        {
            wprintf(L"%s: %s\n", label, str);
            LocalFree(str);
        }
        else
        {
            wprintf(L"%s: <unavailable>\n", label);
        }
    }

    Result Classify()
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            wprintf(L"OpenProcessToken failed: %lu\n", GetLastError());
            return Result::Unknown;
        }

        DWORD tokenUserLen = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &tokenUserLen);
        std::string tokenUserBuf(tokenUserLen, '\0');
        if (!GetTokenInformation(token, TokenUser, tokenUserBuf.data(), tokenUserLen, &tokenUserLen))
        {
            wprintf(L"GetTokenInformation(TokenUser) failed: %lu\n", GetLastError());
            CloseHandle(token);
            return Result::Unknown;
        }
        CloseHandle(token);

        const auto* tokenUserPtr = reinterpret_cast<TOKEN_USER*>(tokenUserBuf.data());
        PSID tokenSid = tokenUserPtr->User.Sid;
        PrintSid(L"process token user SID", tokenSid);

        DWORD sessionId = 0;
        if (!ProcessIdToSessionId(GetCurrentProcessId(), &sessionId))
        {
            wprintf(L"ProcessIdToSessionId failed: %lu\n", GetLastError());
            return Result::Unknown;
        }
        wprintf(L"WTS session id: %lu\n", sessionId);

        LPWSTR userName = nullptr;
        DWORD userLen = 0;
        if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &userName, &userLen))
        {
            wprintf(L"WTSQuerySessionInformation(WTSUserName) failed: %lu\n", GetLastError());
            return Result::Unknown;
        }
        if (userLen <= sizeof(wchar_t) || !userName || userName[0] == L'\0')
        {
            wprintf(L"WTS session has no logged-on user (Session 0 / locked / etc.)\n");
            WTSFreeMemory(userName);
            return Result::Unknown;
        }

        LPWSTR domainName = nullptr;
        DWORD domainLen = 0;
        const auto haveDomain = WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSDomainName, &domainName, &domainLen);

        std::wstring fullName;
        if (haveDomain && domainName && domainLen > sizeof(wchar_t) && domainName[0] != L'\0')
        {
            fullName.append(domainName);
            fullName.push_back(L'\\');
        }
        fullName.append(userName);
        wprintf(L"WTS session user: %s\n", fullName.c_str());

        BYTE sidBuf[SECURITY_MAX_SID_SIZE]{};
        DWORD sidBufLen = sizeof(sidBuf);
        wchar_t referencedDomain[256]{};
        DWORD referencedDomainLen = ARRAYSIZE(referencedDomain);
        SID_NAME_USE use{};
        const auto lookupOk = LookupAccountNameW(nullptr, fullName.c_str(), sidBuf, &sidBufLen, referencedDomain, &referencedDomainLen, &use);

        WTSFreeMemory(userName);
        if (haveDomain && domainName)
        {
            WTSFreeMemory(domainName);
        }

        if (!lookupOk)
        {
            wprintf(L"LookupAccountName failed: %lu\n", GetLastError());
            return Result::Unknown;
        }
        PrintSid(L"WTS session user SID", sidBuf);

        return EqualSid(tokenSid, sidBuf) ? Result::Match : Result::Different;
    }
}

int wmain()
{
    const auto result = Classify();
    switch (result)
    {
    case Result::Match:
        wprintf(L"RESULT: same\n");
        return 0;
    case Result::Different:
        wprintf(L"RESULT: different\n");
        return 1;
    case Result::Unknown:
    default:
        wprintf(L"RESULT: unknown\n");
        return 2;
    }
}
