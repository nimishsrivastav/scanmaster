rule detect_keylogger_api
{
    meta:
        description = "Detects keylogger API usage"
        author = "Nimish Srivastav"
        last_modified = "2025-12-27"

    strings:
        $getasynckeystate = "GetAsyncKeyState" ascii
        $getforegroundwindow = "GetForegroundWindow" ascii
        $setwindowshookex = "SetWindowsHookEx" ascii

    condition:
        // Detect PE files importing keylogger-related APIs
        pe and (
            $getasynckeystate or
            $getforegroundwindow or
            $setwindowshookex
        )
}
