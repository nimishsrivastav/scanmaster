rule detect_shellcode
{
    meta:
        description = "Detects shellcode in PE files"
        author = "Nimish Srivastav"
        last_modified = "2025-12-27"

    strings:
        $shellcode_pattern1 = { 31 C0 50 40 50 40 50 40 50 40 50 40 50 40 50 40 } // Common shellcode pattern
        $shellcode_pattern2 = { 89 E1 31 C0 50 68 } // Common x86 shellcode pattern

    condition:
        // Detect files containing common shellcode patterns
        pe and (
            $shellcode_pattern1 or
            $shellcode_pattern2
        )
}
