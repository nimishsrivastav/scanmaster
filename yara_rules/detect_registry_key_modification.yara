rule detect_registry_key_modification
{
    meta:
        description = "Detects registry key modification for persistence"
        author = "Nimish Srivastav"
        last_modified = "2025-12-27"

    strings:
        $registry_run_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
        $registry_runonce_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii
        $registry_persistence_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii

    condition:
        // Detect files that reference registry keys often used for persistence
        pe and (
            $registry_run_key or
            $registry_runonce_key or
            $registry_persistence_key
        )
}
