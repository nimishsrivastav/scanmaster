rule detect_packer
{
    meta:
        description = "Detects UPX packed files"
        author = "Nimish Srivastav"
        last_modified = "2025-12-27"

    strings:
        $upx_string = "UPX" ascii
        $upx_header = { 55 50 58 00 01 00 00 00 } // UPX packed file signature

    condition:
        // Detect UPX packed files
        pe and (
            $upx_string or
            $upx_header
        )
}
