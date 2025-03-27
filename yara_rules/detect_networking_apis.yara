rule detect_networking_apis
{
    meta:
        description = "Detects networking API usage in PE files"
        author = "Nimish Srivastav"
        last_modified = "2025-12-27"

    strings:
        $ws2_32_socket = "socket" ascii
        $ws2_32_connect = "connect" ascii
        $ws2_32_send = "send" ascii
        $ws2_32_recv = "recv" ascii
        $ws2_32_closesocket = "closesocket" ascii
        $ws2_32_gethostbyname = "gethostbyname" ascii
        $ws2_32_inet_addr = "inet_addr" ascii
        $ws2_32_ntohs = "ntohs" ascii
        $wininet_internetopen = "InternetOpen" ascii
        $wininet_internetconnect = "InternetConnect" ascii
        $wininet_httpopenrequest = "HttpOpenRequest" ascii
        $wininet_httpsendrequest = "HttpSendRequest" ascii

    condition:
        // Detect PE files importing networking functions
        pe and (
            $ws2_32_socket or
            $ws2_32_connect or
            $ws2_32_send or
            $ws2_32_recv or
            $ws2_32_closesocket or
            $ws2_32_gethostbyname or
            $ws2_32_inet_addr or
            $ws2_32_ntohs or
            $wininet_internetopen or
            $wininet_internetconnect or
            $wininet_httpopenrequest or
            $wininet_httpsendrequest
        )
}
