package types

// WinRM protocol constants.
// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wsmv/

// ContentType is the MIME type for WS-Management SOAP messages.
const ContentType = "application/soap+xml;charset=UTF-8"

// WSManPath is the HTTP path for WS-Management requests.
const WSManPath = "/wsman"

// DefaultHTTPPort is the default WinRM HTTP port.
const DefaultHTTPPort = 5985

// DefaultHTTPSPort is the default WinRM HTTPS port.
const DefaultHTTPSPort = 5986
