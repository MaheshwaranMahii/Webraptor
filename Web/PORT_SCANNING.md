# Port Scanning Functionality

## Overview
The Web Raptor project now includes functional port scanning capabilities that can detect open ports and gather service information from target IP addresses.

## Features

### Port Scanning
- Scans common ports: 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433, 8080, 8443, 8888
- Uses TCP socket connections to detect open ports
- Implements batch scanning with delays to avoid overwhelming targets
- Includes safety measures to prevent scanning private/local IPs

### Service Detection
- Attempts to grab banners from open ports
- Identifies service types (HTTP, SSH, FTP, etc.)
- Extracts server information when possible
- Provides fallback data when banner grabbing fails

### Safety Features
- **Private IP Protection**: Automatically skips scanning of private/local IP ranges:
  - 127.x.x.x (loopback)
  - 10.x.x.x (Class A private)
  - 172.16-31.x.x (Class B private)
  - 192.168.x.x (Class C private)
  - 169.254.x.x (link-local)
  - IPv6 private ranges
- **Rate Limiting**: Scans ports in small batches with delays
- **Timeout Protection**: All connections have timeouts to prevent hanging
- **Error Handling**: Graceful fallback when scanning fails

## Configuration

### Environment Variables
- `ENABLE_PORT_SCANNING`: Set to 'false' to disable port scanning (default: enabled)

### Port Scan Settings
- **Timeout**: 3 seconds per port scan
- **Banner Timeout**: 2 seconds for banner grabbing
- **Batch Size**: 3 ports per batch
- **Batch Delay**: 200ms between batches

## Usage

The port scanning is automatically triggered when:
1. A valid IP address is provided as the target
2. Port scanning is enabled (not disabled via environment variable)
3. The IP is not in a private range

### Example API Call
```bash
curl -X POST http://localhost:3000/api/reconnaissance \
  -H "Content-Type: application/json" \
  -d '{"target": "8.8.8.8"}'
```

### Response Format
```json
{
  "shodan": {
    "ip_str": "8.8.8.8",
    "ports": [53],
    "data": [
      {
        "port": 53,
        "protocol": "tcp",
        "service": "dns",
        "product": "Unknown",
        "version": "",
        "timestamp": "2024-01-01T00:00:00.000Z",
        "banner": "No banner received"
      }
    ]
  }
}
```

## Implementation Details

### Core Functions
- `performPortScan(ip)`: Main port scanning function
- `scanPort(ip, port)`: Individual port scan
- `grabBanner(ip, port)`: Banner grabbing for open ports
- `isPrivateIP(ip)`: Safety check for private IPs

### Error Handling
- All scanning operations are wrapped in try-catch blocks
- Failed scans fall back to basic HTTP/HTTPS detection
- Private IPs are automatically skipped
- Network errors are logged but don't break the analysis

## Security Considerations

1. **Ethical Use**: Only scan targets you own or have permission to scan
2. **Rate Limiting**: Built-in delays prevent aggressive scanning
3. **Private IP Protection**: Automatic blocking of private network ranges
4. **Timeout Protection**: All operations have reasonable timeouts
5. **Error Handling**: Graceful degradation when scanning fails

## Troubleshooting

### Common Issues
1. **No ports found**: Target might be behind a firewall or have no open ports
2. **Scan timeout**: Network connectivity issues or target is unreachable
3. **Private IP blocked**: System correctly prevents scanning of private networks

### Debugging
- Check server logs for port scan results
- Verify target IP is public and reachable
- Ensure port scanning is enabled in environment variables

## Future Enhancements

Potential improvements could include:
- UDP port scanning
- More comprehensive service detection
- SSL/TLS certificate information
- Custom port ranges
- Scan result caching
- Integration with external port scanning services
