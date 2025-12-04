import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Server, MapPin, Globe, Shield, AlertTriangle, Wifi, Lock, Eye, CheckCircle, XCircle, Info } from "lucide-react"

interface ShodanDataProps {
  data?: any
  errors?: Record<string, string>
}

export function ShodanData({ data, errors }: ShodanDataProps) {
  // Handle errors
  if (errors?.pentestTools) {
    return (
      <Card className="bg-slate-800/50 border-slate-700 animate-fade-in">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-slate-100">
            <Server className="h-5 w-5 text-cyan-400" />
            Pentest-Tools Network Intelligence
          </CardTitle>
          <CardDescription className="text-slate-400">Network exposure and service analysis</CardDescription>
        </CardHeader>
        <CardContent>
          <Alert variant="destructive" className="bg-red-900/30 border-red-500">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription className="text-red-200">Pentest-Tools lookup failed: {errors.pentestTools}</AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    )
  }

  if (!data) {
    return (
      <Card className="bg-slate-800/50 border-slate-700 animate-fade-in">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-slate-100">
            <Server className="h-5 w-5 text-cyan-400" />
            Pentest-Tools Network Intelligence
          </CardTitle>
          <CardDescription className="text-slate-400">Network exposure and service analysis</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-slate-400">No Pentest-Tools data available for this target.</p>
        </CardContent>
      </Card>
    )
  }

  const hasVulnerabilities = data.vulns && Object.keys(data.vulns).length > 0
  const portCount = data.ports ? data.ports.length : 0
  const serviceCount = data.data ? data.data.length : 0
  const vulnCount = hasVulnerabilities ? Object.keys(data.vulns).length : 0

  // Security analysis functions
  const getExposureLevel = () => {
    if (portCount > 20) return { level: "CRITICAL", color: "red", icon: XCircle }
    if (portCount > 10) return { level: "HIGH", color: "orange", icon: AlertTriangle }
    if (portCount > 5) return { level: "MEDIUM", color: "yellow", icon: AlertTriangle }
    if (portCount > 0) return { level: "LOW", color: "blue", icon: Info }
    return { level: "MINIMAL", color: "green", icon: CheckCircle }
  }

  const exposureLevel = getExposureLevel()

  // Generate security recommendations based on detected services
  const generateSecurityTips = () => {
    const tips = []
    const criticalPorts = []
    const warnings = []

    if (!data.data) return { tips, criticalPorts, warnings }

    data.data.forEach((service: any) => {
      const port = service.port
      const product = service.product || "Unknown"
      const version = service.version || ""

      // Critical services that should be secured
      if (port === 22) {
        tips.push({
          port,
          service: "SSH",
          risk: "HIGH",
          recommendations: [
            "Disable password authentication, use key-based auth only",
            "Change default port from 22 to non-standard port",
            "Implement fail2ban or similar intrusion prevention",
            "Restrict access to specific IP ranges",
            "Disable root login",
            "Use strong SSH key passphrases",
          ],
        })
      } else if (port === 21) {
        criticalPorts.push(port)
        tips.push({
          port,
          service: "FTP",
          risk: "CRITICAL",
          recommendations: [
            "⚠️ IMMEDIATE ACTION: Disable FTP if not essential",
            "Replace with SFTP or FTPS for secure file transfer",
            "If FTP required, use strong authentication",
            "Implement IP whitelisting",
            "Monitor all FTP access logs",
          ],
        })
      } else if (port === 23) {
        criticalPorts.push(port)
        tips.push({
          port,
          service: "Telnet",
          risk: "CRITICAL",
          recommendations: [
            "🚨 CRITICAL: Disable Telnet immediately",
            "Replace with SSH for secure remote access",
            "Telnet transmits credentials in plain text",
            "High risk of credential interception",
          ],
        })
      } else if (port === 3389) {
        tips.push({
          port,
          service: "RDP",
          risk: "HIGH",
          recommendations: [
            "Enable Network Level Authentication",
            "Use strong passwords or certificate authentication",
            "Implement account lockout policies",
            "Restrict access to specific IP ranges",
            "Consider VPN access instead of direct exposure",
            "Enable RDP logging and monitoring",
          ],
        })
      } else if (port === 80) {
        tips.push({
          port,
          service: "HTTP",
          risk: "MEDIUM",
          recommendations: [
            "Redirect all HTTP traffic to HTTPS",
            "Implement security headers (HSTS, CSP, etc.)",
            "Regular security updates and patches",
            "Web application firewall (WAF) recommended",
            "Regular vulnerability scanning",
          ],
        })
      } else if (port === 443) {
        tips.push({
          port,
          service: "HTTPS",
          risk: "LOW",
          recommendations: [
            "Ensure strong SSL/TLS configuration",
            "Use modern cipher suites only",
            "Implement HSTS headers",
            "Regular SSL certificate renewal",
            "Monitor for SSL vulnerabilities",
          ],
        })
      } else if (port === 25 || port === 587 || port === 465) {
        tips.push({
          port,
          service: "SMTP",
          risk: "MEDIUM",
          recommendations: [
            "Implement SMTP authentication",
            "Use TLS encryption for email transmission",
            "Configure SPF, DKIM, and DMARC records",
            "Monitor for spam and abuse",
            "Regular security updates",
          ],
        })
      } else if ([135, 139, 445].includes(port)) {
        criticalPorts.push(port)
        tips.push({
          port,
          service: "SMB/NetBIOS",
          risk: "CRITICAL",
          recommendations: [
            "🚨 CRITICAL: Block SMB ports from internet",
            "SMB should never be exposed to public internet",
            "High risk of ransomware and lateral movement",
            "Implement network segmentation",
            "Use VPN for remote file access",
          ],
        })
      } else if (port === 1433 || port === 3306 || port === 5432) {
        criticalPorts.push(port)
        tips.push({
          port,
          service: "Database",
          risk: "CRITICAL",
          recommendations: [
            "🚨 CRITICAL: Database should not be internet-facing",
            "Implement database firewall",
            "Use application-layer access only",
            "Strong authentication and encryption",
            "Regular security patches and updates",
            "Database activity monitoring",
          ],
        })
      }

      // Check for outdated software versions
      if (version && (version.includes("2019") || version.includes("2018") || version.includes("2017"))) {
        warnings.push(`Potentially outdated software detected on port ${port}: ${product} ${version}`)
      }
    })

    return { tips, criticalPorts, warnings }
  }

  const securityAnalysis = generateSecurityTips()

  return (
    <Card className="bg-slate-800/50 border-slate-700 animate-fade-in">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-slate-100">
          <Server className="h-5 w-5 text-cyan-400" />
          Network Intelligence Analysis
        </CardTitle>
        <CardDescription className="text-slate-400">
          Network exposure and security analysis via multiple sources
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Critical Security Alerts */}
        {(hasVulnerabilities || securityAnalysis.criticalPorts.length > 0) && (
          <Alert variant="destructive" className="bg-red-900/30 border-red-500 animate-fade-in">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription className="text-red-200">
              {hasVulnerabilities && (
                <div>🚨 CRITICAL: {vulnCount} known vulnerabilities detected. Immediate patching required.</div>
              )}
              {securityAnalysis.criticalPorts.length > 0 && (
                <div>⚠️ HIGH RISK: Critical services exposed on ports {securityAnalysis.criticalPorts.join(", ")}</div>
              )}
            </AlertDescription>
          </Alert>
        )}

        {/* Network Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-slate-900/30 p-4 rounded-lg border border-slate-600 text-center animate-fade-in-up">
            <Wifi className="h-8 w-8 text-cyan-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-slate-100">{portCount}</div>
            <div className="text-sm text-slate-400">Open Ports</div>
          </div>
          <div
            className="bg-slate-900/30 p-4 rounded-lg border border-slate-600 text-center animate-fade-in-up"
            style={{ animationDelay: "0.1s" }}
          >
            <Server className="h-8 w-8 text-blue-400 mx-auto mb-2" />
            <div className="text-2xl font-bold text-slate-100">{serviceCount}</div>
            <div className="text-sm text-slate-400">Services</div>
          </div>
          <div
            className="bg-slate-900/30 p-4 rounded-lg border border-slate-600 text-center animate-fade-in-up"
            style={{ animationDelay: "0.2s" }}
          >
            <Shield className={`h-8 w-8 mx-auto mb-2 ${hasVulnerabilities ? "text-red-400" : "text-green-400"}`} />
            <div className={`text-2xl font-bold ${hasVulnerabilities ? "text-red-300" : "text-green-300"}`}>
              {vulnCount}
            </div>
            <div className="text-sm text-slate-400">Vulnerabilities</div>
          </div>
          <div
            className="bg-slate-900/30 p-4 rounded-lg border border-slate-600 text-center animate-fade-in-up"
            style={{ animationDelay: "0.3s" }}
          >
            <Eye className={`h-8 w-8 mx-auto mb-2 text-${exposureLevel.color}-400`} />
            <div className={`text-lg font-bold text-${exposureLevel.color}-300`}>{exposureLevel.level}</div>
            <div className="text-sm text-slate-400">Exposure</div>
          </div>
        </div>

        {/* Data Sources Indicator */}
        {data && (
          <div className="bg-slate-900/30 p-3 rounded-lg border border-slate-600 animate-fade-in">
            <h4 className="text-sm font-medium text-slate-200 mb-2">Intelligence Sources</h4>
            <div className="flex flex-wrap gap-2">
              {data.sources?.ipinfo && (
                <Badge variant="outline" className="border-blue-500 text-blue-300">
                  IPInfo
                </Badge>
              )}
              {data.sources?.urlvoid && (
                <Badge variant="outline" className="border-purple-500 text-purple-300">
                  URLVoid
                </Badge>
              )}
              {!data.sources?.ipinfo && !data.sources?.urlvoid && (
                <Badge variant="outline" className="border-yellow-500 text-yellow-300">
                  Limited Data Available
                </Badge>
              )}
            </div>
          </div>
        )}

        {/* Security Recommendations */}
        {securityAnalysis.tips.length > 0 && (
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.1s" }}>
            <h3 className="font-semibold flex items-center gap-2 text-slate-200">
              <Lock className="h-4 w-4 text-cyan-400" />
              Security Recommendations
            </h3>
            <div className="space-y-4 bg-slate-900/30 p-4 rounded-lg border border-slate-600 max-h-96 overflow-y-auto">
              {securityAnalysis.tips.map((tip, index) => (
                <div
                  key={tip.port}
                  className={`p-4 rounded-lg border animate-fade-in ${
                    tip.risk === "CRITICAL"
                      ? "bg-red-900/20 border-red-500/50"
                      : tip.risk === "HIGH"
                        ? "bg-orange-900/20 border-orange-500/50"
                        : tip.risk === "MEDIUM"
                          ? "bg-yellow-900/20 border-yellow-500/50"
                          : "bg-blue-900/20 border-blue-500/50"
                  }`}
                  style={{ animationDelay: `${index * 0.1}s` }}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="border-cyan-500 text-cyan-300">
                        Port {tip.port}
                      </Badge>
                      <Badge variant="outline" className="border-slate-500 text-slate-300">
                        {tip.service}
                      </Badge>
                    </div>
                    <Badge
                      variant={tip.risk === "CRITICAL" ? "destructive" : "secondary"}
                      className={
                        tip.risk === "CRITICAL"
                          ? "bg-red-600 animate-pulse"
                          : tip.risk === "HIGH"
                            ? "bg-orange-600"
                            : tip.risk === "MEDIUM"
                              ? "bg-yellow-600"
                              : "bg-blue-600"
                      }
                    >
                      {tip.risk} RISK
                    </Badge>
                  </div>
                  <div className="space-y-2">
                    <h4 className="text-sm font-medium text-slate-200">Recommended Actions:</h4>
                    <ul className="text-sm space-y-1">
                      {tip.recommendations.map((rec, recIndex) => (
                        <li key={recIndex} className="flex items-start gap-2 text-slate-300">
                          <span className="text-cyan-400 mt-1 text-xs">▶</span>
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Reputation Analysis */}
        {data.reputation && (
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.15s" }}>
            <h3 className="font-semibold flex items-center gap-2 text-slate-200">
              <Shield className="h-4 w-4 text-cyan-400" />
              Domain Reputation Analysis
            </h3>
            <div
              className={`bg-slate-900/30 p-4 rounded-lg border ${
                data.reputation.status === "unsupported" || data.reputation.status === "unavailable"
                  ? "border-yellow-500/50"
                  : data.reputation.malicious
                    ? "border-red-500/50"
                    : "border-green-500/50"
              }`}
            >
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  {data.reputation.status === "unsupported" || data.reputation.status === "unavailable" ? (
                    <AlertTriangle className="h-5 w-5 text-yellow-400" />
                  ) : data.reputation.malicious ? (
                    <XCircle className="h-5 w-5 text-red-400" />
                  ) : (
                    <CheckCircle className="h-5 w-5 text-green-400" />
                  )}
                  <span
                    className={`font-medium ${
                      data.reputation.status === "unsupported" || data.reputation.status === "unavailable"
                        ? "text-yellow-300"
                        : data.reputation.malicious
                          ? "text-red-300"
                          : "text-green-300"
                    }`}
                  >
                    {data.reputation.status === "unsupported"
                      ? "Domain Type Not Supported"
                      : data.reputation.status === "unavailable"
                        ? "Reputation Data Unavailable"
                        : data.reputation.malicious
                          ? "Malicious Activity Detected"
                          : "Clean Reputation"}
                  </span>
                </div>
                {data.reputation.status === "scanned" && (
                  <Badge
                    variant={data.reputation.malicious ? "destructive" : "default"}
                    className={data.reputation.malicious ? "bg-red-600" : "bg-green-600"}
                  >
                    {data.reputation.detections || 0}/{data.reputation.total_engines || 0} Detections
                  </Badge>
                )}
              </div>

              {data.reputation.status === "unsupported" && (
                <div className="text-sm text-yellow-200">
                  <strong>Note:</strong> This domain type is not supported by URLVoid reputation scanning. This is
                  common for local domains, development environments, or certain TLDs.
                </div>
              )}

              {data.reputation.status === "unavailable" && (
                <div className="text-sm text-yellow-200">
                  <strong>Note:</strong> Reputation data could not be retrieved at this time. This may be due to API
                  limitations or temporary service issues.
                </div>
              )}

              {data.reputation.malicious && data.reputation.engines && data.reputation.engines.length > 0 && (
                <div className="text-sm text-slate-300">
                  <strong>Flagged by:</strong> {data.reputation.engines.join(", ")}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Host Information */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.2s" }}>
            <h3 className="font-semibold flex items-center gap-2 text-slate-200">
              <Globe className="h-4 w-4 text-cyan-400" />
              Host Information
            </h3>
            <div className="space-y-2 text-sm bg-slate-900/30 p-4 rounded-lg border border-slate-600">
              <div className="text-slate-300">
                <strong className="text-slate-100">IP Address:</strong>
                <span className="font-mono ml-2 text-cyan-300">{data.ip_str}</span>
              </div>
              {data.hostnames && data.hostnames.length > 0 && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">Hostnames:</strong> {data.hostnames.join(", ")}
                </div>
              )}
              {data.org && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">Organization:</strong> {data.org}
                </div>
              )}
              {data.isp && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">ISP:</strong> {data.isp}
                </div>
              )}
              {data.asn && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">ASN:</strong> {data.asn}
                </div>
              )}
            </div>
          </div>

          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.3s" }}>
            <h3 className="font-semibold flex items-center gap-2 text-slate-200">
              <MapPin className="h-4 w-4 text-cyan-400" />
              Geolocation
            </h3>
            <div className="space-y-2 text-sm bg-slate-900/30 p-4 rounded-lg border border-slate-600">
              {data.country_name && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">Country:</strong> {data.country_name}
                </div>
              )}
              {data.city && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">City:</strong> {data.city}
                </div>
              )}
              {data.region_code && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">Region:</strong> {data.region_code}
                </div>
              )}
              {data.postal_code && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">Postal Code:</strong> {data.postal_code}
                </div>
              )}
              {data.latitude && data.longitude && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">Coordinates:</strong> {data.latitude}, {data.longitude}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Open Ports */}
        {data.ports && data.ports.length > 0 && (
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.4s" }}>
            <h3 className="font-semibold flex items-center gap-2 text-slate-200">
              <Wifi className="h-4 w-4 text-cyan-400" />
              Network Exposure ({data.ports.length} ports)
            </h3>
            <div className="flex flex-wrap gap-2 bg-slate-900/30 p-4 rounded-lg border border-slate-600">
              {data.ports.map((port: number, index: number) => {
                const isCritical = [21, 23, 135, 139, 445, 1433, 3306, 5432].includes(port)
                const isHighRisk = [22, 3389].includes(port)

                return (
                  <Badge
                    key={port}
                    variant="outline"
                    className={`transition-colors animate-fade-in ${
                      isCritical
                        ? "border-red-500 text-red-300 hover:bg-red-500/20"
                        : isHighRisk
                          ? "border-orange-500 text-orange-300 hover:bg-orange-500/20"
                          : "border-cyan-500 text-cyan-300 hover:bg-cyan-500/20"
                    }`}
                    style={{ animationDelay: `${index * 0.05}s` }}
                  >
                    {port}
                    {isCritical && " ⚠️"}
                  </Badge>
                )
              })}
            </div>
          </div>
        )}

        {/* Vulnerabilities */}
        {hasVulnerabilities && (
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.5s" }}>
            <h3 className="font-semibold text-red-300 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Critical Vulnerabilities
            </h3>
            <div className="space-y-3 bg-red-900/20 p-4 rounded-lg border border-red-500/30">
              {Object.entries(data.vulns).map(([vuln, details], index) => (
                <div
                  key={vuln}
                  className="p-3 bg-red-900/30 border border-red-500/50 rounded animate-fade-in"
                  style={{ animationDelay: `${index * 0.1}s` }}
                >
                  <div className="flex items-center justify-between mb-2">
                    <Badge variant="destructive" className="animate-pulse">
                      {vuln}
                    </Badge>
                    <span className="text-xs text-red-300">IMMEDIATE ACTION REQUIRED</span>
                  </div>
                  <p className="text-sm text-red-200">
                    🚨 Critical vulnerability detected - Requires immediate security attention and patching
                  </p>
                  <div className="mt-2 text-xs text-red-300">
                    <strong>Recommended Actions:</strong>
                    <ul className="mt-1 space-y-1">
                      <li>• Apply security patches immediately</li>
                      <li>• Consider taking service offline until patched</li>
                      <li>• Implement additional monitoring</li>
                      <li>• Review access logs for exploitation attempts</li>
                    </ul>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Software Warnings */}
        {securityAnalysis.warnings.length > 0 && (
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.6s" }}>
            <h3 className="font-semibold text-yellow-300 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Software Security Warnings
            </h3>
            <div className="space-y-2 bg-yellow-900/20 p-4 rounded-lg border border-yellow-500/30">
              {securityAnalysis.warnings.map((warning, index) => (
                <div key={index} className="text-sm text-yellow-200 flex items-start gap-2">
                  <span className="text-yellow-400 mt-1">⚠️</span>
                  {warning}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Services Details */}
        {data.data && data.data.length > 0 && (
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.7s" }}>
            <h3 className="font-semibold text-slate-200">Detected Services</h3>
            <div className="space-y-3 max-h-96 overflow-y-auto bg-slate-900/30 p-4 rounded-lg border border-slate-600">
              {data.data.slice(0, 10).map((service: any, index: number) => {
                const isCritical = [21, 23, 135, 139, 445, 1433, 3306, 5432].includes(service.port)

                return (
                  <div
                    key={index}
                    className={`p-4 rounded-lg border transition-all duration-200 animate-fade-in ${
                      isCritical
                        ? "bg-red-900/20 border-red-500/50 hover:border-red-400/70"
                        : "bg-slate-800/50 border-slate-600 hover:border-cyan-500/50"
                    }`}
                    style={{ animationDelay: `${index * 0.1}s` }}
                  >
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2">
                        <Badge variant="secondary" className="bg-blue-600 text-white">
                          Port {service.port}
                        </Badge>
                        {service.product && (
                          <Badge variant="outline" className="border-cyan-500 text-cyan-300">
                            {service.product}
                          </Badge>
                        )}
                        {isCritical && (
                          <Badge variant="destructive" className="animate-pulse">
                            HIGH RISK
                          </Badge>
                        )}
                      </div>
                      <span className="text-xs text-slate-400">{new Date(service.timestamp).toLocaleDateString()}</span>
                    </div>

                    {service.banner && (
                      <div className="mt-3">
                        <strong className="text-sm text-slate-200">Service Banner:</strong>
                        <pre className="text-xs bg-slate-900/50 p-3 rounded border border-slate-600 mt-2 overflow-x-auto text-slate-300 font-mono">
                          {service.banner.substring(0, 300)}
                          {service.banner.length > 300 && "..."}
                        </pre>
                      </div>
                    )}

                    <div className="grid grid-cols-2 gap-3 mt-3 text-xs">
                      {service.version && (
                        <div className="text-slate-300">
                          <strong className="text-slate-200">Version:</strong> {service.version}
                        </div>
                      )}
                      {service.transport && (
                        <div className="text-slate-300">
                          <strong className="text-slate-200">Protocol:</strong> {service.transport}
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}
              {data.data.length > 10 && (
                <p className="text-sm text-slate-400 text-center py-3 border-t border-slate-600">
                  ... and {data.data.length - 10} more services detected
                </p>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
