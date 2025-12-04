import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Globe, Calendar, User, Building, AlertTriangle, Shield } from "lucide-react"

interface WhoisDataProps {
  data?: any
  errors?: Record<string, string>
}

export function WhoisData({ data, errors }: WhoisDataProps) {
  // Handle errors
  if (errors?.whois) {
    return (
      <Card className="bg-slate-800/50 border-slate-700 animate-fade-in">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-slate-100">
            <Globe className="h-5 w-5 text-cyan-400" />
            WHOIS Intelligence
          </CardTitle>
          <CardDescription className="text-slate-400">Domain registration and ownership data</CardDescription>
        </CardHeader>
        <CardContent>
          <Alert variant="destructive" className="bg-red-900/30 border-red-500">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription className="text-red-200">WHOIS lookup failed: {errors.whois}</AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    )
  }

  if (!data || !data.WhoisRecord) {
    return (
      <Card className="bg-slate-800/50 border-slate-700 animate-fade-in">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-slate-100">
            <Globe className="h-5 w-5 text-cyan-400" />
            WHOIS Intelligence
          </CardTitle>
          <CardDescription className="text-slate-400">Domain registration and ownership data</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-slate-400">No WHOIS data available for this target.</p>
        </CardContent>
      </Card>
    )
  }

  const whois = data.WhoisRecord

  // Safe handling of nameServers - ensure it's an array
  const getNameServers = () => {
    if (!whois.nameServers) return []

    // Handle case where nameServers might be a string
    if (typeof whois.nameServers === "string") {
      return [whois.nameServers]
    }

    // Handle case where nameServers is an array
    if (Array.isArray(whois.nameServers)) {
      return whois.nameServers
    }

    // Handle case where nameServers is an object with hostNames property
    if (whois.nameServers.hostNames && Array.isArray(whois.nameServers.hostNames)) {
      return whois.nameServers.hostNames
    }

    return []
  }

  const nameServers = getNameServers()

  // Calculate domain age for security assessment
  const getDomainAge = () => {
    if (!whois.createdDate) return null
    const created = new Date(whois.createdDate)
    const now = new Date()
    const ageInYears = Math.floor((now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24 * 365))
    return ageInYears
  }

  const domainAge = getDomainAge()

  // Security assessment based on domain data
  const getSecurityAssessment = () => {
    const issues = []
    const recommendations = []

    if (domainAge !== null && domainAge < 1) {
      issues.push("Recently registered domain (less than 1 year)")
      recommendations.push("Monitor for suspicious activity")
    }

    if (!whois.registrant?.name && !whois.registrant?.organization) {
      issues.push("Registrant information protected/hidden")
      recommendations.push("Additional verification may be required")
    }

    if (whois.expiresDate) {
      const expires = new Date(whois.expiresDate)
      const now = new Date()
      const daysUntilExpiry = Math.floor((expires.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))

      if (daysUntilExpiry < 30) {
        issues.push("Domain expires soon")
        recommendations.push("Monitor for domain renewal")
      }
    }

    return { issues, recommendations }
  }

  const securityAssessment = getSecurityAssessment()

  return (
    <Card className="bg-slate-800/50 border-slate-700 animate-fade-in">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-slate-100">
          <Globe className="h-5 w-5 text-cyan-400" />
          WHOIS Intelligence
        </CardTitle>
        <CardDescription className="text-slate-400">Domain registration and ownership data</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Security Assessment */}
        {(securityAssessment.issues.length > 0 || securityAssessment.recommendations.length > 0) && (
          <div className="space-y-3 animate-fade-in-up">
            <h3 className="font-semibold flex items-center gap-2 text-slate-200">
              <Shield className="h-4 w-4 text-cyan-400" />
              Security Assessment
            </h3>
            <div className="bg-slate-900/30 p-4 rounded-lg border border-slate-600">
              {securityAssessment.issues.length > 0 && (
                <div className="mb-3">
                  <h4 className="text-sm font-medium text-yellow-300 mb-2">⚠️ Security Considerations:</h4>
                  <ul className="text-sm text-slate-300 space-y-1">
                    {securityAssessment.issues.map((issue, index) => (
                      <li key={index} className="flex items-start gap-2">
                        <span className="text-yellow-400 mt-1">•</span>
                        {issue}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {securityAssessment.recommendations.length > 0 && (
                <div>
                  <h4 className="text-sm font-medium text-blue-300 mb-2">🛡️ Recommendations:</h4>
                  <ul className="text-sm text-slate-300 space-y-1">
                    {securityAssessment.recommendations.map((rec, index) => (
                      <li key={index} className="flex items-start gap-2">
                        <span className="text-blue-400 mt-1">•</span>
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Domain Info */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.1s" }}>
            <h3 className="font-semibold flex items-center gap-2 text-slate-200">
              <Globe className="h-4 w-4 text-cyan-400" />
              Domain Information
            </h3>
            <div className="space-y-2 text-sm bg-slate-900/30 p-4 rounded-lg border border-slate-600">
              <div className="text-slate-300">
                <strong className="text-slate-100">Domain:</strong> {whois.domainName}
              </div>
              {whois.status && (
                <div className="flex items-center gap-2">
                  <strong className="text-slate-100">Status:</strong>
                  <Badge variant="outline" className="border-green-500 text-green-300">
                    {Array.isArray(whois.status) ? whois.status.join(", ") : whois.status}
                  </Badge>
                </div>
              )}
              {domainAge !== null && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">Domain Age:</strong> {domainAge} years
                  {domainAge < 1 && <span className="text-yellow-400 ml-2">⚠️ Recently registered</span>}
                </div>
              )}
              {nameServers.length > 0 && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">Name Servers:</strong>
                  <ul className="ml-4 mt-1 space-y-1">
                    {nameServers.map((ns: string, index: number) => (
                      <li key={index} className="text-slate-400 font-mono text-xs">
                        • {ns}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>

          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.2s" }}>
            <h3 className="font-semibold flex items-center gap-2 text-slate-200">
              <Calendar className="h-4 w-4 text-cyan-400" />
              Timeline
            </h3>
            <div className="space-y-2 text-sm bg-slate-900/30 p-4 rounded-lg border border-slate-600">
              {whois.createdDate && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">Created:</strong>{" "}
                  {new Date(whois.createdDate).toLocaleDateString()}
                </div>
              )}
              {whois.updatedDate && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">Updated:</strong>{" "}
                  {new Date(whois.updatedDate).toLocaleDateString()}
                </div>
              )}
              {whois.expiresDate && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">Expires:</strong>{" "}
                  {new Date(whois.expiresDate).toLocaleDateString()}
                  {(() => {
                    const expires = new Date(whois.expiresDate)
                    const now = new Date()
                    const daysUntilExpiry = Math.floor((expires.getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
                    if (daysUntilExpiry < 30) {
                      return <span className="text-yellow-400 ml-2">⚠️ Expires soon</span>
                    }
                    return null
                  })()}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Registrant Info */}
        {whois.registrant && (
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.3s" }}>
            <h3 className="font-semibold flex items-center gap-2 text-slate-200">
              <User className="h-4 w-4 text-cyan-400" />
              Registrant Information
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm bg-slate-900/30 p-4 rounded-lg border border-slate-600">
              <div className="space-y-2">
                {whois.registrant.name ? (
                  <div className="text-slate-300">
                    <strong className="text-slate-100">Name:</strong> {whois.registrant.name}
                  </div>
                ) : (
                  <div className="text-slate-400">
                    <strong className="text-slate-100">Name:</strong> Protected/Hidden
                  </div>
                )}
                {whois.registrant.organization ? (
                  <div className="text-slate-300">
                    <strong className="text-slate-100">Organization:</strong> {whois.registrant.organization}
                  </div>
                ) : (
                  <div className="text-slate-400">
                    <strong className="text-slate-100">Organization:</strong> Not disclosed
                  </div>
                )}
                {whois.registrant.email ? (
                  <div className="text-slate-300">
                    <strong className="text-slate-100">Email:</strong> {whois.registrant.email}
                  </div>
                ) : (
                  <div className="text-slate-400">
                    <strong className="text-slate-100">Email:</strong> Protected/Hidden
                  </div>
                )}
              </div>
              <div className="space-y-2">
                {whois.registrant.country && (
                  <div className="text-slate-300">
                    <strong className="text-slate-100">Country:</strong> {whois.registrant.country}
                  </div>
                )}
                {whois.registrant.state && (
                  <div className="text-slate-300">
                    <strong className="text-slate-100">State:</strong> {whois.registrant.state}
                  </div>
                )}
                {whois.registrant.city && (
                  <div className="text-slate-300">
                    <strong className="text-slate-100">City:</strong> {whois.registrant.city}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Registrar Info */}
        {whois.registrarName && (
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.4s" }}>
            <h3 className="font-semibold flex items-center gap-2 text-slate-200">
              <Building className="h-4 w-4 text-cyan-400" />
              Registrar Information
            </h3>
            <div className="text-sm bg-slate-900/30 p-4 rounded-lg border border-slate-600 space-y-2">
              <div className="text-slate-300">
                <strong className="text-slate-100">Registrar:</strong> {whois.registrarName}
              </div>
              {whois.registrarIANAID && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">IANA ID:</strong> {whois.registrarIANAID}
                </div>
              )}
              {whois.registrarWhoisServer && (
                <div className="text-slate-300">
                  <strong className="text-slate-100">WHOIS Server:</strong> {whois.registrarWhoisServer}
                </div>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
