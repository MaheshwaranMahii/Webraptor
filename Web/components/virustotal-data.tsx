import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Shield, AlertTriangle, CheckCircle, XCircle, Clock } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"

interface VirusTotalDataProps {
  data?: any
  errors?: Record<string, string>
}

export function VirusTotalData({ data, errors }: VirusTotalDataProps) {
  // Handle errors
  if (errors?.virustotal) {
    return (
      <Card className="bg-slate-800/50 border-slate-700 animate-fade-in">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-slate-100">
            <Shield className="h-5 w-5 text-cyan-400" />
            VirusTotal Threat Intelligence
          </CardTitle>
          <CardDescription className="text-slate-400">Malware and threat detection analysis</CardDescription>
        </CardHeader>
        <CardContent>
          <Alert variant="destructive" className="bg-red-900/30 border-red-500">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription className="text-red-200">VirusTotal scan failed: {errors.virustotal}</AlertDescription>
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
            <Shield className="h-5 w-5 text-cyan-400" />
            VirusTotal Threat Intelligence
          </CardTitle>
          <CardDescription className="text-slate-400">Malware and threat detection analysis</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-slate-400">No VirusTotal data available for this target.</p>
        </CardContent>
      </Card>
    )
  }

  const getThreatLevel = () => {
    if (data.positives > 5) return { level: "CRITICAL", color: "bg-red-600", textColor: "text-red-300", icon: XCircle }
    if (data.positives > 2)
      return { level: "HIGH", color: "bg-orange-600", textColor: "text-orange-300", icon: AlertTriangle }
    if (data.positives > 0)
      return { level: "MEDIUM", color: "bg-yellow-600", textColor: "text-yellow-300", icon: AlertTriangle }
    return { level: "CLEAN", color: "bg-green-600", textColor: "text-green-300", icon: CheckCircle }
  }

  const threat = getThreatLevel()
  const ThreatIcon = threat.icon

  return (
    <Card className="bg-slate-800/50 border-slate-700 animate-fade-in">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-slate-100">
          <Shield className="h-5 w-5 text-cyan-400" />
          VirusTotal Threat Intelligence
        </CardTitle>
        <CardDescription className="text-slate-400">Malware and threat detection analysis</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Threat Summary */}
        <div
          className={`flex items-center justify-between p-4 rounded-lg border animate-fade-in-up ${threat.color}/20 border-${threat.color.split("-")[1]}-500`}
        >
          <div className="flex items-center gap-3">
            <ThreatIcon className={`h-8 w-8 ${threat.textColor} animate-pulse`} />
            <div>
              <h3 className="font-semibold text-slate-100">Threat Assessment</h3>
              <p className="text-sm text-slate-300">
                {data.positives} of {data.total} security engines flagged this target
              </p>
            </div>
          </div>
          <Badge className={`${threat.color} text-white font-bold px-3 py-1 animate-bounce`}>{threat.level}</Badge>
        </div>

        {/* Detection Alert */}
        {data.positives > 0 && (
          <Alert variant="destructive" className="bg-red-900/30 border-red-500 animate-fade-in">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription className="text-red-200">
              ⚠️ SECURITY ALERT: This target has been flagged by {data.positives} security vendors. Implement immediate
              defensive measures and restrict access.
            </AlertDescription>
          </Alert>
        )}

        {/* Scan Information */}
        <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.1s" }}>
          <h3 className="font-semibold flex items-center gap-2 text-slate-200">
            <Clock className="h-4 w-4 text-cyan-400" />
            Scan Details
          </h3>
          <div className="grid grid-cols-2 gap-4 text-sm bg-slate-900/30 p-4 rounded-lg border border-slate-600">
            <div className="text-slate-300">
              <strong className="text-slate-100">Scan Date:</strong> {data.scan_date || "N/A"}
            </div>
            <div className="text-slate-300">
              <strong className="text-slate-100">Response Code:</strong> {data.response_code}
            </div>
            <div className="col-span-2 text-slate-300">
              <strong className="text-slate-100">Status:</strong> {data.verbose_msg}
            </div>
          </div>
        </div>

        {/* Detected URLs */}
        {data.detected_urls && data.detected_urls.length > 0 && (
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.2s" }}>
            <h3 className="font-semibold text-slate-200">🚨 Malicious URLs Detected</h3>
            <div className="max-h-48 overflow-y-auto space-y-2 bg-slate-900/30 p-4 rounded-lg border border-red-500/30">
              {data.detected_urls.slice(0, 10).map((urlData: any, index: number) => (
                <div
                  key={index}
                  className="flex justify-between items-center text-sm p-3 bg-red-900/20 rounded border border-red-500/30 hover:bg-red-900/30 transition-colors"
                >
                  <span className="font-mono text-xs text-red-200 truncate flex-1 mr-2">{urlData.url}</span>
                  <Badge variant="destructive" size="sm" className="animate-pulse">
                    {urlData.positives}/{urlData.total}
                  </Badge>
                </div>
              ))}
              {data.detected_urls.length > 10 && (
                <p className="text-xs text-slate-400 text-center py-2">
                  ... and {data.detected_urls.length - 10} more malicious URLs detected
                </p>
              )}
            </div>
          </div>
        )}

        {/* DNS Resolutions */}
        {data.resolutions && data.resolutions.length > 0 && (
          <div className="space-y-3 animate-fade-in-up" style={{ animationDelay: "0.3s" }}>
            <h3 className="font-semibold text-slate-200">DNS Resolution History</h3>
            <div className="max-h-40 overflow-y-auto space-y-2 bg-slate-900/30 p-4 rounded-lg border border-slate-600">
              {data.resolutions.slice(0, 8).map((resolution: any, index: number) => (
                <div
                  key={index}
                  className="text-sm p-2 bg-slate-800/50 rounded border border-slate-600 hover:border-cyan-500/50 transition-colors"
                >
                  <div className="font-mono text-cyan-300">{resolution.ip_address}</div>
                  <div className="text-xs text-slate-400">Last resolved: {resolution.last_resolved}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
