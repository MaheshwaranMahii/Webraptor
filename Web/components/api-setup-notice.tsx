"use client"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { CheckCircle, Zap, Shield, Globe, Server } from "lucide-react"

export function APISetupNotice() {
  return (
    <Alert className="glass-strong border-green-500/20 animate-fade-in">
      <CheckCircle className="h-5 w-5 text-green-400" />
      <AlertDescription className="text-green-200">
        <div className="space-y-4">
          <div className="flex items-start gap-3">
            <Zap className="h-5 w-5 text-yellow-400 mt-0.5 flex-shrink-0" />
            <div>
              <strong className="text-green-100 block mb-2">Network Intelligence APIs Active</strong>
              <p className="text-sm text-green-200/80">
                Web Raptor is fully configured with integrated API keys for comprehensive web reconnaissance and threat
                intelligence gathering.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
            <div className="glass p-4 rounded-xl border border-green-500/20 card-interactive">
              <div className="flex items-center gap-3 mb-3">
                <div className="status-dot status-online"></div>
                <div className="flex items-center gap-2">
                  <Globe className="h-4 w-4 text-blue-400" />
                  <strong className="text-white">IPInfo.io</strong>
                </div>
                <Badge className="ml-auto bg-green-500/10 text-green-400 border-green-500/20 text-xs">Active</Badge>
              </div>
              <p className="text-green-200/70 text-xs">
                IP geolocation, ASN, ISP data, and network infrastructure mapping
              </p>
            </div>

            <div className="glass p-4 rounded-xl border border-green-500/20 card-interactive">
              <div className="flex items-center gap-3 mb-3">
                <div className="status-dot status-online"></div>
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-purple-400" />
                  <strong className="text-white">URLVoid</strong>
                </div>
                <Badge className="ml-auto bg-green-500/10 text-green-400 border-green-500/20 text-xs">Active</Badge>
              </div>
              <p className="text-green-200/70 text-xs">Domain reputation analysis and malicious URL detection</p>
            </div>

            <div className="glass p-4 rounded-xl border border-green-500/20 card-interactive">
              <div className="flex items-center gap-3 mb-3">
                <div className="status-dot status-online"></div>
                <div className="flex items-center gap-2">
                  <Server className="h-4 w-4 text-cyan-400" />
                  <strong className="text-white">Whois.com</strong>
                </div>
                <Badge className="ml-auto bg-green-500/10 text-green-400 border-green-500/20 text-xs">Active</Badge>
              </div>
              <p className="text-green-200/70 text-xs">Domain registration data and ownership information</p>
            </div>

            <div className="glass p-4 rounded-xl border border-green-500/20 card-interactive">
              <div className="flex items-center gap-3 mb-3">
                <div className="status-dot status-online"></div>
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-red-400" />
                  <strong className="text-white">VirusTotal</strong>
                </div>
                <Badge className="ml-auto bg-green-500/10 text-green-400 border-green-500/20 text-xs">Active</Badge>
              </div>
              <p className="text-green-200/70 text-xs">Malware detection and threat intelligence scanning</p>
            </div>

            <div className="glass p-4 rounded-xl border border-green-500/20 card-interactive">
              <div className="flex items-center gap-3 mb-3">
                <div className="status-dot status-online"></div>
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-pink-400" />
                  <strong className="text-white">Nessus</strong>
                </div>
                <Badge className="ml-auto bg-green-500/10 text-green-400 border-green-500/20 text-xs">Active</Badge>
              </div>
              <p className="text-green-200/70 text-xs">Vulnerability scanning and CVE-based risk assessment</p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-sm bg-green-500/5 p-4 rounded-xl border border-green-500/10">
            <CheckCircle className="h-5 w-5 text-green-400 flex-shrink-0" />
            <div>
              <strong className="text-green-300">System Ready:</strong>
              <span className="text-green-200/80 ml-2">
                All network intelligence APIs are configured and operational for reconnaissance operations.
              </span>
            </div>
          </div>
        </div>
      </AlertDescription>
    </Alert>
  )
}
