"use client"

import { useState, useEffect } from "react"
import { Card, CardContent } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { CheckCircle, XCircle, AlertTriangle, Wifi, Bot, Cpu, Activity } from "lucide-react"

interface SystemStatusProps {
  errors?: Record<string, string>
  reportType?: "ai" | "fallback"
}

export function SystemStatus({ errors = {}, reportType }: SystemStatusProps) {
  const [isVisible, setIsVisible] = useState(false)

  useEffect(() => {
    // Show status for a few seconds after analysis
    if (Object.keys(errors).length > 0 || reportType) {
      setIsVisible(true)
      const timer = setTimeout(() => setIsVisible(false), 12000)
      return () => clearTimeout(timer)
    }
  }, [errors, reportType])

  if (!isVisible) return null

  const getServiceStatus = (service: string) => {
    if (errors[service]) {
      return {
        status: "error",
        icon: XCircle,
        color: "text-red-400",
        bgColor: "bg-red-500/10",
        borderColor: "border-red-500/20",
      }
    }
    return {
      status: "success",
      icon: CheckCircle,
      color: "text-green-400",
      bgColor: "bg-green-500/10",
      borderColor: "border-green-500/20",
    }
  }

  const services = [
    { name: "WHOIS", key: "whois", icon: Wifi },
    { name: "VirusTotal", key: "virustotal", icon: Activity },
    { name: "Network Intel", key: "shodan", icon: Cpu },
  ]

  return (
    <Card className="glass-strong border-white/10 animate-scale-in">
      <CardContent className="p-6">
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Wifi className="h-5 w-5 text-blue-400" />
              <h3 className="text-lg font-semibold text-white">System Status</h3>
            </div>
            <Badge
              className={`${reportType === "ai" ? "bg-green-500/10 text-green-400 border-green-500/20" : "bg-blue-500/10 text-blue-400 border-blue-500/20"}`}
            >
              {reportType === "ai" ? (
                <>
                  <Bot className="h-3 w-3 mr-1" />
                  AI Enhanced
                </>
              ) : (
                <>
                  <Cpu className="h-3 w-3 mr-1" />
                  Standard Mode
                </>
              )}
            </Badge>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {services.map((service) => {
              const status = getServiceStatus(service.key)
              const StatusIcon = status.icon
              const ServiceIcon = service.icon

              return (
                <div
                  key={service.key}
                  className={`flex items-center gap-3 p-4 rounded-xl glass border ${status.bgColor} ${status.borderColor} transition-all duration-300`}
                >
                  <ServiceIcon className="h-5 w-5 text-gray-400" />
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-white text-sm">{service.name}</div>
                    <div className="flex items-center gap-2 mt-1">
                      <StatusIcon className={`h-3 w-3 ${status.color}`} />
                      <span className={`text-xs ${status.color}`}>
                        {status.status === "error" ? "Error" : "Online"}
                      </span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>

          {Object.keys(errors).length > 0 && (
            <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-4">
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-yellow-400 mt-0.5 flex-shrink-0" />
                <div>
                  <h4 className="text-yellow-300 font-medium text-sm mb-1">Partial Service Interruption</h4>
                  <p className="text-yellow-200/80 text-xs">
                    Some services experienced issues but analysis completed successfully with available data sources.
                  </p>
                </div>
              </div>
            </div>
          )}

          <div className="text-xs text-gray-500 text-center">Last updated: {new Date().toLocaleTimeString()}</div>
        </div>
      </CardContent>
    </Card>
  )
}
