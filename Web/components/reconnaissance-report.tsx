"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { FileText, Download, Bot, Cpu, Info } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"

interface ReconnaissanceReportProps {
  report?: string
  target: string
  reportType?: "ai" | "fallback"
}

export function ReconnaissanceReport({ report, target, reportType = "fallback" }: ReconnaissanceReportProps) {
  const handleDownload = () => {
    if (!report) return

    const blob = new Blob([report], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `web-raptor-intel-${target}-${new Date().toISOString().split("T")[0]}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  if (!report) {
    return (
      <Card className="bg-slate-800/50 border-slate-700 animate-fade-in">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-slate-100">
            <FileText className="h-5 w-5 text-cyan-400" />
            Intelligence Report
          </CardTitle>
          <CardDescription className="text-slate-400">No report data available</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-slate-400">Unable to generate intelligence report for this target.</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="bg-slate-800/50 border-slate-700 animate-fade-in">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-slate-100">
              <img
                src="/shuriken-logo.svg"
                alt="Web Raptor Logo"
                className="h-5 w-5"
                style={{
                  filter:
                    "brightness(0) saturate(100%) invert(70%) sepia(98%) saturate(1000%) hue-rotate(180deg) brightness(95%) contrast(101%)",
                }}
              />
              Web Raptor Reconnaissance Report
              <span className="text-xs text-slate-400 ml-2">by Maheshwaran</span>
            </CardTitle>
            <CardDescription className="text-slate-400">Comprehensive analysis for {target}</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            {reportType === "ai" ? (
              <Badge variant="default" className="bg-green-600 hover:bg-green-700 animate-pulse">
                <Bot className="h-3 w-3 mr-1" />
                AI Enhanced
              </Badge>
            ) : (
              <Badge variant="secondary" className="bg-blue-600 hover:bg-blue-700">
                <Cpu className="h-3 w-3 mr-1" />
                Automated Analysis
              </Badge>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={handleDownload}
              className="border-slate-600 text-slate-300 hover:bg-slate-700 transition-all duration-200 hover:scale-105"
            >
              <Download className="h-4 w-4 mr-2" />
              Export Report
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {reportType === "fallback" && (
          <Alert className="bg-blue-900/30 border-blue-500 animate-fade-in">
            <Info className="h-4 w-4" />
            <AlertDescription className="text-blue-200">
              This report was generated using our advanced automated analysis engine. All data sources have been
              processed and analyzed according to defensive security protocols to provide comprehensive threat
              intelligence.
            </AlertDescription>
          </Alert>
        )}

        {reportType === "ai" && (
          <Alert className="bg-green-900/30 border-green-500 animate-fade-in">
            <Bot className="h-4 w-4" />
            <AlertDescription className="text-green-200">
              This report has been enhanced with AI-powered analysis to provide deeper insights and contextual threat
              intelligence recommendations.
            </AlertDescription>
          </Alert>
        )}

        <div className="bg-slate-900/50 rounded-lg border border-slate-600 p-4 animate-fade-in-up">
          <pre className="whitespace-pre-wrap text-sm leading-relaxed text-slate-200 font-mono overflow-x-auto">
            {report}
          </pre>
        </div>

        {/* Report Quality Indicators */}
        <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-700">
          <div className="flex items-center gap-4">
            <span>Report Quality: {reportType === "ai" ? "Enhanced" : "Standard"}</span>
            <span>Analysis Engine: {reportType === "ai" ? "AI + Automated" : "Automated"}</span>
          </div>
          <div>Generated: {new Date().toLocaleString()}</div>
        </div>
      </CardContent>
    </Card>
  )
}
