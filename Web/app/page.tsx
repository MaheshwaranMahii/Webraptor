"use client"

import type React from "react"
import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Progress } from "@/components/ui/progress"
import {
  Loader2,
  Shield,
  Search,
  FileText,
  Globe,
  Server,
  Eye,
  CheckCircle,
  AlertTriangle,
  Cpu,
  Activity,
  Wifi,
  Menu,
  ChevronDown,
} from "lucide-react"
import { ReconnaissanceReport } from "@/components/reconnaissance-report"
import { WhoisData } from "@/components/whois-data"
import { VirusTotalData } from "@/components/virustotal-data"
import { ShodanData } from "@/components/shodan-data"
import { NessusReport } from "@/components/nessus-report"
import { ComplianceFooter } from "@/components/compliance-footer"
import { SystemStatus } from "@/components/system-status"
import { APISetupNotice } from "@/components/api-setup-notice"
import { MobileNavigation } from "@/components/mobile-navigation"

interface ReconData {
  whois?: any
  virustotal?: any
  pentestTools?: any
  vulnerabilities?: any
  aiReport?: string
  fallbackReport?: string
  reportType?: "ai" | "fallback"
  errors?: Record<string, string>
}

interface AnalysisStep {
  name: string
  status: "pending" | "loading" | "complete" | "error"
  icon: React.ElementType
  description: string
}

export default function WebRaptorDashboard() {
  const [target, setTarget] = useState("")
  const [loading, setLoading] = useState(false)
  const [data, setData] = useState<ReconData>({})
  const [error, setError] = useState("")
  const [progress, setProgress] = useState(0)
  const [currentStep, setCurrentStep] = useState("")
  const [mounted, setMounted] = useState(false)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [activeTab, setActiveTab] = useState("report")
  const [analysisSteps, setAnalysisSteps] = useState<AnalysisStep[]>([
    { name: "WHOIS Lookup", status: "pending", icon: Globe, description: "Domain registration data" },
    { name: "VirusTotal Scan", status: "pending", icon: Shield, description: "Threat intelligence" },
    { name: "Network Analysis", status: "pending", icon: Server, description: "Infrastructure mapping" },
    { name: "Vulnerability Scan", status: "pending", icon: AlertTriangle, description: "Security vulnerabilities" },
    { name: "Report Generation", status: "pending", icon: FileText, description: "Intelligence compilation" },
  ])

  useEffect(() => {
    setMounted(true)
  }, [])

  const updateStepStatus = (stepName: string, status: AnalysisStep["status"]) => {
    setAnalysisSteps((prev) => prev.map((step) => (step.name === stepName ? { ...step, status } : step)))
  }

  const handleAnalysis = async () => {
    if (!target.trim()) {
      setError("Please enter a domain or IP address")
      return
    }

    // Basic client-side validation for better UX
    const cleanTarget = target.trim().toLowerCase()
    
    // Helper function for basic domain validation
    const isValidDomain = (domain: string): boolean => {
      const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '')
      const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/
      return domainRegex.test(cleanDomain) && cleanDomain.length <= 253 && !cleanDomain.includes('..')
    }
    
    const basicDomainCheck = isValidDomain(cleanTarget)
    const basicIPCheck = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(cleanTarget)
    const basicIPv6Check = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(cleanTarget) || 
                          /^::1$/.test(cleanTarget) || 
                          /^::$/.test(cleanTarget)

    if (!basicDomainCheck && !basicIPCheck && !basicIPv6Check) {
      setError("Please enter a valid domain (e.g., example.com, subdomain.example.com) or IP address (e.g., 8.8.8.8, 2001:db8::1)")
      return
    }

    setLoading(true)
    setError("")
    setData({})
    setProgress(0)
    setCurrentStep("Initializing reconnaissance systems...")

    // Reset all steps
    setAnalysisSteps((prev) => prev.map((step) => ({ ...step, status: "pending" as const })))

    try {
      setProgress(10)
      setCurrentStep("Establishing secure connections...")

      // Update steps progressively with realistic timing
      setTimeout(() => {
        updateStepStatus("WHOIS Lookup", "loading")
        setCurrentStep("Querying domain registration databases...")
        setProgress(25)
      }, 800)

      setTimeout(() => {
        updateStepStatus("VirusTotal Scan", "loading")
        setCurrentStep("Scanning threat intelligence databases...")
        setProgress(50)
      }, 1800)

      setTimeout(() => {
        updateStepStatus("Network Analysis", "loading")
        setCurrentStep("Mapping network infrastructure...")
        setProgress(60)
      }, 2800)

      setTimeout(() => {
        updateStepStatus("Vulnerability Scan", "loading")
        setCurrentStep("Scanning for security vulnerabilities...")
        setProgress(75)
      }, 3800)

      setTimeout(() => {
        updateStepStatus("Report Generation", "loading")
        setCurrentStep("Compiling intelligence report...")
        setProgress(90)
      }, 4800)

      const response = await fetch("/api/reconnaissance", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ target: target.trim() }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || "Analysis failed")
      }

      const result = await response.json()

      setProgress(100)
      setCurrentStep("Analysis complete! Intelligence gathered successfully.")

      // Update all steps to complete
      setAnalysisSteps((prev) => prev.map((step) => ({ ...step, status: "complete" as const })))

      setData(result)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to perform analysis. Please try again."
      setError(errorMessage)
      console.error("Analysis error:", err)

      // Mark current step as error
      setAnalysisSteps((prev) =>
        prev.map((step) => (step.status === "loading" ? { ...step, status: "error" as const } : step)),
      )
    } finally {
      setLoading(false)
      setTimeout(() => setCurrentStep(""), 3000)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      handleAnalysis()
    }
  }

  if (!mounted) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 relative">
      {/* Background Pattern */}
      <div className="absolute inset-0 bg-[url('data:image/svg+xml,%3Csvg width=&quot;60&quot; height=&quot;60&quot; viewBox=&quot;0 0 60 60&quot; xmlns=&quot;http://www.w3.org/2000/svg&quot;%3E%3Cg fill=&quot;none&quot; fillRule=&quot;evenodd&quot;%3E%3Cg fill=&quot;%23ffffff&quot; fillOpacity=&quot;0.02&quot;%3E%3Ccircle cx=&quot;30&quot; cy=&quot;30&quot; r=&quot;1&quot;/%3E%3C/g%3E%3C/g%3E%3C/svg%3E')] opacity-50"></div>

      {/* Mobile Navigation */}
      <MobileNavigation isOpen={mobileMenuOpen} onClose={() => setMobileMenuOpen(false)} />

      {/* Main Content */}
      <div className="relative z-10">
        {/* Header */}
        <header className="sticky top-0 z-40 w-full border-b border-white/5 glass-strong">
          <div className="container-wide px-4 sm:px-6 lg:px-8">
            <div className="flex h-16 items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-3">
                  <div className="relative">
                    <img
                      src="/shuriken-logo.svg"
                      alt="Web Raptor Logo"
                      className="h-8 w-8 animate-rotate-slow"
                    />
                  </div>
                  <div>
                    <h1 className="text-xl font-bold text-gradient">Web Raptor</h1>
                    <p className="text-xs text-gray-400 hidden sm:block">by Trojen Hex</p>
                  </div>
                </div>
              </div>

              {/* Desktop Navigation */}
              <nav className="hidden md:flex items-center gap-6">
                <Badge variant="outline" className="badge-enhanced bg-green-500/10 text-green-400 border-green-500/20">
                  <div className="status-dot status-online mr-2"></div>
                  Online
                </Badge>
                <Badge variant="outline" className="badge-enhanced bg-blue-500/10 text-blue-400 border-blue-500/20">
                  <Cpu className="h-3 w-3 mr-1" />
                  AI Ready
                </Badge>
              </nav>

              {/* Mobile Menu Button */}
              <Button
                variant="ghost"
                size="sm"
                className="md:hidden focus-ring"
                onClick={() => setMobileMenuOpen(true)}
                aria-label="Open menu"
              >
                <Menu className="h-5 w-5" />
              </Button>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="container-wide px-4 sm:px-6 lg:px-8 section-spacing">
          <div className="content-spacing">
            {/* Hero Section */}
            <section className="text-center space-y-6 animate-fade-in">
              <div className="space-y-4">
                <div className="flex items-center justify-center gap-4 mb-6">
                  <div className="relative">
                    <div className="absolute -inset-4 bg-gradient-to-r from-blue-500/20 to-purple-500/20 rounded-full blur-xl animate-pulse-subtle"></div>
                    <img
                      src="/shuriken-logo.svg"
                      alt="Web Raptor Logo"
                      className="relative h-16 w-16 sm:h-20 sm:w-20 animate-bounce-subtle"
                    />
                  </div>
                </div>

                <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold text-gradient leading-tight">
                   Web Attack Surface Discovery Platform
                </h1>
                <p className="text-lg sm:text-xl text-gray-300 max-w-3xl mx-auto leading-relaxed">
                  Professional-grade web reconnaissance and threat intelligence gathering with real-time analysis and
                  comprehensive reporting.
                </p>
              </div>

              <div className="flex flex-wrap items-center justify-center gap-3 animate-fade-in-up">
                <Badge className="badge-enhanced bg-green-500/10 text-green-400 border-green-500/20 px-3 py-1">
                  <Shield className="h-3 w-3 mr-1" />
                  Defensive Security
                </Badge>
                <Badge className="badge-enhanced bg-blue-500/10 text-blue-400 border-blue-500/20 px-3 py-1">
                  <Activity className="h-3 w-3 mr-1" />
                  Real-time Intel
                </Badge>
                <Badge className="badge-enhanced bg-purple-500/10 text-purple-400 border-purple-500/20 px-3 py-1">
                  <Wifi className="h-3 w-3 mr-1" />
                  Multi-Source
                </Badge>
              </div>
            </section>

            {/* API Status Notice */}
            <section className="animate-fade-in-up" style={{ animationDelay: "0.2s" }}>
              <APISetupNotice />
            </section>

            {/* Analysis Input Section */}
            <section className="animate-fade-in-up" style={{ animationDelay: "0.4s" }}>
              <Card className="container-narrow glass-strong border-white/10 card-interactive">
                <CardHeader className="text-center pb-6">
                  <CardTitle className="flex items-center justify-center gap-3 text-2xl sm:text-3xl font-bold text-white">
                    <Search className="h-6 w-6 sm:h-7 sm:w-7 text-blue-400 animate-pulse-subtle" />
                    Target Analysis
                  </CardTitle>
                  <CardDescription className="text-gray-400 text-base sm:text-lg">
                    Enter a domain name or IP address for comprehensive intelligence gathering
                  </CardDescription>
                </CardHeader>

                <CardContent className="space-y-6">
                  <div className="space-y-4">
                    <Label htmlFor="target" className="text-white font-medium text-lg">
                      Target Domain or IP Address
                    </Label>
                    <div className="relative">
                      <Input
                        id="target"
                        placeholder="example.com or 192.168.1.1"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        onKeyPress={handleKeyPress}
                        disabled={loading}
                        className="input-enhanced text-lg py-4 pl-4 pr-12 rounded-xl focus-ring"
                        aria-describedby="target-help"
                      />
                      <Search className="absolute right-4 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                    </div>
                    <p id="target-help" className="text-sm text-gray-500">
                      Supports domains (google.com) and IP addresses (8.8.8.8)
                    </p>
                  </div>

                  {error && (
                    <Alert className="bg-red-500/10 border-red-500/20 animate-scale-in">
                      <AlertTriangle className="h-4 w-4 text-red-400" />
                      <AlertDescription className="text-red-300">{error}</AlertDescription>
                    </Alert>
                  )}

                  {loading && (
                    <div className="space-y-6">
                      <div className="space-y-3">
                        <div className="flex justify-between items-center">
                          <span className="text-white font-medium">{currentStep}</span>
                          <span className="text-blue-400 font-mono text-sm">{progress}%</span>
                        </div>
                        <div className="relative">
                          <Progress value={progress} className="progress-enhanced h-3" />
                        </div>
                      </div>

                      {/* Enhanced Analysis Steps */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {analysisSteps.map((step, index) => {
                          const Icon = step.icon
                          return (
                            <div
                              key={step.name}
                              className={`flex items-center gap-4 p-4 rounded-xl transition-all duration-500 glass ${
                                step.status === "complete"
                                  ? "bg-green-500/10 border-green-500/20"
                                  : step.status === "loading"
                                    ? "bg-blue-500/10 border-blue-500/20 animate-pulse-subtle"
                                    : step.status === "error"
                                      ? "bg-red-500/10 border-red-500/20"
                                      : "bg-white/5 border-white/10"
                              }`}
                              style={{ animationDelay: `${index * 0.1}s` }}
                            >
                              <div className="flex-shrink-0">
                                {step.status === "loading" ? (
                                  <Loader2 className="h-5 w-5 animate-spin text-blue-400" />
                                ) : step.status === "complete" ? (
                                  <CheckCircle className="h-5 w-5 text-green-400" />
                                ) : step.status === "error" ? (
                                  <AlertTriangle className="h-5 w-5 text-red-400" />
                                ) : (
                                  <Icon className="h-5 w-5 text-gray-400" />
                                )}
                              </div>
                              <div className="flex-1 min-w-0">
                                <div className="font-medium text-white text-sm">{step.name}</div>
                                <div className="text-xs text-gray-400 truncate">{step.description}</div>
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )}

                  <Button
                    onClick={handleAnalysis}
                    disabled={loading || !target.trim()}
                    className="btn-primary w-full text-lg py-6 rounded-xl focus-ring"
                    aria-describedby="analyze-help"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="mr-3 h-5 w-5 animate-spin" />
                        Analyzing Target...
                      </>
                    ) : (
                      <>
                        <Eye className="mr-3 h-5 w-5" />
                        Launch Analysis
                      </>
                    )}
                  </Button>
                  <p id="analyze-help" className="text-xs text-gray-500 text-center">
                    Analysis typically takes 30-60 seconds to complete
                  </p>
                </CardContent>
              </Card>
            </section>

            {/* Results Section */}
            {Object.keys(data).length > 0 && (
              <section className="space-y-8 animate-fade-in-up" style={{ animationDelay: "0.6s" }}>
                <div className="text-center space-y-4">
                  <h2 className="text-3xl sm:text-4xl font-bold text-gradient">Intelligence Report</h2>
                  <div className="flex flex-wrap items-center justify-center gap-4">
                    <div className="flex items-center gap-2">
                      <span className="text-gray-400">Target:</span>
                      <code className="text-blue-400 bg-blue-500/10 px-3 py-1 rounded-lg font-mono text-sm">
                        {target}
                      </code>
                    </div>
                    <Badge className="badge-enhanced bg-green-500/10 text-green-400 border-green-500/20">
                      <CheckCircle className="h-3 w-3 mr-1" />
                      Analysis Complete
                    </Badge>
                  </div>
                </div>

                {/* System Status */}
                <SystemStatus errors={data.errors} reportType={data.reportType} />

                {/* Enhanced Tabs */}
                <div className="glass-strong rounded-2xl border border-white/10 overflow-hidden">
                  <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                    {/* Mobile Tab Selector */}
                    <div className="md:hidden border-b border-white/10">
                      <div className="relative">
                        <select
                          value={activeTab}
                          onChange={(e) => setActiveTab(e.target.value)}
                          className="w-full bg-transparent text-white p-4 appearance-none focus:outline-none focus:ring-2 focus:ring-blue-500"
                        >
                          <option value="report" className="bg-slate-900">
                            Intelligence Report
                          </option>
                          <option value="whois" className="bg-slate-900">
                            WHOIS Data
                          </option>
                          <option value="virustotal" className="bg-slate-900">
                            VirusTotal
                          </option>
                          <option value="shodan" className="bg-slate-900">
                            Pentest-Tools
                          </option>
                          <option value="nessus" className="bg-slate-900">
                            Nessus Scan
                          </option>
                        </select>
                        <ChevronDown className="absolute right-4 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400 pointer-events-none" />
                      </div>
                    </div>

                    {/* Desktop Tabs */}
                    <TabsList className="hidden md:grid w-full grid-cols-5 bg-transparent border-b border-white/10 rounded-none h-auto p-0">
                      <TabsTrigger
                        value="report"
                        className="flex items-center gap-3 py-4 px-6 data-[state=active]:bg-blue-500/10 data-[state=active]:text-blue-400 data-[state=active]:border-b-2 data-[state=active]:border-blue-500 transition-all duration-300 rounded-none focus-ring"
                      >
                        <FileText className="h-4 w-4" />
                        <span className="hidden lg:inline">Intelligence Report</span>
                        <span className="lg:hidden">Report</span>
                      </TabsTrigger>
                      <TabsTrigger
                        value="whois"
                        className="flex items-center gap-3 py-4 px-6 data-[state=active]:bg-blue-500/10 data-[state=active]:text-blue-400 data-[state=active]:border-b-2 data-[state=active]:border-blue-500 transition-all duration-300 rounded-none focus-ring"
                      >
                        <Globe className="h-4 w-4" />
                        <span className="hidden lg:inline">WHOIS Data</span>
                        <span className="lg:hidden">WHOIS</span>
                      </TabsTrigger>
                      <TabsTrigger
                        value="virustotal"
                        className="flex items-center gap-3 py-4 px-6 data-[state=active]:bg-blue-500/10 data-[state=active]:text-blue-400 data-[state=active]:border-b-2 data-[state=active]:border-blue-500 transition-all duration-300 rounded-none focus-ring"
                      >
                        <Shield className="h-4 w-4" />
                        <span className="hidden lg:inline">VirusTotal</span>
                        <span className="lg:hidden">Threats</span>
                      </TabsTrigger>
                      <TabsTrigger
                        value="shodan"
                        className="flex items-center gap-3 py-4 px-6 data-[state=active]:bg-blue-500/10 data-[state=active]:text-blue-400 data-[state=active]:border-b-2 data-[state=active]:border-blue-500 transition-all duration-300 rounded-none focus-ring"
                      >
                        <Server className="h-4 w-4" />
                        <span className="hidden lg:inline">Pentest-Tools</span>
                        <span className="lg:hidden">Pentest</span>
                      </TabsTrigger>
                      <TabsTrigger
                        value="nessus"
                        className="flex items-center gap-3 py-4 px-6 data-[state=active]:bg-blue-500/10 data-[state=active]:text-blue-400 data-[state=active]:border-b-2 data-[state=active]:border-blue-500 transition-all duration-300 rounded-none focus-ring"
                      >
                        <AlertTriangle className="h-4 w-4" />
                        <span className="hidden lg:inline">Nessus Scan</span>
                        <span className="lg:hidden">Nessus</span>
                      </TabsTrigger>
                    </TabsList>

                    <div className="p-6">
                      <TabsContent value="report" className="animate-fade-in mt-0">
                        <ReconnaissanceReport
                          report={data.aiReport || data.fallbackReport}
                          target={target}
                          reportType={data.reportType}
                        />
                      </TabsContent>

                      <TabsContent value="whois" className="animate-fade-in mt-0">
                        <WhoisData data={data.whois} errors={data.errors} />
                      </TabsContent>

                      <TabsContent value="virustotal" className="animate-fade-in mt-0">
                        <VirusTotalData data={data.virustotal} errors={data.errors} />
                      </TabsContent>

                      <TabsContent value="shodan" className="animate-fade-in mt-0">
                        <ShodanData data={data.pentestTools} errors={data.errors} />
                      </TabsContent>

                      <TabsContent value="nessus" className="animate-fade-in mt-0">
                        <NessusReport data={data.vulnerabilities} loading={loading} />
                      </TabsContent>
                    </div>
                  </Tabs>
                </div>
              </section>
            )}
          </div>
        </main>

        {/* Footer */}
        <footer className="animate-fade-in-up" style={{ animationDelay: "0.8s" }}>
          <ComplianceFooter />
        </footer>
      </div>
    </div>
  )
}
