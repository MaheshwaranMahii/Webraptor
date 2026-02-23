"use client"

import { useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { X, Shield, Cpu, Activity, Wifi, ExternalLink, Github, Mail } from "lucide-react"

interface MobileNavigationProps {
  isOpen: boolean
  onClose: () => void
}

export function MobileNavigation({ isOpen, onClose }: MobileNavigationProps) {
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = "hidden"
    } else {
      document.body.style.overflow = "unset"
    }

    return () => {
      document.body.style.overflow = "unset"
    }
  }, [isOpen])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 md:hidden">
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />

      {/* Navigation Panel */}
      <div className="fixed right-0 top-0 h-full w-80 max-w-[85vw] glass-strong border-l border-white/10 animate-slide-in-right">
        <div className="flex h-full flex-col">
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-white/10">
            <div className="flex items-center gap-3">
              <img
                src="/shuriken-logo.svg"
                alt="Web Raptor Logo"
                className="h-8 w-8 filter brightness-0 invert"
                style={{
                  filter:
                    "brightness(0) saturate(100%) invert(70%) sepia(98%) saturate(1000%) hue-rotate(180deg) brightness(95%) contrast(101%)",
                }}
              />
              <div>
                <h2 className="text-lg font-bold text-white">Web Raptor</h2>
                <p className="text-xs text-gray-400">by Trojen Hex</p>
              </div>
            </div>
            <Button variant="ghost" size="sm" onClick={onClose} className="focus-ring">
              <X className="h-5 w-5" />
            </Button>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6">
            {/* Status Section */}
            <div className="space-y-4">
              <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">System Status</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="status-dot status-online"></div>
                    <span className="text-white">Platform Status</span>
                  </div>
                  <Badge className="bg-green-500/10 text-green-400 border-green-500/20">Online</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Cpu className="h-4 w-4 text-blue-400" />
                    <span className="text-white">AI Enhancement</span>
                  </div>
                  <Badge className="bg-blue-500/10 text-blue-400 border-blue-500/20">Ready</Badge>
                </div>
              </div>
            </div>

            {/* Features Section */}
            <div className="space-y-4">
              <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Features</h3>
              <div className="space-y-3">
                <div className="flex items-center gap-3 p-3 rounded-lg bg-white/5">
                  <Shield className="h-5 w-5 text-green-400" />
                  <div>
                    <div className="text-white font-medium">Web Reconnaissance</div>
                    <div className="text-xs text-gray-400">Comprehensive analysis</div>
                  </div>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-white/5">
                  <Activity className="h-5 w-5 text-blue-400" />
                  <div>
                    <div className="text-white font-medium">Real-time Intel</div>
                    <div className="text-xs text-gray-400">Live threat analysis</div>
                  </div>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-white/5">
                  <Wifi className="h-5 w-5 text-purple-400" />
                  <div>
                    <div className="text-white font-medium">Multi-Source</div>
                    <div className="text-xs text-gray-400">Comprehensive data</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Quick Actions */}
            <div className="space-y-4">
              <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Quick Actions</h3>
              <div className="space-y-2">
                <Button
                  variant="ghost"
                  className="w-full justify-start text-left focus-ring"
                  onClick={() => {
                    document.getElementById("target")?.focus()
                    onClose()
                  }}
                >
                  Start New Analysis
                </Button>
                <Button variant="ghost" className="w-full justify-start text-left focus-ring" onClick={onClose}>
                  View Documentation
                  <ExternalLink className="h-4 w-4 ml-auto" />
                </Button>
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="p-6 border-t border-white/10">
            <div className="flex items-center justify-center gap-4">
              <Button variant="ghost" size="sm" className="focus-ring">
                <Github className="h-4 w-4" />
              </Button>
              <Button variant="ghost" size="sm" className="focus-ring">
                <Mail className="h-4 w-4" />
              </Button>
            </div>
            <p className="text-xs text-gray-500 text-center mt-3">© 2024 Trojen Hex. All rights reserved.</p>
          </div>
        </div>
      </div>
    </div>
  )
}
