"use client"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Info, Zap, Shield } from "lucide-react"

export function AIStatusNotice() {
  return (
    <Alert className="bg-blue-900/20 border-blue-500/50 animate-fade-in">
      <Info className="h-4 w-4" />
      <AlertDescription className="text-blue-200">
        <div className="flex items-start gap-2">
          <div className="flex-1">
            <strong className="text-blue-100">Enhanced Analysis Available:</strong> Web Raptor features both AI-enhanced
            and automated analysis modes. Our automated analysis engine provides comprehensive threat intelligence even
            when AI enhancement is temporarily unavailable.
          </div>
          <div className="flex gap-1">
            <Zap className="h-4 w-4 text-yellow-400" />
            <Shield className="h-4 w-4 text-green-400" />
          </div>
        </div>
      </AlertDescription>
    </Alert>
  )
}
