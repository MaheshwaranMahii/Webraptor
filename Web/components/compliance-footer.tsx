import { Card, CardContent } from "@/components/ui/card"

export function ComplianceFooter() {
  return (
    <Card className="bg-slate-800/30 border-slate-700 mt-8">
      <CardContent className="p-6">
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center gap-2">
            <img
              src="/shuriken-logo.svg"
              alt="Trojen Hex logo"
              className="h-6 w-6"
              style={{
                filter:
                  "brightness(0) saturate(100%) invert(70%) sepia(98%) saturate(1000%) hue-rotate(180deg) brightness(95%) contrast(101%)",
              }}
            />
            <h3 className="text-lg font-semibold text-slate-200">Trojen Hex</h3>
          </div>

          <div className="text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
            <p className="mb-2">
              <strong className="text-slate-300">Web Raptor</strong> - Web Reconnaissance Platform and threat
              intelligence solution developed by Trojen Hex. Our cutting-edge cybersecurity tools provide comprehensive
              domain analysis and network intelligence for security professionals.
            </p>
            <p>
              Leveraging multiple intelligence sources to deliver actionable security insights and defensive
              capabilities for modern cybersecurity operations.
            </p>
          </div>

          <div className="text-xs text-slate-500 space-y-1">
            <div>Web Raptor v2.0 | Web Reconnaissance Platform</div>
            <div className="flex items-center justify-center gap-2">
              <span>Developed by</span>
              <span className="text-cyan-400 font-semibold">Trojen Hex</span>
              <img
                src="/shuriken-logo.svg"
                alt="Trojen Hex logo"
                className="h-3 w-3 inline-block"
                style={{
                  filter:
                    "brightness(0) saturate(100%) invert(70%) sepia(98%) saturate(1000%) hue-rotate(180deg) brightness(95%) contrast(101%)",
                }}
              />
              <span>| Contact: maheshwaranofficial31999@gmail.com</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
