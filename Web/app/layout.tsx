import type React from "react"
import type { Metadata } from "next"
import { ThemeProvider } from "@/components/theme-provider"
import "./globals.css"

export const metadata: Metadata = {
  title: "Web Raptor | Web Reconnaissance Platform & Threat Intelligence",
  description:
    "Professional-grade web reconnaissance and threat intelligence platform developed by Trojen Hex. Comprehensive domain analysis, network intelligence, and security assessment tools.",
  keywords: ["OSINT", "reconnaissance", "cybersecurity", "threat intelligence", "security analysis", "domain analysis"],
  authors: [{ name: "Trojen Hex", url: "https://trojenhex.com" }],
  creator: "Trojen Hex",
  publisher: "Trojen Hex",
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://web-raptor.vercel.app",
    title: "Web Raptor | Web Reconnaissance Platform",
    description: "Web reconnaissance and threat intelligence platform for cybersecurity professionals",
    siteName: "Web Raptor",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "Web Raptor OSINT Platform",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Web Raptor | Web Reconnaissance Platform",
    description: "Web reconnaissance and threat intelligence platform",
    images: ["/og-image.png"],
    creator: "@trojenhex",
  },
  viewport: {
    width: "device-width",
    initialScale: 1,
    maximumScale: 5,
  },
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "white" },
    { media: "(prefers-color-scheme: dark)", color: "#0f172a" },
  ],
    generator: 'v0.dev'
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/favicon.ico" sizes="any" />
        <link rel="icon" href="/icon.svg" type="image/svg+xml" />
        <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
        <link rel="manifest" href="/manifest.json" />
        <meta name="theme-color" content="#0f172a" />
        <meta name="color-scheme" content="dark light" />
      </head>
      <body className="min-h-screen bg-background font-sans antialiased">
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem disableTransitionOnChange>
          {children}
        </ThemeProvider>
      </body>
    </html>
  )
}
