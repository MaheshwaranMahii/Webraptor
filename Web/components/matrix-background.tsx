"use client"

import { useEffect, useRef } from "react"

export function MatrixBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext("2d")
    if (!ctx) return

    // Set canvas size
    const resizeCanvas = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }

    resizeCanvas()
    window.addEventListener("resize", resizeCanvas)

    // Matrix characters
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+-=[]{}|;:,.<>?"
    const charArray = chars.split("")

    const fontSize = 14
    const columns = canvas.width / fontSize

    // Array to store y position of each column
    const drops: number[] = []
    for (let i = 0; i < columns; i++) {
      drops[i] = 1
    }

    // Animation function
    const draw = () => {
      // Black background with slight transparency for trail effect
      ctx.fillStyle = "rgba(0, 0, 0, 0.05)"
      ctx.fillRect(0, 0, canvas.width, canvas.height)

      // Cyan text
      ctx.fillStyle = "rgba(34, 211, 238, 0.8)"
      ctx.font = `${fontSize}px monospace`

      // Loop through drops
      for (let i = 0; i < drops.length; i++) {
        // Random character
        const text = charArray[Math.floor(Math.random() * charArray.length)]

        // Draw character
        ctx.fillText(text, i * fontSize, drops[i] * fontSize)

        // Reset drop to top randomly
        if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
          drops[i] = 0
        }

        // Increment y position
        drops[i]++
      }
    }

    // Start animation
    const interval = setInterval(draw, 50)

    return () => {
      clearInterval(interval)
      window.removeEventListener("resize", resizeCanvas)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-0 opacity-20"
      style={{ background: "transparent" }}
    />
  )
}
