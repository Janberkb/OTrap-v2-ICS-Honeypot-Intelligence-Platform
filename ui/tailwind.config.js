const colorVar = (name) => `rgb(var(${name}) / <alpha-value>)`;

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // ── OTrap Theme Tokens (resolved from CSS preset vars) ─────────────
        bg: {
          base:     colorVar("--bg-base"),
          surface:  colorVar("--bg-surface"),
          elevated: colorVar("--bg-elevated"),
          border:   colorVar("--bg-border"),
        },
        accent: {
          DEFAULT:   colorVar("--accent"),
          hover:     colorVar("--accent-hover"),
          muted:     colorVar("--accent-muted"),
          secondary: colorVar("--accent-secondary"),
        },
        severity: {
          critical: colorVar("--severity-critical"),
          high:     colorVar("--severity-high"),
          medium:   colorVar("--severity-medium"),
          low:      colorVar("--severity-low"),
          noise:    colorVar("--severity-noise"),
        },
        text: {
          primary: colorVar("--text-primary"),
          muted:   colorVar("--text-muted"),
          faint:   colorVar("--text-faint"),
        },
      },
      fontFamily: {
        sans: ["Space Grotesk", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "slide-in":   "slideIn 0.2s ease-out",
        "fade-in":    "fadeIn 0.3s ease-out",
      },
      keyframes: {
        slideIn: {
          "0%":   { transform: "translateY(-8px)", opacity: "0" },
          "100%": { transform: "translateY(0)",    opacity: "1" },
        },
        fadeIn: {
          "0%":   { opacity: "0" },
          "100%": { opacity: "1" },
        },
      },
    },
  },
  plugins: [],
};
