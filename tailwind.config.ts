import type { Config } from 'tailwindcss'
import plugin from 'tailwindcss/plugin'

/**
 * Cova Vault design tokens.
 *
 * Colours are declared as CSS custom properties in `src/index.css` and
 * referenced here through the `rgb(var(--token-rgb) / <alpha-value>)` pattern
 * so Tailwind can apply opacity modifiers to any token.
 */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  // Dark is the default theme; `html.light` opts into the light palette.
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cova: {
          bg: 'rgb(var(--cova-bg-rgb) / <alpha-value>)',
          surface: 'rgb(var(--cova-surface-rgb) / <alpha-value>)',
          elevated: 'rgb(var(--cova-elevated-rgb) / <alpha-value>)',
          border: 'rgb(var(--cova-border-rgb) / <alpha-value>)',
          primary: 'rgb(var(--cova-primary-rgb) / <alpha-value>)',
          'primary-hover': 'rgb(var(--cova-primary-hover-rgb) / <alpha-value>)',
          accent: 'rgb(var(--cova-accent-rgb) / <alpha-value>)',
          violet: 'rgb(var(--cova-violet-rgb) / <alpha-value>)',
          text: 'rgb(var(--cova-text-rgb) / <alpha-value>)',
          muted: 'rgb(var(--cova-muted-rgb) / <alpha-value>)',
          faint: 'rgb(var(--cova-faint-rgb) / <alpha-value>)',
        },
      },
      fontFamily: {
        // Segoe UI Variable ships with Windows 11; fall back gracefully.
        sans: [
          '"Segoe UI Variable Text"',
          '"Segoe UI Variable"',
          '"Segoe UI"',
          'system-ui',
          '-apple-system',
          'BlinkMacSystemFont',
          '"Helvetica Neue"',
          'Arial',
          'sans-serif',
        ],
      },
      borderRadius: {
        btn: '0.625rem',
        card: '0.875rem',
        panel: '1rem',
        badge: '9999px',
      },
      boxShadow: {
        card: 'var(--cova-shadow-card)',
        glow: 'var(--cova-shadow-glow)',
      },
      backgroundImage: {
        'cova-gradient': 'var(--cova-gradient)',
      },
      letterSpacing: {
        tightest: '-0.03em',
      },
    },
  },
  plugins: [
    // `light:` variant - the light palette is applied via an `html.light` class.
    plugin(({ addVariant }) => {
      addVariant('light', 'html.light &')
    }),
  ],
} satisfies Config
