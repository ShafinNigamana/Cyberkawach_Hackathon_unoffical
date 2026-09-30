/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Institutional Color System — trust-first, government-grade
        surface: {
          DEFAULT: '#FFFFFF',
          secondary: '#F8FAFC',
          dark: '#0B0F1A',
          'dark-elevated': '#131825',
          'dark-hover': '#1A2035',
        },
        accent: {
          DEFAULT: '#059669',  // Emerald — safety, verified, government
          hover: '#047857',
          light: '#ECFDF5',
          muted: '#D1FAE5',
          dark: '#065F46',
        },
        border: {
          DEFAULT: '#E2E8F0',
          dark: '#1E293B',
          subtle: '#F1F5F9',
        },
        status: {
          safe: '#059669',
          warning: '#D97706',
          danger: '#DC2626',
          critical: '#991B1B',
          info: '#0284C7',
        },
      },
      fontFamily: {
        sans: ['Plus Jakarta Sans', 'Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      borderRadius: {
        chip: '6px',
        btn: '10px',
        card: '14px',
        badge: '6px',
      },
      boxShadow: {
        'card': '0 1px 3px 0 rgba(0, 0, 0, 0.04), 0 1px 2px -1px rgba(0, 0, 0, 0.03)',
        'card-elevated': '0 4px 16px -4px rgba(15, 23, 42, 0.06), 0 1px 3px -1px rgba(15, 23, 42, 0.03)',
        'card-hover': '0 8px 24px -6px rgba(15, 23, 42, 0.08), 0 2px 6px -2px rgba(15, 23, 42, 0.04)',
      },
    },
  },
  plugins: [],
}
