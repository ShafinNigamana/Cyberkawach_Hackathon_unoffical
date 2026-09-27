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
        brand: {
          charcoal: '#0F172A',
          navy: '#1E293B',
          slate: '#334155',
          border: '#E2E8F0',
          darkborder: '#1E293B',
          surface: '#FFFFFF',
          darksurface: '#0F172A',
        },
        alert: {
          red: '#DC2626',
          darkred: '#991B1B',
          lightred: '#FEF2F2',
        },
      },
      fontFamily: {
        sans: ['Plus Jakarta Sans', 'Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      borderRadius: {
        chip: '6px',
        btn: '8px',
        card: '10px',
        badge: '4px',
      },
      boxShadow: {
        card: '0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1)',
        'card-elevated': '0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1)',
        'gov-focus': '0 0 0 3px rgba(212, 175, 55, 0.35)',
      },
    },
  },
  plugins: [],
}
