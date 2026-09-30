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
        // Neo-Fintech Luxury Color System
        night: {
          950: '#060A13', // deepest background
          900: '#0A0F1D', // main dark background
          850: '#0F172A', // midnight sapphire surface
          800: '#141E33', // elevated card surface
          750: '#1B2742', // hover surface
          700: '#233252', // border highlight
          border: '#1E2C4A',
          subtle: '#2A3C63',
        },
        luxury: {
          violet: '#8B5CF6',
          indigo: '#6366F1',
          purple: '#A855F7',
          deepViolet: '#7C3AED',
          deepIndigo: '#4F46E5',
          gold: '#F59E0B',
          amber: '#D97706',
          emerald: '#10B981',
          rose: '#F43F5E',
          cyan: '#06B6D4',
          ice: '#F8FAFC',
        },
        brand: {
          charcoal: '#0F172A',
          navy: '#141E33',
          slate: '#334155',
          border: '#E2E8F0',
          darkborder: '#1E2C4A',
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
        btn: '10px',
        card: '16px',
        badge: '6px',
      },
      boxShadow: {
        card: '0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05)',
        'card-elevated': '0 8px 30px -4px rgba(15, 23, 42, 0.08), 0 2px 6px -1px rgba(15, 23, 42, 0.04)',
        'luxury-glow': '0 0 35px -5px rgba(124, 58, 237, 0.25)',
        'sapphire-glow': '0 0 35px -5px rgba(99, 102, 241, 0.22)',
        'emerald-glow': '0 0 30px -5px rgba(16, 185, 129, 0.25)',
        'rose-glow': '0 0 30px -5px rgba(244, 63, 94, 0.25)',
        'gov-focus': '0 0 0 3px rgba(139, 92, 246, 0.35)',
      },
    },
  },
  plugins: [],
}
