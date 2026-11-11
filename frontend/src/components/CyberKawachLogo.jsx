import React from 'react';

/**
 * CyberKawachLogo — Sovereign Threat Defense Emblem
 * 
 * Handcrafted vector SVG emblem:
 * - Faceted cyber shield geometry with emerald gradient depth
 * - Inner neural defense node with glowing radial core
 * - Precision lines that scale flawlessly from 24px to 128px
 * - Zero raster clipping or aspect-ratio distortion
 */
export default function CyberKawachLogo({
  size = 'md',
  showText = false,
  subtitle = 'National Threat Triage',
  className = '',
  onClick = null
}) {
  const sizeMap = {
    xs: { box: 'w-7 h-7', svg: 28, text: 'text-xs', sub: 'text-[9px]' },
    sm: { box: 'w-8 h-8', svg: 32, text: 'text-sm', sub: 'text-[10px]' },
    md: { box: 'w-10 h-10', svg: 40, text: 'text-base', sub: 'text-[11px]' },
    lg: { box: 'w-12 h-12', svg: 48, text: 'text-lg', sub: 'text-xs' },
    xl: { box: 'w-16 h-16', svg: 64, text: 'text-xl', sub: 'text-xs' },
  };

  const currentSize = sizeMap[size] || sizeMap.md;

  return (
    <div 
      className={`inline-flex items-center gap-3 select-none ${onClick ? 'cursor-pointer' : ''} ${className}`}
      onClick={onClick}
    >
      {/* Emblem Badge Container */}
      <div 
        className={`relative ${currentSize.box} rounded-xl flex items-center justify-center flex-shrink-0 bg-slate-900 dark:bg-slate-950 border border-emerald-500/30 dark:border-emerald-500/40 shadow-sm shadow-emerald-950/20 group hover:border-emerald-400/80 transition-all duration-300 p-1.5`}
      >
        <svg 
          viewBox="0 0 44 44" 
          className="w-full h-full drop-shadow-sm group-hover:scale-105 transition-transform duration-300" 
          fill="none" 
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            {/* Outer Shield Gradient */}
            <linearGradient id="ckShieldGrad" x1="22" y1="2" x2="22" y2="42" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#047857" />
              <stop offset="45%" stopColor="#065f46" />
              <stop offset="100%" stopColor="#022c22" />
            </linearGradient>

            {/* Facet Light Gradient */}
            <linearGradient id="ckFacetLight" x1="6" y1="6" x2="38" y2="38" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#34d399" stopOpacity="0.8" />
              <stop offset="50%" stopColor="#10b981" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#059669" stopOpacity="0.1" />
            </linearGradient>

            {/* Glowing Core Radial */}
            <radialGradient id="ckCoreGlow" cx="22" cy="22" r="12" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#6ee7b7" />
              <stop offset="40%" stopColor="#10b981" />
              <stop offset="100%" stopColor="#047857" stopOpacity="0" />
            </radialGradient>

            {/* Sovereign Tricolor Accent */}
            <linearGradient id="ckSovereign" x1="14" y1="5" x2="30" y2="5" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#FF9933" />
              <stop offset="50%" stopColor="#FFFFFF" />
              <stop offset="100%" stopColor="#138808" />
            </linearGradient>
          </defs>

          {/* Outer Shield Armor Silhouette */}
          <path 
            d="M22 3.5 L37 8.5 V21.5 C37 31.5 30.5 38.5 22 41.5 C13.5 38.5 7 31.5 7 21.5 V8.5 L22 3.5 Z" 
            fill="url(#ckShieldGrad)" 
            stroke="#10b981" 
            strokeWidth="1.8" 
            strokeLinejoin="round" 
          />

          {/* Right-Side Faceted Shading for 3D Depth */}
          <path 
            d="M22 4 L36.5 8.8 V21.5 C36.5 31.2 30.2 38 22 41 V4 Z" 
            fill="#022c22" 
            fillOpacity="0.45" 
          />

          {/* Left-Side Specular Highlight */}
          <path 
            d="M22 4 L7.5 8.8 V21.5 C7.5 31.2 13.8 38 22 41 V4 Z" 
            fill="url(#ckFacetLight)" 
            fillOpacity="0.25" 
          />

          {/* Inner Geometric Shield Border */}
          <path 
            d="M22 8 L33 12 V21 C33 28.5 28 34.5 22 37 C16 34.5 11 28.5 11 21 V12 L22 8 Z" 
            stroke="#34d399" 
            strokeWidth="1" 
            strokeOpacity="0.4" 
            strokeDasharray="2 1.5"
            fill="none" 
          />

          {/* Central Cyber Node Hexagon */}
          <polygon 
            points="22,14.5 28,18 28,25 22,28.5 16,25 16,18" 
            fill="#022c22" 
            stroke="#10b981" 
            strokeWidth="1.4" 
          />

          {/* Interlocking Defense Circuit / Chakra Spokes */}
          <line x1="22" y1="14.5" x2="22" y2="28.5" stroke="#34d399" strokeWidth="1" strokeOpacity="0.6" />
          <line x1="16" y1="18" x2="28" y2="25" stroke="#34d399" strokeWidth="1" strokeOpacity="0.6" />
          <line x1="16" y1="25" x2="28" y2="18" stroke="#34d399" strokeWidth="1" strokeOpacity="0.6" />

          {/* Pulsing Core Defense Jewel */}
          <circle cx="22" cy="21.5" r="4.5" fill="url(#ckCoreGlow)" />
          <circle cx="22" cy="21.5" r="2.2" fill="#ffffff" />
          <circle cx="22" cy="21.5" r="1.1" fill="#065f46" />

          {/* Sovereign Apex Ribbon Micro-Pip */}
          <rect x="19.5" y="4" width="5" height="1.8" rx="0.9" fill="url(#ckSovereign)" />
        </svg>
      </div>

      {/* Brand Text */}
      {showText && (
        <div className="flex flex-col min-w-0 leading-tight">
          <div className="flex items-center gap-1.5">
            <span className={`${currentSize.text} font-black tracking-tight text-slate-900 dark:text-white uppercase`}>
              CYBER<span className="text-emerald-600 dark:text-emerald-400">KAWACH</span>
            </span>
          </div>
          {subtitle && (
            <span className={`${currentSize.sub} text-slate-500 dark:text-slate-400 font-medium truncate`}>
              {subtitle}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
