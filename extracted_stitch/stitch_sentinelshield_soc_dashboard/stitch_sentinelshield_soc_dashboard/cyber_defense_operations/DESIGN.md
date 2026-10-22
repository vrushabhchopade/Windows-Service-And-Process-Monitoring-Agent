---
name: Cyber Defense Operations
colors:
  surface: '#0b1326'
  surface-dim: '#0b1326'
  surface-bright: '#31394d'
  surface-container-lowest: '#060e20'
  surface-container-low: '#131b2e'
  surface-container: '#171f33'
  surface-container-high: '#222a3d'
  surface-container-highest: '#2d3449'
  on-surface: '#dae2fd'
  on-surface-variant: '#c2c6d6'
  inverse-surface: '#dae2fd'
  inverse-on-surface: '#283044'
  outline: '#8c909f'
  outline-variant: '#424754'
  surface-tint: '#adc6ff'
  primary: '#adc6ff'
  on-primary: '#002e6a'
  primary-container: '#4d8eff'
  on-primary-container: '#00285d'
  inverse-primary: '#005ac2'
  secondary: '#4cd7f6'
  on-secondary: '#003640'
  secondary-container: '#03b5d3'
  on-secondary-container: '#00424e'
  tertiary: '#d0bcff'
  on-tertiary: '#3c0091'
  tertiary-container: '#a078ff'
  on-tertiary-container: '#340080'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#d8e2ff'
  primary-fixed-dim: '#adc6ff'
  on-primary-fixed: '#001a42'
  on-primary-fixed-variant: '#004395'
  secondary-fixed: '#acedff'
  secondary-fixed-dim: '#4cd7f6'
  on-secondary-fixed: '#001f26'
  on-secondary-fixed-variant: '#004e5c'
  tertiary-fixed: '#e9ddff'
  tertiary-fixed-dim: '#d0bcff'
  on-tertiary-fixed: '#23005c'
  on-tertiary-fixed-variant: '#5516be'
  background: '#0b1326'
  on-background: '#dae2fd'
  surface-variant: '#2d3449'
typography:
  headline-xl:
    fontFamily: Inter
    fontSize: 36px
    fontWeight: '700'
    lineHeight: 44px
    letterSpacing: -0.02em
  headline-xl-mobile:
    fontFamily: Inter
    fontSize: 28px
    fontWeight: '700'
    lineHeight: 36px
    letterSpacing: -0.01em
  headline-lg:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
  headline-sm:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '600'
    lineHeight: 24px
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
  code-lg:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 14px
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '600'
    lineHeight: 16px
    letterSpacing: 0.05em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.08em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  margin: 1.5rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1rem
  space-xl: 1.5rem
---

## Brand & Style

This design system is engineered for Tier-2 and Tier-3 Security Operations Center (SOC) analysts, incident responders, and threat hunters operating in mission-critical environments. The visual language balances tactical clarity, high-density data parsing, and low ocular fatigue during extended night-shift operations.

The aesthetic fuses **Modern Technical Corporate** with **High-Precision HUD Glassmorphism**. UI elements are crisp, disciplined, and strictly hierarchical. Translucent surface containers with micro-borders provide clear structural delineation, while calibrated neon status glows direct cognitive focus immediately to high-severity anomalies, active exploits, and incoming telemetry vectors.

## Colors

The palette operates on a calibrated dark-spectrum architecture:

- **Base Canvas & Surfaces**: Deep void navy (`#0B0F19`) establishes the root ground. Primary working surfaces utilize rich slate navy (`#0F172A`), elevated containers sit on charcoal slate (`#111827`), and top-level floating elements use deep charcoal (`#1E293B`).
- **Borders & Dividers**: Structural boundaries utilize crisp slate borders (`#1E293B`) for standard grouping and `#334155` for active, interactive, or highlighted boundaries.
- **Signal Accents**: Electric Blue (`#3B82F6`) drives core interactions, focus states, and primary system controls. Vibrant Cyan (`#06B6D4`) designates real-time streams, automated agent telemetry, and active packet queries. Vivid Purple (`#8B5CF6`) denotes deep packet inspection heuristics, behavioral AI models, and ruleset triggers.
- **SOC Threat Severity Scale**:
  - **Critical / Exploit Detected**: Crimson Red (`#EF4444`) with optional 12px blur halo.
  - **High / Anomalous Infiltration**: Bright Orange (`#F97316`).
  - **Medium / Warning**: Amber Yellow (`#F59E0B`).
  - **Safe / Resolved / Normal**: Emerald Green (`#10B981`).
  - **Informational / Audited**: Slate Muted (`#64748B`).

## Typography

Typography enforces a strict functional split:

1. **Interface Layer (`Inter`)**: Governs structural titles, navigation links, panel headings, modal copy, and explanatory body text. Inter’s neutral, geometric aperture ensures effortless scanning at compressed line heights.
2. **Telemetry & Artifact Layer (`JetBrains Mono`)**: Mandatory for all cryptographic hashes (SHA-256/MD5), IPv4/IPv6 addresses, payload strings, raw ingress/egress rules, CIDR blocks, port tuples, SIEM timestamps, and dynamic key performance metrics. JetBrains Mono prevents character confusion (e.g., `0` vs `O`, `1` vs `l`) during high-pressure threat mitigation.

## Layout & Spacing

The architecture operates on an ultra-compact 4px grid optimized for high-density multi-monitor command walls and enterprise workstations:

- **Desktop (1440px+)**: 12-column or 24-column flexible grid with 16px (`1rem`) gutters and 24px (`1.5rem`) outer canvas margins. Allows concurrent live streams: threat feeds, topology graphs, and incident inspection drawers side-by-side.
- **Tablet (768px - 1439px)**: 8-column layout. Sidebar navigation collapses to iconic rail. Metric widgets wrap into two-column cards.
- **Mobile (< 768px)**: 4-column layout with 12px gutters. Telemetry tables convert into horizontally swipeable cards or prioritized stacked lists with monospace values docked to the right boundary.
- **Component Density**: Inner panel padding standardizes to `space-md` (12px) and `space-lg` (16px) to maximize screen real estate and minimize viewport scrolling.

## Elevation & Depth

Visual depth is achieved through structural layering, glassmorphism, and colored glow diffusions rather than traditional drop shadows:

- **Ground Layer (Canvas)**: `#0B0F19` solid.
- **Layer 1 (Card / Grid Module)**: Background `rgba(15, 23, 42, 0.75)`, backdrop blur of `12px`, with a crisp 1px stroke of `#1E293B`.
- **Layer 2 (Hover / Active Cards / Dropdowns)**: Background `rgba(30, 41, 59, 0.85)`, backdrop blur of `16px`, stroke `#334155`.
- **Layer 3 (Modals / Alert Drawers / Flying Overlays)**: Background `rgba(17, 24, 39, 0.95)`, backdrop blur of `20px`, stroke `#3B82F6` (30% opacity), with an ambient shadow `0 20px 40px -15px rgba(0, 0, 0, 0.7)`.
- **Tactical Halos (Telemetry Alerts)**:
  - Critical Severity: Inner/outer glow `0 0 12px rgba(239, 68, 68, 0.35)`.
  - Active Scanning / Sync: Pulsing outer glow `0 0 10px rgba(6, 182, 212, 0.3)`.
  - Heuristic Engine Active: Border glow `0 0 8px rgba(139, 92, 246, 0.25)`.

## Shapes

The interface embraces a technical, calibrated corner radius. All interactive elements, status badges, telemetry pods, and metric cards utilize a strict soft radius (`roundedness: 1` = `0.25rem` / `4px`).

- Standard containers, buttons, inputs, and chips use `4px` borders to reinforce military-grade precision and avoid wasted corner space.
- Floating modal dialogs and outer slide-over drawers expand to `rounded-lg` (`0.5rem` / `8px`).
- Circular geometry (`rounded-full`) is strictly reserved for live pulse dots, node connection vertices on topology diagrams, and user avatars.

## Components

### Buttons & Interactive Triggers
- **Primary Action (Mitigate / Deploy Rule)**: Background `#3B82F6`, text `#FFFFFF`, font `Inter` 600. On hover, background `#2563EB` with `0 0 12px rgba(59, 130, 246, 0.5)` glow.
- **Critical Action (Isolate Host / Sever Connection)**: Background `#EF4444`, text `#FFFFFF`. Hover `#DC2626` with `0 0 14px rgba(239, 68, 68, 0.6)`.
- **Secondary / Ghost (Filter / Export Log)**: Background `rgba(30, 41, 59, 0.5)`, border `1px solid #334155`, text `#E2E8F0`. Hover brings border to `#3B82F6` and text to `#FFFFFF`.

### Telemetry Badges & Severity Chips
- Built with `JetBrains Mono` label-sm (`10px`), uppercase with `0.08em` tracking.
- Padding: 2px vertical, 6px horizontal. Border radius `4px`.
- **Critical**: Background `rgba(239, 68, 68, 0.15)`, text `#FCA5A5`, border `1px solid rgba(239, 68, 68, 0.4)`. Includes a 6px blinking red indicator dot.
- **High**: Background `rgba(249, 115, 22, 0.15)`, text `#FDBA74`, border `1px solid rgba(249, 115, 22, 0.4)`.
- **Medium**: Background `rgba(245, 158, 11, 0.15)`, text `#FDE68A`, border `1px solid rgba(245, 158, 11, 0.4)`.
- **Safe / Resolved**: Background `rgba(16, 185, 129, 0.15)`, text `#6EE7B7`, border `1px solid rgba(16, 185, 129, 0.4)`.

### Data Tables & Log Feeds
- Fixed header with background `#0B0F19`, bottom border `1px solid #334155`.
- Alternating row background: odd rows `transparent`, even rows `rgba(15, 23, 42, 0.3)`.
- Row height: condensed `36px` to display maximum events per viewport.
- Interactive state: hovering a row highlights background with `rgba(59, 130, 246, 0.08)` and illuminates a 2px left border marker in Electric Blue.
- Cell formatting: IP addresses, Ports, Hashes, and Timestamps formatted in `code-md` (`JetBrains Mono`).

### Input Fields & Query Consoles
- Background `rgba(11, 15, 25, 0.8)`, border `1px solid #1E293B`, radius `4px`.
- Text color `#F8FAFC`, placeholder `#475569`.
- Focus state: border `#3B82F6`, outline `none`, box-shadow `0 0 0 1px #3B82F6, 0 0 8px rgba(59, 130, 246, 0.3)`.
- Syntax highlighting for KQL/SPL search bars: keywords in Cyan (`#06B6D4`), operators in Purple (`#8B5CF6`), strings in Emerald (`#10B981`).

### Form Controls (Checkboxes, Toggles, Radio)
- **Checkboxes & Radios**: 16x16px frame with `1px solid #334155` on `#0F172A`. Checked state: `#3B82F6` fill with white checkmark and subtle neon blur.
- **Firewall Rule Switch**: 32x18px pill track. Inactive track `#1E293B`; active track `#10B981`. Thumb is `14px` solid `#FFFFFF`.

### Cards & Analytical Panels
- Glass-backed container with 1px border `#1E293B`.
- Header bar features metric title in `Inter` body-sm muted (`#94A3B8`) paired with real-time refresh rate in `JetBrains Mono` label-sm (`#06B6D4`).
- Footer actions allow one-click query drill-down and log expansion.