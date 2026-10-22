---
name: Midnight Protocol
colors:
  surface: '#051424'
  surface-dim: '#051424'
  surface-bright: '#2c3a4c'
  surface-container-lowest: '#010f1f'
  surface-container-low: '#0d1c2d'
  surface-container: '#122131'
  surface-container-high: '#1c2b3c'
  surface-container-highest: '#273647'
  on-surface: '#d4e4fa'
  on-surface-variant: '#bac9cc'
  inverse-surface: '#d4e4fa'
  inverse-on-surface: '#233143'
  outline: '#849396'
  outline-variant: '#3b494c'
  surface-tint: '#00daf3'
  primary: '#c3f5ff'
  on-primary: '#00363d'
  primary-container: '#00e5ff'
  on-primary-container: '#00626e'
  inverse-primary: '#006875'
  secondary: '#b0c6ff'
  on-secondary: '#002d6e'
  secondary-container: '#0068ed'
  on-secondary-container: '#f2f3ff'
  tertiary: '#efecec'
  on-tertiary: '#313030'
  tertiary-container: '#d3d0cf'
  on-tertiary-container: '#5a5959'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#9cf0ff'
  primary-fixed-dim: '#00daf3'
  on-primary-fixed: '#001f24'
  on-primary-fixed-variant: '#004f58'
  secondary-fixed: '#d9e2ff'
  secondary-fixed-dim: '#b0c6ff'
  on-secondary-fixed: '#001945'
  on-secondary-fixed-variant: '#00429b'
  tertiary-fixed: '#e5e2e1'
  tertiary-fixed-dim: '#c8c6c5'
  on-tertiary-fixed: '#1c1b1b'
  on-tertiary-fixed-variant: '#474646'
  background: '#051424'
  on-background: '#d4e4fa'
  surface-variant: '#273647'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '700'
    lineHeight: '1.2'
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: '1.3'
  title-sm:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: '1.4'
  body-main:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: '1.5'
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: '1.5'
  code-data:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: '1.4'
    letterSpacing: -0.01em
  label-caps:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '700'
    lineHeight: '1'
    letterSpacing: 0.05em
spacing:
  base-unit: 4px
  container-padding: 24px
  widget-gap: 16px
  row-height-dense: 32px
  row-height-standard: 48px
---

## Brand & Style

The design system is engineered for high-stakes environments where split-second decision-making is paramount. It utilizes a **Midnight Corporate** aesthetic—a blend of systematic professionalism and high-tech utility. 

The target audience consists of Security Operations Center (SOC) analysts and network administrators who require prolonged focus without eye strain. The UI evokes a sense of authority, precision, and vigilance. By utilizing a "Midnight" dark mode with sharp, geometric boundaries, the design system minimizes visual noise and prioritizes data density. The emotional response is one of controlled urgency; the interface feels like a high-performance instrument rather than a consumer application.

## Colors

The palette is anchored by a "Midnight" foundation (`#020617`), providing a deep, low-light base that makes neon accents pop with high legibility. 

- **Primary & Secondary:** Cyan (`#00E5FF`) and Blue (`#2979FF`) serve as the functional identifiers for interactive elements and active states. 
- **Status Indicators:** Use the high-visibility triad—Critical Red, Warning Amber, and Success Green. These must be used sparingly but boldly to draw immediate attention to system anomalies.
- **Surface Strategy:** Use nested shades of navy and charcoal to create "modular" containers, ensuring that data-heavy panels are visually distinct from the global background.

## Typography

This design system utilizes **Inter** for its neutral, systematic clarity and high legibility at small sizes. For technical data strings (IP addresses, hashes, logs), **JetBrains Mono** is introduced to provide a distinct visual "texture" that identifies raw data.

- **Scale:** Maintain a tight typographic scale to maximize information density.
- **Hierarchy:** Use `label-caps` for table headers and section metadata to differentiate structural labels from live data.
- **Mobile:** On smaller viewports, `display-lg` scales down to 24px to maintain readability within compact card structures.

## Layout & Spacing

The layout follows a **Fixed-Fluid Hybrid Grid**. Sidebars and inspector panels occupy fixed widths (280px and 360px respectively), while the central dashboard area uses a 12-column fluid grid.

- **Density:** Use a 4px baseline grid. Data tables should utilize "dense" row heights (32px) to allow for 20+ records to be visible above the fold.
- **Modular Blocks:** Dashboards are composed of "Widgets." Each widget must have a consistent 16px internal padding and be separated by a 16px gutter.
- **Breakpoints:**
  - Desktop: 1280px+ (Full multi-column SOC view)
  - Tablet: 768px - 1279px (Stacking widgets, 2 columns)
  - Mobile: <767px (Single column, navigation collapses to bottom bar)

## Elevation & Depth

This design system avoids heavy shadows in favor of **Tonal Layering and Sharp Borders**.

- **Level 0 (Background):** Base `#020617`.
- **Level 1 (Panels/Widgets):** Surface `#0F172A` with a 1px solid border of `#1E293B`.
- **Level 2 (Popovers/Modals):** Surface `#1E293B` with a subtle 8px blur shadow (0% offset, `#000000` at 40% opacity) and a `#2979FF` accent border.
- **Active State:** Elements being hovered or focused should receive a subtle cyan outer glow (`box-shadow: 0 0 8px rgba(0, 229, 255, 0.3)`).

## Shapes

The design system employs a **Sharp (0px)** corner radius for all primary containers, buttons, and input fields. This reinforces the "military-grade" and precise nature of the software. 

Internal elements like status pips or circular avatars may use a 100% radius (circles), but all structural UI components must remain strictly rectangular. This allows for seamless "tiling" of data widgets without awkward gaps created by rounded corners.

## Components

- **Buttons:** Sharp-edged. Primary buttons use a solid Cyan background with black text for maximum contrast. Ghost buttons use Cyan borders and text.
- **Status Indicators:** "Pills" or "Glow Dots." A critical alert uses a Red dot with a subtle CSS pulse animation to signal urgency.
- **Data Tables:** Zebra striping is discouraged. Use 1px bottom borders in `#1E293B`. Hovered rows should highlight in `#1E293B`.
- **Input Fields:** Dark background (`#020617`), 1px border. On focus, the border changes to Primary Cyan with a sharp 2px inset highlight.
- **Cards/Widgets:** Must include a header area with `label-caps` text and a "drag handle" or "settings" icon to reinforce the modular dashboard feel.
- **Charts:** Use thin stroke lines (1px) for axes. Sparklines should use the Secondary Blue, while threshold violations should turn the line Critical Red.