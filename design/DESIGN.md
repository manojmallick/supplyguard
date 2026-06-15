---
name: SupplyGuard Security Architecture
colors:
  surface: '#111318'
  surface-dim: '#111318'
  surface-bright: '#37393f'
  surface-container-lowest: '#0c0e13'
  surface-container-low: '#1a1b21'
  surface-container: '#1e1f25'
  surface-container-high: '#282a2f'
  surface-container-highest: '#33353a'
  on-surface: '#e2e2e9'
  on-surface-variant: '#bdcab9'
  inverse-surface: '#e2e2e9'
  inverse-on-surface: '#2e3036'
  outline: '#879484'
  outline-variant: '#3e4a3c'
  surface-tint: '#64df74'
  primary: '#82fd8e'
  on-primary: '#003910'
  primary-container: '#65e075'
  on-primary-container: '#006120'
  inverse-primary: '#006e26'
  secondary: '#aac7ff'
  on-secondary: '#003064'
  secondary-container: '#3e90ff'
  on-secondary-container: '#002957'
  tertiary: '#dbe3fc'
  on-tertiary: '#283043'
  tertiary-container: '#bfc7df'
  on-tertiary-container: '#4b5367'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#81fc8d'
  primary-fixed-dim: '#64df74'
  on-primary-fixed: '#002106'
  on-primary-fixed-variant: '#00531a'
  secondary-fixed: '#d6e3ff'
  secondary-fixed-dim: '#aac7ff'
  on-secondary-fixed: '#001b3e'
  on-secondary-fixed-variant: '#00468d'
  tertiary-fixed: '#dae2fb'
  tertiary-fixed-dim: '#bec6de'
  on-tertiary-fixed: '#131b2d'
  on-tertiary-fixed-variant: '#3f475a'
  background: '#111318'
  on-background: '#e2e2e9'
  surface-variant: '#33353a'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 30px
    fontWeight: '700'
    lineHeight: 38px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.01em
  title-sm:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '600'
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
    lineHeight: 18px
  mono-label:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
  mono-data:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
  headline-lg-mobile:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '700'
    lineHeight: 32px
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  unit: 4px
  container-padding: 24px
  element-gap-xs: 4px
  element-gap-sm: 8px
  element-gap-md: 16px
  column-gutter: 20px
  sidebar-width: 260px
---

## Brand & Style
The design system is engineered for high-stakes Security Operations Centers (SOC) focused on supply chain integrity. The brand personality is **vigilant, technical, and authoritative**, prioritizing rapid data synthesis over aesthetic decoration.

The visual style is **Corporate / Modern with a Technical bias**, utilizing a deep-space dark mode to reduce eye strain during long monitoring shifts. It leans into a systematic, grid-based layout that mirrors the structured nature of software bill of materials (SBOM) and dependency trees. The aesthetic is "glass-and-wire"—using subtle borders and tonal shifts rather than heavy shadows to define hierarchy, ensuring the interface feels like a high-performance instrument rather than a general-purpose application.

## Colors
The palette is optimized for a **Dark-First** environment, using depth-based surfacing to organize information density.

- **Foundational Layers:** The base background (#0D0F14) provides maximum contrast for data. Sidebar and navigation elements use a slightly elevated surface (#151A24) to create structural anchoring.
- **Action & Identity:** Splunk Green (#65E075) is reserved for primary actions and system health indicators. Info Blue (#0A84FF) is used for secondary interactive elements and neutral system state updates.
- **Severity Logic:** These colors are the most "vibrant" in the UI to ensure immediate peripheral recognition. Critical and High alerts must be isolated from other colorful elements to prevent visual noise.

## Typography
The typographic system utilizes a dual-font approach to distinguish between **UI Guidance** and **Technical Evidence**.

- **Inter:** Used for all structural navigation, labels, and instructional text. It provides the necessary clarity and legibility for complex dashboard layouts.
- **JetBrains Mono:** Applied to all machine-generated content, including CVE IDs, SHA-256 hashes, SBOM lists, and terminal logs. This monospaced font ensures that strings of technical data are easily scannable and that characters (like 0 vs O) are distinct.
- **Scale:** Maintain a tight scale. In an enterprise security context, more information on screen is often preferable to large, "airy" typography.

## Layout & Spacing
This design system employs a **Fixed-Fluid Hybrid Grid** optimized for 1080p and 1440p SOC monitors. 

- **The Layout:** A fixed left sidebar for global navigation, with a fluid content area that uses a 12-column grid. 
- **Information Density:** Spacing follows a strict 4px base unit. Gaps between related technical items (like a label and its value) should use `element-gap-xs` (4px) or `sm` (8px). Large-scale containers use `element-gap-md` (16px) to maintain a clean separation of concerns.
- **Data Tables:** These are the heart of the system. Rows should be compact (32px-40px height) to maximize visible records. Padding within table cells is kept at a minimum (8px horizontal).

## Elevation & Depth
In this design system, depth is communicated through **Tonal Layering and Low-Contrast Outlines** rather than traditional shadows.

- **Level 0 (Background):** #0D0F14 — The "void." Used for the main app canvas.
- **Level 1 (Navigation/Sidebar):** #151A24 — Used for persistent layout elements.
- **Level 2 (Main Cards/Containers):** #1C2436 — The primary surface for data widgets, tables, and charts.
- **Level 3 (Overlays/Modals):** #242D42 — Elevated surfaces for temporal tasks.

**Borders:** Every container (Level 2+) must have a 1px solid border (#2A3555). This provides a crisp, technical "blueprint" feel that maintains structure even in low-light environments. Shadows are only used for Level 3 Modals, utilizing a very subtle, large-blur black shadow with 0% offset to separate the modal from the background.

## Shapes
The shape language is **Soft (0.25rem)** to balance modern aesthetics with the precision of a security tool. 

- **Standard Elements:** Buttons, input fields, and small cards use a 4px (0.25rem) radius.
- **Data Highlighting:** Status badges (Severity labels) are nearly square with minimal rounding to maximize their "tag" appearance.
- **Large Containers:** Main dashboard widgets may use `rounded-lg` (8px) to soften the overall layout, but never more. 
- **Selection States:** Active tabs or selected list items use a hard left-edge accent bar (2px width) in the primary color rather than rounded shapes to indicate focus.

## Components
- **Buttons:** Primary buttons are Solid Splunk Green with black text for maximum contrast. Secondary buttons use an outline style with #2A3555 borders and white text.
- **Status Badges:** Use a "Glow-Pill" style—a dark background tinted with the severity color, a 1px border of the severity color, and a small center-aligned dot of the same color next to the JetBrains Mono text.
- **Severity Tables:** Row backgrounds remain neutral, but the "Impact" column must use high-contrast text or a color-coded vertical bar at the start of the row to signify urgency.
- **Technical Code Blocks:** Encased in a Level 3 surface with a subtle "Copy" icon in the top right. Syntax highlighting must follow a custom dark-theme profile using the Primary and Semantic colors.
- **Circular Gauges:** Used for compliance scores (e.g., NIS2 readiness). Use a thin (2px-4px) track width with a solid primary-colored stroke for the value.
- **Impact Diagrams:** Use thin 1px lines (#2A3555) to connect nodes in a dependency tree. Active threats should pulse with a subtle Critical red glow behind the node icon.