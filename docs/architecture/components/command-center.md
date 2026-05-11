# Command Center

Source PRD sections: Feature 5, 3.2, 3.4.3, 3.4.4, 4.9, 4.10, 4.12.5.

Command Center is the operator UI for security review, administration, reporting, and platform observability.

## Responsibilities

- Show executive and KPI dashboards with draggable and resizable panels.
- Review quarantine queue, evidence, sandbox telemetry, AI explanations, overrides, and audit trail.
- Configure registry proxies, tenant namespace settings, policy profiles, AI providers, and integration credentials.
- Provide policy simulation and CISO reporting workflows.
- Use backend RBAC, never UI-only authorization.

## Design System

The UI uses Next.js App Router, TypeScript, Tailwind CSS v4, Radix-compatible primitives, TanStack Query/Table, Recharts, Framer Motion, and lucide icons. Theme values must come from CSS custom properties for dark, light, and dim themes.

## Current Implementation State

The Next.js App Router shell, theme tokens, sidebar, KPI/dashboard panels, tenant-scoped timeline, quarantine review, artifact evidence viewer, override workflow, admin panels, and policy simulator are implemented and wired to live or typed control-plane routes. Route-mocked and seeded Playwright coverage now exists for the dashboard, admin, override, and policy simulator slices, while persisted personalization, command palette, auth/RBAC, accessibility hardening, and broader live seeded workflow coverage remain open.