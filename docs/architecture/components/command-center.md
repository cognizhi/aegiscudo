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

The Next.js scaffold, dashboard shell, theme tokens, sidebar, metrics, chart, decision table, tooltip primitive, Vitest test, and Playwright smoke test exist. Real workflows, API integration, persisted personalization, command palette, auth/RBAC, accessibility checks, and full Playwright coverage remain Phase 1C work.