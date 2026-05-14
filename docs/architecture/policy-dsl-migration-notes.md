# Policy DSL Migration Notes

Source PRD sections: policy and decisioning architecture, plus [ADR 0011](../adr/0011-policy-dsl-evaluation-opa-rego-cedar.md).

## Phase 2 Decision

Aegiscudo keeps the current typed YAML policy DSL as the only active policy authoring format through Phase 2.

This means:

- no parallel policy-as-code surface in Phase 2
- no dual-authoring requirement for tenants or operators
- no request-time dependency on an external policy engine
- no migration away from the current policy schema during this phase

OPA/Rego is not adopted because it adds runtime complexity and authoring overhead that do not fit the current snapshot-based control-plane model. Cedar remains the preferred future candidate if tenant-authored rule expressions become necessary in a later phase.

## Backward Compatibility Rule

Existing YAML policy profiles remain the compatibility baseline.

- the JSON schema and fixture-based validation stay authoritative
- older profiles that omit newer optional fields must continue to validate with defaults
- any future policy-runtime change must preserve versioned policy snapshots used by Triage Counter and analysis pipelines

## Migration Trigger

Re-open the policy-format question only if at least one of these becomes true:

- operators need tenant-authored expressions that exceed the current typed field model
- policy review workflows require a more formal authorization language with analyzable principals, resources, and actions
- the current YAML representation cannot express new enforcement rules without unsafe ad hoc extensions

Until then, Phase 2 work should keep improving the existing DSL instead of splitting effort across two formats.

## Future Cedar Migration Outline

If Phase 3 requires a policy-language migration, use a staged path:

1. Define a lossless mapping from the current YAML policy profile into Cedar entities, actions, and conditions.
2. Compile YAML profiles into Cedar policies as a generated artifact before allowing direct Cedar authoring.
3. Run dual evaluation in read-only diff mode and compare decisions for a representative policy corpus.
4. Preserve the original YAML snapshot and the generated Cedar artifact in audit history.
5. Introduce direct Cedar authoring only after diff-mode parity is demonstrated and admin UX is ready.

## Non-Goals

These notes do not authorize immediate policy-format expansion.

- no OPA/Rego sidecar or inline evaluation path
- no mixed YAML plus Cedar authoring in Phase 2
- no breaking schema change for existing policy fixtures or tenant policy records
