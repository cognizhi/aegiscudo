use aegiscudo_core::{FeedState, PackageCoordinate, PolicyDecision, PolicyMode};
use aegiscudo_protocol::DecisionResponse;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyInput {
    pub tenant_id: Uuid,
    pub policy_profile_id: Uuid,
    pub policy_snapshot_id: Uuid,
    pub coordinate: PackageCoordinate,
    pub trace_id: String,
    #[serde(default)]
    pub mode: PolicyMode,
    #[serde(default)]
    pub known_safe_verdict: bool,
    #[serde(default)]
    pub known_malicious: bool,
    #[serde(default)]
    pub vulnerable_above_threshold: bool,
    #[serde(default)]
    pub vulnerable_above_threshold_action: VulnerabilityPolicyAction,
    #[serde(default)]
    pub minimum_release_age_violation: bool,
    #[serde(default)]
    pub install_script_detected: bool,
    #[serde(default)]
    pub dependency_confusion_risk: bool,
    #[serde(default)]
    pub typosquat_risk: bool,
    #[serde(default)]
    pub artifact_digest_reputation_risk: bool,
    #[serde(default)]
    pub cross_ecosystem_ioc_correlation_risk: bool,
    #[serde(default)]
    pub static_analysis_score_violation: bool,
    #[serde(default)]
    pub dynamic_sandbox_policy_violation: bool,
    #[serde(default)]
    pub github_to_registry_publish_gap_risk: bool,
    #[serde(default)]
    pub trusted_publisher_identity_mismatch: bool,
    #[serde(default)]
    pub scorecard_code_review_risk: bool,
    #[serde(default)]
    pub scorecard_branch_protection_risk: bool,
    #[serde(default)]
    pub scorecard_ci_cd_risk: bool,
    #[serde(default)]
    pub scorecard_maintained_risk: bool,
    #[serde(default)]
    pub scorecard_signed_releases_risk: bool,
    #[serde(default)]
    pub scorecard_code_review_action: SignalPolicyAction,
    #[serde(default)]
    pub scorecard_branch_protection_action: SignalPolicyAction,
    #[serde(default)]
    pub scorecard_ci_cd_action: SignalPolicyAction,
    #[serde(default)]
    pub scorecard_maintained_action: SignalPolicyAction,
    #[serde(default)]
    pub scorecard_signed_releases_action: SignalPolicyAction,
    #[serde(default)]
    pub provenance_or_signature_verification_failed: bool,
    #[serde(default)]
    pub missing_or_failed_attestation: bool,
    #[serde(default)]
    pub ai_agent_injection_indicator: bool,
    #[serde(default)]
    pub maintainer_account_age_risk: bool,
    #[serde(default)]
    pub recent_maintainer_change_risk: bool,
    #[serde(default)]
    pub new_maintainer_ratio_risk: bool,
    #[serde(default)]
    pub unknown_artifact: bool,
    #[serde(default)]
    pub hitl_required: bool,
    #[serde(default)]
    pub active_override: bool,
    #[serde(default)]
    pub emergency_bypass: bool,
    #[serde(default)]
    pub fallback_eligible: bool,
    #[serde(default)]
    pub fallback_candidate: Option<PackageCoordinate>,
    #[serde(default = "default_feed_state")]
    pub feed_state: FeedState,
    #[serde(default)]
    pub feed_snapshot_age_seconds: u64,
}

fn default_feed_state() -> FeedState {
    FeedState::Fresh
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum VulnerabilityPolicyAction {
    #[default]
    Warn,
    Block,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SignalPolicyAction {
    Allow,
    #[default]
    Warn,
    Block,
    Hitl,
}

fn scorecard_policy_outcome(
    input: &PolicyInput,
    rationale: &mut Vec<String>,
) -> Option<PolicyDecision> {
    let mut warn = false;
    let mut hitl = false;
    let mut block = false;

    for (risk, action, message) in [
        (
            input.scorecard_code_review_risk,
            input.scorecard_code_review_action,
            "OpenSSF Scorecard code review check indicates incomplete review coverage",
        ),
        (
            input.scorecard_branch_protection_risk,
            input.scorecard_branch_protection_action,
            "OpenSSF Scorecard branch protection check indicates incomplete protection",
        ),
        (
            input.scorecard_ci_cd_risk,
            input.scorecard_ci_cd_action,
            "OpenSSF Scorecard CI/CD check indicates incomplete CI protections",
        ),
        (
            input.scorecard_maintained_risk,
            input.scorecard_maintained_action,
            "OpenSSF Scorecard maintained check indicates weak maintenance posture",
        ),
        (
            input.scorecard_signed_releases_risk,
            input.scorecard_signed_releases_action,
            "OpenSSF Scorecard signed releases check indicates unsigned or inconsistently signed releases",
        ),
    ] {
        if !risk || matches!(action, SignalPolicyAction::Allow) {
            continue;
        }

        rationale.push(message.to_owned());
        match action {
            SignalPolicyAction::Allow => {}
            SignalPolicyAction::Warn => warn = true,
            SignalPolicyAction::Block => block = true,
            SignalPolicyAction::Hitl => hitl = true,
        }
    }

    if block {
        Some(PolicyDecision::BlockPolicyViolation)
    } else if hitl {
        Some(PolicyDecision::RequireHitlApproval)
    } else if warn {
        Some(PolicyDecision::AllowWithWarning)
    } else {
        None
    }
}

#[derive(Debug, Default, Clone)]
pub struct DecisionEngine;

impl DecisionEngine {
    pub fn evaluate(&self, input: PolicyInput) -> DecisionResponse {
        let mut rationale = Vec::new();

        let (decision, fallback_coordinate, create_analysis_job) = if input.active_override
            || input.emergency_bypass
        {
            rationale.push("time-bound override or emergency bypass is active".to_owned());
            (PolicyDecision::AllowWithWarning, None, false)
        } else if input.known_malicious {
            rationale.push("known malicious package or artifact match".to_owned());
            (PolicyDecision::BlockKnownMalicious, None, false)
        } else if input.known_safe_verdict {
            rationale.push("previous safe organizational verdict matched".to_owned());
            (PolicyDecision::Allow, None, false)
        } else if input.dependency_confusion_risk
            || input.typosquat_risk
            || input.artifact_digest_reputation_risk
            || input.cross_ecosystem_ioc_correlation_risk
            || input.static_analysis_score_violation
            || input.dynamic_sandbox_policy_violation
            || input.github_to_registry_publish_gap_risk
            || input.ai_agent_injection_indicator
            || input.minimum_release_age_violation
            || input.maintainer_account_age_risk
            || input.recent_maintainer_change_risk
            || input.new_maintainer_ratio_risk
        {
            if input.dependency_confusion_risk {
                rationale.push("dependency confusion namespace risk".to_owned());
            }
            if input.typosquat_risk {
                rationale.push("typosquatting similarity risk".to_owned());
            }
            if input.artifact_digest_reputation_risk {
                rationale.push("artifact digest reputation risk".to_owned());
            }
            if input.cross_ecosystem_ioc_correlation_risk {
                rationale.push("cross-ecosystem IOC correlation risk".to_owned());
            }
            if input.static_analysis_score_violation {
                rationale.push(
                    "static analysis score exceeded the configured policy threshold".to_owned(),
                );
            }
            if input.dynamic_sandbox_policy_violation {
                rationale.push(
                    "dynamic sandbox result exceeded the configured policy threshold".to_owned(),
                );
            }
            if input.github_to_registry_publish_gap_risk {
                rationale.push("GitHub-to-registry publish gap risk matched policy".to_owned());
            }
            if input.ai_agent_injection_indicator {
                rationale.push("AI agent instruction injection indicator".to_owned());
            }
            if input.minimum_release_age_violation {
                rationale.push("minimum release age policy violation".to_owned());
            }
            if input.maintainer_account_age_risk {
                rationale.push("maintainer account age risk".to_owned());
            }
            if input.recent_maintainer_change_risk {
                rationale.push("recent maintainer change risk".to_owned());
            }
            if input.new_maintainer_ratio_risk {
                rationale.push("new maintainer publishing ratio risk".to_owned());
            }
            (PolicyDecision::BlockPolicyViolation, None, false)
        } else if input.hitl_required {
            rationale.push("human approval is required by policy".to_owned());
            (PolicyDecision::RequireHitlApproval, None, false)
        } else if input.fallback_eligible && input.fallback_candidate.is_some() {
            rationale.push(
                "eligible resolver metadata flow can use approved fallback candidate".to_owned(),
            );
            (
                PolicyDecision::FallbackToApprovedCandidate,
                input.fallback_candidate.clone(),
                false,
            )
        } else if input.unknown_artifact {
            rationale.push("unknown artifact requires asynchronous analysis".to_owned());
            (PolicyDecision::QuarantinePendingAnalysis, None, true)
        } else if input.vulnerable_above_threshold {
            rationale
                .push("known vulnerability exceeded the configured policy threshold".to_owned());
            match input.vulnerable_above_threshold_action {
                VulnerabilityPolicyAction::Warn => (PolicyDecision::AllowWithWarning, None, false),
                VulnerabilityPolicyAction::Block => {
                    (PolicyDecision::BlockPolicyViolation, None, false)
                }
            }
        } else if let Some(scorecard_decision) = scorecard_policy_outcome(&input, &mut rationale) {
            (scorecard_decision, None, false)
        } else if input.install_script_detected
            || input.trusted_publisher_identity_mismatch
            || input.provenance_or_signature_verification_failed
            || input.missing_or_failed_attestation
        {
            if input.install_script_detected {
                rationale.push("install or lifecycle script requires review".to_owned());
            }
            if input.trusted_publisher_identity_mismatch {
                rationale.push(
                    "Trusted Publisher identity did not match expected CI/CD publisher".to_owned(),
                );
            }
            if input.provenance_or_signature_verification_failed {
                rationale.push(
                    "provenance or registry signature verification failed or was unavailable"
                        .to_owned(),
                );
            }
            if input.missing_or_failed_attestation {
                rationale.push("attestation is missing, failed, or unverifiable".to_owned());
            }
            (PolicyDecision::AllowWithWarning, None, false)
        } else {
            rationale.push("no blocking policy signal matched".to_owned());
            (PolicyDecision::Allow, None, false)
        };

        DecisionResponse {
            decision,
            tenant_id: input.tenant_id,
            policy_profile_id: input.policy_profile_id,
            policy_snapshot_id: input.policy_snapshot_id,
            mode: input.mode,
            feed_state: input.feed_state,
            feed_snapshot_age_seconds: input.feed_snapshot_age_seconds,
            trace_id: input.trace_id,
            rationale,
            fallback_coordinate,
            create_analysis_job,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegiscudo_core::PackageEcosystem;

    fn base_input() -> PolicyInput {
        PolicyInput {
            tenant_id: Uuid::now_v7(),
            policy_profile_id: Uuid::now_v7(),
            policy_snapshot_id: Uuid::now_v7(),
            coordinate: PackageCoordinate::new(
                PackageEcosystem::Npm,
                "left-pad",
                Some("1.3.0"),
                None::<String>,
            ),
            trace_id: "trace-1".to_owned(),
            mode: PolicyMode::Enforce,
            known_safe_verdict: false,
            known_malicious: false,
            vulnerable_above_threshold: false,
            vulnerable_above_threshold_action: VulnerabilityPolicyAction::Warn,
            minimum_release_age_violation: false,
            install_script_detected: false,
            dependency_confusion_risk: false,
            typosquat_risk: false,
            artifact_digest_reputation_risk: false,
            cross_ecosystem_ioc_correlation_risk: false,
            static_analysis_score_violation: false,
            dynamic_sandbox_policy_violation: false,
            github_to_registry_publish_gap_risk: false,
            trusted_publisher_identity_mismatch: false,
            scorecard_code_review_risk: false,
            scorecard_branch_protection_risk: false,
            scorecard_ci_cd_risk: false,
            scorecard_maintained_risk: false,
            scorecard_signed_releases_risk: false,
            scorecard_code_review_action: SignalPolicyAction::Warn,
            scorecard_branch_protection_action: SignalPolicyAction::Warn,
            scorecard_ci_cd_action: SignalPolicyAction::Warn,
            scorecard_maintained_action: SignalPolicyAction::Warn,
            scorecard_signed_releases_action: SignalPolicyAction::Warn,
            provenance_or_signature_verification_failed: false,
            missing_or_failed_attestation: false,
            ai_agent_injection_indicator: false,
            maintainer_account_age_risk: false,
            recent_maintainer_change_risk: false,
            new_maintainer_ratio_risk: false,
            unknown_artifact: false,
            hitl_required: false,
            active_override: false,
            emergency_bypass: false,
            fallback_eligible: false,
            fallback_candidate: None,
            feed_state: FeedState::Fresh,
            feed_snapshot_age_seconds: 0,
        }
    }

    fn evaluate(mut input: PolicyInput) -> PolicyDecision {
        let engine = DecisionEngine;
        input.trace_id = "test-trace".to_owned();
        engine.evaluate(input).decision
    }

    #[test]
    fn returns_all_decision_states() {
        assert_eq!(evaluate(base_input()), PolicyDecision::Allow);

        let mut warn = base_input();
        warn.install_script_detected = true;
        assert_eq!(evaluate(warn), PolicyDecision::AllowWithWarning);

        let mut quarantine = base_input();
        quarantine.unknown_artifact = true;
        assert_eq!(
            evaluate(quarantine),
            PolicyDecision::QuarantinePendingAnalysis
        );

        let mut malicious = base_input();
        malicious.known_malicious = true;
        assert_eq!(evaluate(malicious), PolicyDecision::BlockKnownMalicious);

        let mut policy = base_input();
        policy.minimum_release_age_violation = true;
        assert_eq!(evaluate(policy), PolicyDecision::BlockPolicyViolation);

        let mut hitl = base_input();
        hitl.hitl_required = true;
        assert_eq!(evaluate(hitl), PolicyDecision::RequireHitlApproval);

        let mut fallback = base_input();
        fallback.fallback_eligible = true;
        fallback.fallback_candidate = Some(PackageCoordinate::new(
            PackageEcosystem::Npm,
            "left-pad",
            Some("1.2.0"),
            None::<String>,
        ));
        assert_eq!(
            evaluate(fallback),
            PolicyDecision::FallbackToApprovedCandidate
        );
    }

    #[test]
    fn override_precedes_known_malicious_but_warns() {
        let mut input = base_input();
        input.active_override = true;
        input.known_malicious = true;
        assert_eq!(evaluate(input), PolicyDecision::AllowWithWarning);
    }

    #[test]
    fn known_safe_verdict_allows_when_no_higher_confidence_block_exists() {
        let mut input = base_input();
        input.known_safe_verdict = true;
        assert_eq!(evaluate(input), PolicyDecision::Allow);
    }

    #[test]
    fn known_malicious_precedes_known_safe_verdict() {
        let mut input = base_input();
        input.known_safe_verdict = true;
        input.known_malicious = true;
        assert_eq!(evaluate(input), PolicyDecision::BlockKnownMalicious);
    }

    #[test]
    fn cross_ecosystem_ioc_placeholder_blocks_as_policy_violation() {
        let mut input = base_input();
        input.cross_ecosystem_ioc_correlation_risk = true;
        assert_eq!(evaluate(input), PolicyDecision::BlockPolicyViolation);
    }

    #[test]
    fn static_analysis_placeholder_blocks_as_policy_violation() {
        let mut input = base_input();
        input.static_analysis_score_violation = true;
        assert_eq!(evaluate(input), PolicyDecision::BlockPolicyViolation);
    }

    #[test]
    fn dynamic_sandbox_placeholder_blocks_as_policy_violation() {
        let mut input = base_input();
        input.dynamic_sandbox_policy_violation = true;
        assert_eq!(evaluate(input), PolicyDecision::BlockPolicyViolation);
    }

    #[test]
    fn trusted_publisher_mismatch_warns() {
        let mut input = base_input();
        input.trusted_publisher_identity_mismatch = true;
        assert_eq!(evaluate(input), PolicyDecision::AllowWithWarning);
    }

    #[test]
    fn scorecard_signals_warn() {
        let mut input = base_input();
        input.scorecard_branch_protection_risk = true;
        assert_eq!(evaluate(input), PolicyDecision::AllowWithWarning);
    }

    #[test]
    fn scorecard_signals_can_block() {
        let mut input = base_input();
        input.scorecard_signed_releases_risk = true;
        input.scorecard_signed_releases_action = SignalPolicyAction::Block;
        assert_eq!(evaluate(input), PolicyDecision::BlockPolicyViolation);
    }

    #[test]
    fn scorecard_signals_can_require_hitl() {
        let mut input = base_input();
        input.scorecard_maintained_risk = true;
        input.scorecard_maintained_action = SignalPolicyAction::Hitl;
        assert_eq!(evaluate(input), PolicyDecision::RequireHitlApproval);
    }

    #[test]
    fn scorecard_allow_action_keeps_decision_neutral() {
        let mut input = base_input();
        input.scorecard_branch_protection_risk = true;
        input.scorecard_branch_protection_action = SignalPolicyAction::Allow;
        assert_eq!(evaluate(input), PolicyDecision::Allow);
    }

    #[test]
    fn vulnerability_signal_can_block_when_policy_requires_it() {
        let mut input = base_input();
        input.vulnerable_above_threshold = true;
        input.vulnerable_above_threshold_action = VulnerabilityPolicyAction::Block;
        assert_eq!(evaluate(input), PolicyDecision::BlockPolicyViolation);
    }

    #[test]
    fn publish_gap_placeholder_blocks_as_policy_violation() {
        let mut input = base_input();
        input.github_to_registry_publish_gap_risk = true;
        assert_eq!(evaluate(input), PolicyDecision::BlockPolicyViolation);
    }

    #[test]
    fn stale_feed_state_is_preserved() {
        let mut input = base_input();
        input.feed_state = FeedState::Stale;
        input.feed_snapshot_age_seconds = 86_500;
        let response = DecisionEngine.evaluate(input);
        assert_eq!(response.feed_state, FeedState::Stale);
        assert_eq!(response.feed_snapshot_age_seconds, 86_500);
    }

    #[test]
    fn mode_is_preserved_in_response() {
        let mut input = base_input();
        input.mode = PolicyMode::Shadow;
        let response = DecisionEngine.evaluate(input);
        assert_eq!(response.mode, PolicyMode::Shadow);
    }

    #[test]
    fn scorecard_warning_rationale_is_emitted() {
        let mut input = base_input();
        input.scorecard_code_review_risk = true;
        input.scorecard_signed_releases_risk = true;

        let response = DecisionEngine.evaluate(input);

        assert_eq!(response.decision, PolicyDecision::AllowWithWarning);
        assert!(response.rationale.iter().any(|entry| {
            entry == "OpenSSF Scorecard code review check indicates incomplete review coverage"
        }));
        assert!(response.rationale.iter().any(|entry| {
            entry == "OpenSSF Scorecard signed releases check indicates unsigned or inconsistently signed releases"
        }));
    }
}
