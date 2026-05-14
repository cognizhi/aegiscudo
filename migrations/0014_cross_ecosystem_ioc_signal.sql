ALTER TABLE package_signal_observations
  DROP CONSTRAINT IF EXISTS package_signal_observations_signal_check;

ALTER TABLE package_signal_observations
  ADD CONSTRAINT package_signal_observations_signal_check CHECK (signal IN (
    'minimum-release-age-violation',
    'install-script-detected',
    'dependency-confusion-risk',
    'typosquat-risk',
    'artifact-digest-reputation-risk',
    'github-to-registry-publish-gap-risk',
    'trusted-publisher-identity-mismatch',
    'cross-ecosystem-ioc-correlation-risk',
    'maintainer-account-age-risk',
    'recent-maintainer-change-risk',
    'new-maintainer-ratio-risk',
    'known-malicious'
  ));