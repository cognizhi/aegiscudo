use std::time::Duration;

use aegiscudo_protocol::{DecisionRequest, DecisionResponse};
use http::StatusCode;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum TriageClientError {
    #[error("triage counter URL is invalid")]
    InvalidBaseUrl,
    #[error("triage counter is unavailable after HTTP status {0}")]
    UnavailableStatus(StatusCode),
    #[error("triage counter is unavailable")]
    Unavailable(#[source] reqwest::Error),
    #[error("triage counter returned non-retryable HTTP status {0}")]
    NonRetryableStatus(StatusCode),
    #[error("triage counter response was invalid")]
    InvalidResponse(#[source] reqwest::Error),
    #[error("triage counter response did not match the decision request context")]
    ResponseContextMismatch,
    #[error("triage counter client setup failed")]
    ClientSetup(#[source] reqwest::Error),
}

impl TriageClientError {
    pub fn is_outage(&self) -> bool {
        matches!(
            self,
            Self::UnavailableStatus(_) | Self::Unavailable(_) | Self::ClientSetup(_)
        )
    }
}

#[derive(Debug, Clone)]
pub struct TriageClient {
    client: reqwest::Client,
    evaluate_url: Url,
    max_retries: u8,
}

impl TriageClient {
    pub fn new(
        base_url: &str,
        timeout: Duration,
        max_retries: u8,
    ) -> Result<Self, TriageClientError> {
        let base_url = Url::parse(base_url).map_err(|_| TriageClientError::InvalidBaseUrl)?;
        if !matches!(base_url.scheme(), "http" | "https")
            || !base_url.username().is_empty()
            || base_url.password().is_some()
        {
            return Err(TriageClientError::InvalidBaseUrl);
        }
        let evaluate_url = base_url
            .join("/v1/decisions/evaluate")
            .map_err(|_| TriageClientError::InvalidBaseUrl)?;
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(TriageClientError::ClientSetup)?;
        Ok(Self {
            client,
            evaluate_url,
            max_retries,
        })
    }

    pub async fn evaluate(
        &self,
        request: &DecisionRequest,
    ) -> Result<DecisionResponse, TriageClientError> {
        let mut attempt = 0;
        loop {
            let result = self
                .client
                .post(self.evaluate_url.clone())
                .json(request)
                .send()
                .await;
            match result {
                Ok(response) if response.status().is_success() => {
                    let decision = response
                        .json::<DecisionResponse>()
                        .await
                        .map_err(TriageClientError::InvalidResponse)?;
                    validate_response_context(request, &decision)?;
                    return Ok(decision);
                }
                Ok(response)
                    if response.status().is_server_error() && attempt < self.max_retries =>
                {
                    attempt += 1;
                }
                Ok(response) if response.status().is_server_error() => {
                    return Err(TriageClientError::UnavailableStatus(response.status()));
                }
                Ok(response) => {
                    return Err(TriageClientError::NonRetryableStatus(response.status()));
                }
                Err(error) if attempt < self.max_retries => {
                    attempt += 1;
                    if !error.is_connect() && !error.is_timeout() {
                        return Err(TriageClientError::InvalidResponse(error));
                    }
                }
                Err(error) if error.is_connect() || error.is_timeout() => {
                    return Err(TriageClientError::Unavailable(error));
                }
                Err(error) => return Err(TriageClientError::InvalidResponse(error)),
            }
        }
    }
}

fn validate_response_context(
    request: &DecisionRequest,
    response: &DecisionResponse,
) -> Result<(), TriageClientError> {
    if response.tenant_id != request.tenant_id
        || response.policy_profile_id != request.policy_profile_id
        || response.trace_id != request.request.trace_id
    {
        return Err(TriageClientError::ResponseContextMismatch);
    }
    Ok(())
}
