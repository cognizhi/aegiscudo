use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    scan_dir: Option<PathBuf>,

    #[arg(long)]
    scan_artifact: Option<PathBuf>,

    #[arg(long)]
    process_next_job: bool,

    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,

    #[arg(long, env = "SURGEON_ARTIFACT_STORE_DIR")]
    artifact_store_dir: Option<PathBuf>,

    #[arg(long, default_value_t = 3)]
    max_retries: u16,

    #[arg(long, env = "SURGEON_SCAN_TIMEOUT_SECS", default_value_t = 300)]
    scan_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(scan_dir) = args.scan_dir {
        let evidence = surgeon::scan_directory(&scan_dir, surgeon::ScanLimits::default())
            .with_context(|| format!("scanning {}", scan_dir.display()))?;
        println!("{}", serde_json::to_string_pretty(&evidence)?);
        return Ok(());
    }
    if let Some(scan_artifact) = args.scan_artifact {
        let unpack_dir = tempfile::tempdir().context("creating temporary unpack directory")?;
        let (evidence, _manifest) = surgeon::scan_artifact_package(
            &scan_artifact,
            unpack_dir.path(),
            surgeon::ScanLimits::default(),
        )
        .with_context(|| format!("scanning artifact {}", scan_artifact.display()))?;
        println!("{}", serde_json::to_string_pretty(&evidence)?);
        return Ok(());
    }
    if args.process_next_job {
        let database_url = args
            .database_url
            .context("DATABASE_URL is required when --process-next-job is set")?;
        let artifact_store_dir = args
            .artifact_store_dir
            .unwrap_or_else(|| PathBuf::from("infra/buckets/aegiscudo-artifacts-local"));
        let config = surgeon::WorkerConfig {
            database_url,
            artifact_store_dir,
            max_retries: args.max_retries,
            scan_limits: surgeon::ScanLimits::default(),
            scan_timeout_secs: args.scan_timeout_secs,
        };
        match surgeon::process_next_analysis_job(&config).await? {
            Some(job) => println!("processed analysis job {}", job.id),
            None => println!("no queued analysis jobs"),
        }
    }
    Ok(())
}
