use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    scan_dir: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(scan_dir) = args.scan_dir {
        let evidence = surgeon::scan_directory(&scan_dir, surgeon::ScanLimits::default())
            .with_context(|| format!("scanning {}", scan_dir.display()))?;
        println!("{}", serde_json::to_string_pretty(&evidence)?);
    }
    Ok(())
}
