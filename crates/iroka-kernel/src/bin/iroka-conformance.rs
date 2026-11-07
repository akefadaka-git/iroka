use std::{
    collections::BTreeMap,
    env,
    fs::{self, OpenOptions},
    io::Write,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

use iroka_kernel::build_conformance_report;

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(catalog_path) = args.next() else {
        eprintln!("usage: iroka-conformance <catalog.json> [--output <report.json>]");
        return ExitCode::from(2);
    };
    let mut output_path = None;
    while let Some(argument) = args.next() {
        if argument == "--output" {
            output_path = args.next();
        } else {
            eprintln!("unknown argument: {argument}");
            return ExitCode::from(2);
        }
    }

    let started_at = now_unix_ms();
    let catalog = match fs::read_to_string(&catalog_path) {
        Ok(catalog) => catalog,
        Err(error) => {
            eprintln!("cannot read conformance catalog {catalog_path}: {error}");
            return ExitCode::from(2);
        }
    };
    let metadata = [
        "GITHUB_REPOSITORY",
        "GITHUB_REF",
        "GITHUB_SHA",
        "GITHUB_WORKFLOW",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_RUN_URL",
        "RUNNER_OS",
        "RUNNER_ARCH",
    ]
    .into_iter()
    .filter_map(|key| env::var(key).ok().map(|value| (key.to_owned(), value)))
    .collect::<BTreeMap<_, _>>();
    let report = match build_conformance_report(&catalog, &metadata, started_at, now_unix_ms()) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("A2 conformance catalog invalid: {error}");
            return ExitCode::from(1);
        }
    };
    let rendered = match serde_json::to_string_pretty(&report) {
        Ok(rendered) => rendered,
        Err(error) => {
            eprintln!("cannot serialize A2 conformance report: {error}");
            return ExitCode::from(1);
        }
    };
    println!("{rendered}");

    if let Some(path) = output_path {
        if let Err(error) = fs::write(&path, &rendered) {
            eprintln!("cannot write A2 conformance report {path}: {error}");
            return ExitCode::from(1);
        }
    }

    if let Ok(summary_path) = env::var("GITHUB_STEP_SUMMARY") {
        let counts = &report["counts"];
        let mut summary = match OpenOptions::new().create(true).append(true).open(summary_path) {
            Ok(summary) => summary,
            Err(error) => {
                eprintln!("cannot open GitHub step summary: {error}");
                return ExitCode::from(1);
            }
        };
        let _ = writeln!(
            summary,
            "# IROKA A2 conformance disposition\n\n- Gate: **{}**\n- Exact SHA: \x60{}\x60\n- Cases: {}\n- PASS: {} · FAIL: {} · BLOCKED: {} · NOT RUN: {} · NOT APPLICABLE: {}\n\nBLOCKED and NOT RUN cases are not passes. The report JSON is emitted in the workflow log and, when requested, written to the output path.",
            report["gate_status"].as_str().unwrap_or("UNKNOWN"),
            report["commit_sha"].as_str().unwrap_or("UNKNOWN"),
            report["case_count"],
            counts["PASS"],
            counts["FAIL"],
            counts["BLOCKED"],
            counts["NOT RUN"],
            counts["NOT APPLICABLE"],
        );
    }

    if report["gate_status"] == "FAIL" {
        ExitCode::from(1)
    } else {
        // A BLOCKED conformance gate is an honest report of missing platform components,
        // not a harness failure and never a release/closure pass.
        ExitCode::SUCCESS
    }
}
