// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#[test]
fn recovery_replays_across_processes_without_changing_existing_selectors() {
    for seed in [19307, 19308, 31, 26801, 26802] {
        let run = || {
            std::process::Command::new(env!("CARGO_BIN_EXE_sim-replay"))
                .args(["recovery", &seed.to_string()])
                .output()
                .unwrap_or_else(|e| panic!("seed {seed}: {e}"))
        };
        let a = run();
        let b = run();
        assert!(
            a.status.success(),
            "seed {seed}: {}",
            String::from_utf8_lossy(&a.stderr)
        );
        assert!(
            b.status.success(),
            "seed {seed}: {}",
            String::from_utf8_lossy(&b.stderr)
        );
        assert_eq!(a.stdout, b.stdout, "seed {seed}");
        assert!(
            String::from_utf8_lossy(&a.stdout).starts_with(&format!("recovery seed {seed}\n")),
            "seed {seed}"
        );
    }
}
