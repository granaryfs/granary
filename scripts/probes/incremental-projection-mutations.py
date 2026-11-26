#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0

"""Mutation proofs for the incremental sync projection, with byte-exact restoration.

Each mutant edits one source file, shows the diff, checks the edit landed,
runs exactly one named test and requires it to fail at its intended assertion,
then restores the original bytes (SHA-256 checked) and requires the same test
to pass again. A survivor, a wrong selection or a failure elsewhere is an error.
"""
import argparse
import difflib
import hashlib
import os
from pathlib import Path
import re
import subprocess

if not __debug__:
    raise SystemExit("incremental-projection-mutations: refuses to run under python -O; its checks are assert statements")

ROOT = Path(__file__).resolve().parents[2]
CLIENT = "crates/granary-client/src"
PROJECTION = f"{CLIENT}/overlay_store/projection.rs"
OBJECTS = f"{CLIENT}/sync/objects.rs"
ENGINE = f"{CLIENT}/sync/engine.rs"
CAPTURE = f"{CLIENT}/writable_store/capture.rs"
BASE = f"{CLIENT}/sync/base.rs"
COMMIT = f"{CLIENT}/sync/engine/commit.rs"
TESTS = "overlay_store::tests"
ENGINE_TESTS = f"{TESTS}::coordination::engine"
MOVE = f"{TESTS}::incremental::a_synced_move_across_directories_matches"
READER = "a reader of the accepted root does not find the projected tree"

# name: (file, before, after, test path, marker the failure must print)
MUTANTS = {
    "a_drop_destination_parent": (
        PROJECTION,
        "effect_parents.extend(effect.parents.iter().copied());",
        "effect_parents.extend(effect.parents.iter().take(1).copied());",
        MOVE,
        READER,
    ),
    "b_drop_changed_payload_seed": (
        PROJECTION,
        "seeds.insert(parent_of(&entry.path)?);",
        "parent_of(&entry.path)?;",
        f"{TESTS}::projection::a_payload_that_differs_from_its_base_entry_dirties_its_parent_without_any_effect",
        "a changed payload did not dirty its parent",
    ),
    "c_drop_upward_closure": (
        PROJECTION,
        """for end in 1..entry.path.len() {
                    if let Some(ancestor) = entry.path.get(..end).and_then(|p| dir_at.get(p)) {
                        rebuild.insert(*ancestor);
                    }
                }""",
        "",
        f"{TESTS}::incremental::a_chain_twenty_deep_rebuilds_only_its_own_path",
        READER,
    ),
    "d_reuse_a_base_id_inside_the_rebuild_set": (
        OBJECTS,
        "OverlayKind::Directory if self.rebuild.contains(&child.inode) =>",
        """OverlayKind::Directory
            if self.rebuild.contains(&child.inode)
                && !self.base_by_inode.contains_key(&child.inode) =>""",
        MOVE,
        READER,
    ),
    "e_prune_a_changed_files_spill_root": (
        OBJECTS,
        """EntryKind::File {
                            exec: child.exec,
                            size: child.size,
                            grains,
                        }""",
        """{
                            if let FileGrains::Spill { root, .. } = &grains {
                                self.reuse.insert(*root);
                            }
                            EntryKind::File {
                                exec: child.exec,
                                size: child.size,
                                grains,
                            }
                        }""",
        f"{TESTS}::incremental::a_changed_spilled_file_uploads_its_grain_list",
        "the accepted binmap does not resolve",
    ),
    "f_skip_new_directories_outside_the_rebuild_set": (
        PROJECTION,
        """OverlayKind::Directory if !base_dirs.contains(&entry.inode) => {
                    seeds.insert(entry.inode);
                }""",
        "OverlayKind::Directory if !base_dirs.contains(&entry.inode) => {}",
        f"{TESTS}::incremental::an_empty_directory_created_since_the_base_and_untouched_now_is_built",
        "incremental acceptance",
    ),
    "g_reinstate_the_per_entry_pre_charge": (
        ENGINE,
        'budget.charge_as("effects", boundary.effects().len() * 256)?;',
        """budget.charge_as("effects", boundary.effects().len() * 256)?;
        for entry in boundary.entries().iter().chain(boundary.base_entries()) {
            let bytes = entry
                .path
                .iter()
                .try_fold(256_usize, |total, name| {
                    total.checked_add(name.as_bytes().len() + 64)
                })
                .ok_or_else(|| refused("SyncGraphOverflow"))?;
            budget.charge(bytes)?;
        }""",
        f"{ENGINE_TESTS}::incremental::fsync_charge_independent_of_volume",
        "file base refused its fsync",
    ),
    "h_skip_validating_a_new_directory": (
        OBJECTS,
        "manifest::tree::validate_dir_btree_seeded(",
        """(|_: &GrainId,
          _: &dyn Fn(&GrainId) -> Option<Vec<u8>>,
          _: &BTreeSet<(GrainId, u64, u32)>|
         -> Result<(Vec<DirEntry>, Vec<GrainId>), manifest::ValidateError> {
            Ok((Vec::new(), Vec::new()))
        })(""",
        f"{TESTS}::incremental::a_changed_file_whose_grain_list_lies_is_refused_before_any_upload",
        "the row was accepted",
    ),
    "i_navigate_an_unvalidated_decode_in_completion": (
        CAPTURE,
        """let (entries, _children) =
            manifest::validate_dir_btree(&dir, &|id| source.get(id).ok()).map_err(|_| lost())?;""",
        "let entries = entries(source, dir, 1)?;",
        f"{TESTS}::coordination::captures::a_duplicate_name_across_sibling_leaves_on_the_covering_path_loses_coverage",
        "DuplicateOnPath",
    ),
    "j_skip_the_attach_validation": (
        BASE,
        """granary_core::manifest::validate_dir_tree(&doc.manifest_root, &|id| source.get(id).ok())
            .map_err(|_| refused())?;""",
        "let _ = source;",
        f"{ENGINE_TESTS}::incremental::a_signed_base_with_a_doctored_spill_tree_refuses_at_attach",
        "a correctly signed base with a lying grain-list claim attached",
    ),
    "k_drop_the_refresh_containment_check": (
        COMMIT,
        'Some(mapped) if !mapped.contains(id) => Err(refused("SyncCommitContainment")),',
        'Some(_) if false => Err(refused("SyncCommitContainment")),',
        "sync::engine::commit::tests::a_landed_walk_refuses_any_object_its_binmap_does_not_resolve",
        "was accepted",
    ),
    "l_remove_the_per_node_charge": (
        ENGINE,
        'budget.charge_as("retain", bytes.len())?;',
        "let _ = bytes.len();",
        f"{ENGINE_TESTS}::incremental::an_insert_into_an_oversized_directory_refuses_workspace",
        "called `Result::unwrap_err()` on an `Ok` value",
    ),
}


def replace_once(source, before, after):
    positions = [i for i, char in enumerate(source) if not char.isspace()]
    compact = "".join(source[i] for i in positions)
    anchor = "".join(before.split())
    if not anchor or compact.count(anchor) != 1:
        raise ValueError("MutationAnchorNotUnique")
    start = compact.index(anchor)
    return source[:positions[start]] + after + source[positions[start + len(anchor) - 1] + 1:]


def verdict(code, output, test, marker):
    count = re.search(r"Starting (\d+) tests? across", output)
    identities = set(re.findall(r"(?:PASS|FAIL)\s+\[[^\]]*\]\s+\(\s*\d+/\d+\)\s+\S+\s+(\S+)", output))
    if count is None or int(count.group(1)) != 1 or identities != {test}:
        raise ValueError("MutationSelectionMissingOrWrong")
    if code == 0:
        return "SURVIVED"
    if code != 100 or marker not in output:
        raise ValueError("MutationIntendedAssertionMissing")
    return "KILLED"


def run(test):
    package = "granary-client"
    argv = ["cargo", "nextest", "run", "--profile", "ci", "--locked", "-p", package,
            "--features", "granary-client/overlay-fault-tests", "-E", f"test(={test})"]
    result = subprocess.run(argv, cwd=ROOT, env=dict(os.environ, CARGO_NET_OFFLINE="true", CARGO_BUILD_JOBS="1"),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=900)
    return result.returncode, result.stdout


def self_test():
    assert replace_once("a b c", "b", "z") == "a z c"
    controls = [
        lambda: replace_once("a a", "a", "z"),
        lambda: replace_once("abc", "missing", "z"),
        lambda: verdict(100, "Starting 0 tests across", "oracle", "intended"),
        lambda: verdict(100, "Starting 1 tests across\n FAIL [ 0.1s] ( 1/1) granary-client wrong\nintended", "oracle", "intended"),
        lambda: verdict(101, "Starting 1 tests across\n FAIL [ 0.1s] ( 1/1) granary-client oracle", "oracle", "intended"),
    ]
    for control in controls:
        try:
            control()
        except ValueError:
            continue
        raise AssertionError("MutationMalformedControlAccepted")
    text = "Starting 1 tests across\n        FAIL [   0.1s] ( 1/1) granary-client oracle\nintended"
    assert verdict(100, text, "oracle", "intended") == "KILLED"
    text = "Starting 1 tests across\n        PASS [   0.1s] ( 1/1) granary-client oracle\n"
    assert verdict(0, text, "oracle", "intended") == "SURVIVED"
    print("self-controls: 5 refused; valid kill and survivor accepted")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("names", nargs="*", choices=tuple(MUTANTS))
    args = parser.parse_args()
    self_test()
    if args.self_test:
        return
    names = args.names or list(MUTANTS)
    outcomes = []
    for name in names:
        relative, before, after, test, marker = MUTANTS[name]
        path = ROOT / relative
        original = path.read_bytes()
        if not original:
            raise ValueError("MutationSourceEmpty")
        digest = hashlib.sha256(original).hexdigest()
        mutated = replace_once(original.decode(), before, after)
        if mutated.encode() == original:
            raise ValueError("MutationDidNotChangeTheSource")
        print("".join(difflib.unified_diff(original.decode().splitlines(True), mutated.splitlines(True),
                                         fromfile=relative, tofile=relative)), flush=True)
        try:
            path.write_text(mutated)
            if path.read_text() != mutated:
                raise ValueError("MutationDidNotLand")
            print(f"{name}: edit landed in {relative}", flush=True)
            code, output = run(test)
            outcome = verdict(code, output, test, marker)
            outcomes.append(outcome)
            print(f"{name}: {outcome}; rc={code}; selected=1; assertion={marker!r}", flush=True)
        finally:
            path.write_bytes(original)
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("MutationRestorationMismatch")
        code, output = run(test)
        if code != 0 or verdict(code, output, test, marker) != "SURVIVED":
            raise ValueError("MutationRestoredControlFailed")
        print(f"{name}: restored control PASS; source SHA-256={digest}", flush=True)
    if not outcomes or any(outcome != "KILLED" for outcome in outcomes):
        raise SystemExit("MutationSurvivorOrEmptySelection")


if __name__ == "__main__":
    main()
