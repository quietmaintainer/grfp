use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use filetime::{FileTime, set_file_mtime};
use grfp::{
    archive, gf16,
    recipe::{self, Profile, TemplatePolicy, TextPolicy, Window},
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[derive(Clone)]
struct Frame {
    kind: u8,
    slot: u16,
    at: usize,
    end: usize,
}

fn frames(archive: &[u8]) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut at = 0;
    while at < archive.len() {
        assert_eq!(&archive[at..at + 8], b"GRP1\r\n\x1a\n");
        let length = u32::from_le_bytes(archive[at + 13..at + 17].try_into().unwrap()) as usize;
        let end = at + 81 + length;
        frames.push(Frame {
            kind: archive[at + 8],
            slot: u16::from_le_bytes(archive[at + 9..at + 11].try_into().unwrap()),
            at,
            end,
        });
        at = end;
    }
    assert_eq!(at, archive.len());
    frames
}

fn cut(archive: &[u8], remove: impl Fn(&Frame) -> bool) -> Vec<u8> {
    frames(archive)
        .into_iter()
        .filter(|f| !remove(f))
        .flat_map(|f| &archive[f.at..f.end])
        .copied()
        .collect()
}

fn frame_with(archive: &[u8], template: &Frame, id: &[u8], body: &[u8]) -> Vec<u8> {
    let mut header = archive[template.at..template.at + 81].to_vec();
    header[13..17].copy_from_slice(&(body.len() as u32).to_le_bytes());
    header[17..49].copy_from_slice(id);
    let digest = Sha256::new()
        .chain_update(&header[8..49])
        .chain_update(body)
        .finalize();
    header[49..81].copy_from_slice(&digest);
    header.extend_from_slice(body);
    header
}

fn same_files(directory: &Path, canonical: &Path) {
    for name in ["restored.bin", "recipe.grf", "protected.grfp"] {
        assert_eq!(
            fs::read(directory.join(name)).unwrap(),
            fs::read(canonical.join(name)).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn published_regrow8_recipe_frames_recover_byte_for_byte() {
    let temp = tempdir().unwrap();
    let hashes = [
        (
            "alu",
            "181c90d3bd92e7634d8a6bb4e504f02e988c31a8906afc3886910c73954ec0bb",
        ),
        (
            "cpu",
            "1090e19324489dee52122af18efe19fdef496c92cb86415f756dedcd4d67263a",
        ),
    ];
    for (name, expected) in hashes {
        let source = fixture(&format!("regrow8/{name}.grfp"));
        let bytes = fs::read(&source).unwrap();
        let canonical = temp.path().join(format!("{name}-intact"));
        archive::recover(&source, &canonical, None).unwrap();
        let corrupted = temp.path().join(format!("{name}-damaged.grfp"));
        fs::write(&corrupted, cut(&bytes, |f| f.kind == 3 && f.slot == 1)).unwrap();
        let recovered = temp.path().join(name);
        let stats = archive::recover(&corrupted, &recovered, None).unwrap();
        assert_eq!(stats.archive.original_sha256, expected);
        assert_eq!(fs::read(recovered.join("protected.grfp")).unwrap(), bytes);
        same_files(&recovered, &canonical);
        let original = temp.path().join(format!("{name}.bin"));
        let only = archive::recover_original(&corrupted, &original, None).unwrap();
        assert_eq!(only.recipe_groups_from_parity, 1);
        assert_eq!(only.original_sha256, expected);
        assert_eq!(
            fs::read(original).unwrap(),
            fs::read(recovered.join("restored.bin")).unwrap()
        );
    }
}

#[test]
fn node_global16_rebuilds_missing_catalog_and_corrupt_body_header() {
    let temp = tempdir().unwrap();
    let source = fixture("node-global16/global.grfp");
    let bytes = fs::read(source).unwrap();
    let mut header_cut = bytes.clone();
    let data = frames(&bytes)
        .into_iter()
        .find(|f| f.kind == 3 && f.slot == 1)
        .unwrap();
    header_cut[data.at + 13..data.at + 17].fill(255);
    let cases = [
        (
            "catalog",
            cut(&bytes, |f| f.kind == 0 || (f.kind == 3 && f.slot == 0)),
        ),
        ("header", header_cut),
    ];
    for (name, damaged) in cases {
        let input = temp.path().join(format!("{name}.grfp"));
        let out = temp.path().join(name);
        fs::write(&input, damaged).unwrap();
        let result = archive::recover(&input, &out, None).unwrap();
        assert_eq!(
            result.catalog_pieces_from_parity,
            usize::from(name == "catalog")
        );
        assert_eq!(
            fs::read(out.join("restored.bin")).unwrap(),
            fs::read(fixture("node-global16/sample.bin")).unwrap()
        );
        assert_eq!(
            fs::read(out.join("recipe.grf")).unwrap(),
            fs::read(fixture("node-global16/plain.grf")).unwrap()
        );
        assert_eq!(fs::read(out.join("protected.grfp")).unwrap(), bytes);
        let original = temp.path().join(format!("{name}.bin"));
        let only = archive::recover_original(&input, &original, None).unwrap();
        assert_eq!(
            only.catalog_pieces_from_parity,
            result.catalog_pieces_from_parity
        );
        assert_eq!(
            fs::read(original).unwrap(),
            fs::read(out.join("restored.bin")).unwrap()
        );
    }
}

#[test]
fn unrecoverable_input_and_existing_destinations_are_left_intact() {
    let temp = tempdir().unwrap();
    let bytes = fs::read(fixture("node-global16/global.grfp")).unwrap();
    let corrupted = temp.path().join("broken.grfp");
    fs::write(
        &corrupted,
        cut(&bytes, |f| f.kind == 4 || (f.kind == 3 && f.slot == 1)),
    )
    .unwrap();
    let out = temp.path().join("out");
    assert!(archive::recover(&corrupted, &out, None).is_err());
    assert!(!out.exists());
    fs::create_dir(&out).unwrap();
    fs::write(out.join("restored.bin"), b"keep").unwrap();
    assert!(archive::recover(&fixture("node-global16/global.grfp"), &out, None).is_err());
    assert_eq!(fs::read(out.join("restored.bin")).unwrap(), b"keep");
}

#[test]
fn cli_recovers_only_the_original_and_preserves_existing_outputs() {
    let temp = tempdir().unwrap();
    let target = temp.path().join("result.bin");
    let recover = || {
        Command::new(env!("CARGO_BIN_EXE_grfp"))
            .arg("recover-original")
            .arg(fixture("node-global16/global.grfp"))
            .arg(&target)
            .output()
            .unwrap()
    };
    let response = recover();
    assert!(
        response.status.success(),
        "{}",
        String::from_utf8_lossy(&response.stderr)
    );
    let stats: serde_json::Value = serde_json::from_slice(&response.stdout).unwrap();
    let original = fs::read(fixture("node-global16/sample.bin")).unwrap();
    assert_eq!(stats["originalBytes"], original.len());
    assert_eq!(
        stats["originalSha256"],
        format!("{:x}", Sha256::digest(&original))
    );
    assert_eq!(stats["recipeGroupsFromParity"], 0);
    assert_eq!(fs::read(&target).unwrap(), original);
    assert_eq!(temp.path().read_dir().unwrap().count(), 1);
    fs::write(&target, b"keep").unwrap();
    assert!(!recover().status.success());
    assert_eq!(fs::read(target).unwrap(), b"keep");
}

#[test]
fn original_only_can_copy_a_verified_donor_without_parity() {
    let temp = tempdir().unwrap();
    let bytes = fs::read(fixture("node-global16/global.grfp")).unwrap();
    let broken = temp.path().join("missing.grfp");
    fs::write(
        &broken,
        cut(&bytes, |f| f.kind == 4 || (f.kind == 3 && f.slot == 1)),
    )
    .unwrap();
    let out = temp.path().join("output.bin");
    let bad_donor = temp.path().join("bad.bin");
    fs::write(&bad_donor, b"wrong").unwrap();
    assert!(archive::recover_original(&broken, &out, Some(&bad_donor)).is_err());
    assert!(!out.exists());
    let donor = fixture("node-global16/sample.bin");
    let stats = archive::recover_original(&broken, &out, Some(&donor)).unwrap();
    assert_eq!(stats.original_groups_from_damaged, 1);
    assert_eq!(stats.recipe_groups_from_parity, 0);
    assert_eq!(fs::read(out).unwrap(), fs::read(donor).unwrap());
}

#[test]
fn original_only_handles_donors_inside_and_outside_the_parity_budget() {
    const GROUP: usize = 256 * 1024;
    let temp = tempdir().unwrap();
    let source = temp.path().join("source.bin");
    let raw = [vec![48; GROUP], vec![52; GROUP], vec![53; 17]].concat();
    fs::write(&source, &raw).unwrap();
    let intact = temp.path().join("intact.grfp");
    let profile = Profile {
        text: TextPolicy::Off,
        templates: TemplatePolicy::Off,
        text_window: Window::Page,
        ..Profile::default()
    };
    archive::pack(&source, &intact, profile, 50).unwrap();
    let donor = temp.path().join("damaged.bin");
    fs::write(&donor, &raw[..GROUP]).unwrap();
    let archive = fs::read(intact).unwrap();
    for remove_parity in [false, true] {
        let broken = temp.path().join(format!("damaged-{remove_parity}.grfp"));
        let original = temp.path().join(format!("recovered-{remove_parity}.bin"));
        fs::write(
            &broken,
            cut(&archive, |f| {
                (f.kind == 3 && matches!(f.slot, 1 | 2))
                    || (remove_parity && f.kind == 4 && f.slot == 1)
            }),
        )
        .unwrap();
        let stats = archive::recover_original(&broken, &original, Some(&donor)).unwrap();
        assert_eq!(stats.original_groups_from_damaged, 1);
        assert_eq!(stats.recipe_groups_from_parity, 1);
        assert_eq!(fs::read(original).unwrap(), raw);
    }
}

#[test]
fn original_only_checks_the_whole_file_hash_before_publishing() {
    let temp = tempdir().unwrap();
    let archive = fs::read(fixture("node-global16/global.grfp")).unwrap();
    let frames = frames(&archive);
    let data = frames.iter().find(|f| f.kind == 3 && f.slot == 1).unwrap();
    let tail = frames.iter().find(|f| f.kind == 0).unwrap();
    let mut catalog: serde_json::Value =
        serde_json::from_slice(&archive[tail.at + 81..tail.end]).unwrap();
    catalog["originalSha256"] = "0".repeat(64).into();
    let catalog = serde_json::to_vec(&catalog).unwrap();
    let id = Sha256::digest(&catalog);
    let input = temp.path().join("wrong-hash.grfp");
    fs::write(
        &input,
        [
            frame_with(&archive, data, &id, &archive[data.at + 81..data.end]),
            frame_with(&archive, tail, &id, &catalog),
        ]
        .concat(),
    )
    .unwrap();
    let out = temp.path().join("result.bin");
    let error = archive::recover_original(&input, &out, None).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("Final original length or checksum mismatch"),
        "{error}"
    );
    assert!(!out.exists());
}

#[test]
fn rust_archives_support_cross_repair_and_parity_changes() {
    let temp = tempdir().unwrap();
    let source = fixture("node-global16/sample.bin");
    let whole = temp.path().join("whole.grfp");
    let profile = Profile::default();
    archive::pack(&source, &whole, profile.clone(), 0).unwrap();
    let bytes = fs::read(&whole).unwrap();
    let partial = temp.path().join("partial.grfp");
    fs::write(&partial, cut(&bytes, |f| f.kind == 3 && f.slot == 1)).unwrap();
    let out = temp.path().join("out");
    archive::recover(&partial, &out, Some(&source)).unwrap();
    assert_eq!(fs::read(out.join("protected.grfp")).unwrap(), bytes);
    assert_eq!(
        fs::read(out.join("restored.bin")).unwrap(),
        fs::read(&source).unwrap()
    );

    let protected = temp.path().join("protected.grfp");
    let reprotected = temp.path().join("reprotected.grfp");
    archive::protect(&out.join("recipe.grf"), &protected, profile, 50).unwrap();
    archive::reprotect(&whole, &reprotected, Some(50)).unwrap();
    assert_eq!(
        fs::read(&protected).unwrap(),
        fs::read(&reprotected).unwrap()
    );
    let plain = temp.path().join("plain.bin");
    recipe::restore(&out.join("recipe.grf"), &plain, None).unwrap();
    assert_eq!(fs::read(&plain).unwrap(), fs::read(&source).unwrap());
}

#[test]
fn cli_packs_global16_and_rejects_local8() {
    let temp = tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_grfp");
    let input = temp.path().join("empty");
    let target = temp.path().join("empty.grfp");
    fs::write(&input, []).unwrap();
    let run = |flags: &[&str]| {
        Command::new(binary)
            .arg("pack")
            .arg(&input)
            .arg(&target)
            .args(flags)
            .output()
            .unwrap()
    };
    assert!(!run(&["--fec", "local8"]).status.success());
    assert!(!target.exists());
    let packed = run(&[]);
    assert!(
        packed.status.success(),
        "{}",
        String::from_utf8_lossy(&packed.stderr)
    );
    let stats: serde_json::Value = serde_json::from_slice(&packed.stdout).unwrap();
    assert_eq!(stats["fec"], "global16");
    let out = temp.path().join("result");
    archive::recover(&target, &out, None).unwrap();
    assert_eq!(fs::read(out.join("restored.bin")).unwrap(), b"");
}

#[test]
fn split_volumes_recover_an_erased_primary_and_allow_rebuilding_a_custom_recipe() {
    let temp = tempdir().unwrap();
    let dir = temp.path();
    let input = dir.join("file.bin");
    let raw: Vec<_> = (0..(4 * 4096 + 71)).map(|i| (i % 247) as u8).collect();
    fs::write(&input, &raw).unwrap();
    let primary = dir.join("file.grfp");
    let pack = archive::PackOptions {
        block_size: 4096,
        parity: 100,
        recovery_volumes: 2,
        ..Default::default()
    };
    let stats = archive::pack_with(&input, &primary, Profile::default(), &pack).unwrap();
    assert_eq!(stats.groups, 5);
    assert_eq!(stats.parity_frames, 5);
    assert_eq!(
        stats.recovery_volumes,
        [dir.join("file.grfp.rec.001"), dir.join("file.grfp.rec.002")]
    );
    let a = fs::read(&stats.recovery_volumes[0]).unwrap();
    let b = fs::read(&stats.recovery_volumes[1]).unwrap();
    assert_eq!(
        frames(&a).iter().map(|f| f.kind).collect::<Vec<_>>(),
        [4, 4, 4, 0]
    );
    assert_eq!(
        frames(&b).iter().map(|f| f.kind).collect::<Vec<_>>(),
        [4, 4, 0]
    );
    assert!(
        frames(&fs::read(&primary).unwrap())
            .iter()
            .all(|f| f.kind != 4)
    );

    let options = archive::ReadOptions {
        volumes: &stats.recovery_volumes[1..],
        ..Default::default()
    };
    let full = dir.join("complete");
    let recovered =
        archive::recover_with(&stats.recovery_volumes[0], &full, None, &options).unwrap();
    assert_eq!(recovered.archive.block_size, 4096);
    assert_eq!(recovered.archive.inner_format, "GRF2");
    assert_eq!(fs::read(full.join("restored.bin")).unwrap(), raw);
    let standalone = dir.join("standalone.bin");
    recipe::restore(&full.join("recipe.grf"), &standalone, None).unwrap();
    assert_eq!(fs::read(standalone).unwrap(), raw);
    let sealed = dir.join("sealed.grfp");
    archive::protect(&full.join("recipe.grf"), &sealed, Profile::default(), 100).unwrap();
    assert_eq!(
        fs::read(&sealed).unwrap(),
        fs::read(full.join("protected.grfp")).unwrap()
    );
    let split_again = dir.join("split-again.grfp");
    let split = archive::reprotect_with_volumes(&sealed, &split_again, None, 2).unwrap();
    assert_eq!(fs::read(split_again).unwrap(), fs::read(&primary).unwrap());
    assert_eq!(fs::read(&split.recovery_volumes[0]).unwrap(), a);
    assert_eq!(fs::read(&split.recovery_volumes[1]).unwrap(), b);

    let fail = dir.join("too-few.bin");
    assert!(archive::recover_original(&stats.recovery_volumes[0], &fail, None).is_err());
    assert!(!fail.exists());
    let duplicates = archive::ReadOptions {
        volumes: &stats.recovery_volumes[..1],
        ..Default::default()
    };
    assert!(
        archive::recover_original_with(&stats.recovery_volumes[0], &fail, None, &duplicates)
            .is_err()
    );
    assert!(!fail.exists());
    let conflict = dir.join("conflict.grfp");
    fs::write(dir.join("conflict.grfp.rec.002"), b"keep").unwrap();
    assert!(archive::pack_with(&input, &conflict, Profile::default(), &pack).is_err());
    assert!(!conflict.exists());
    assert!(!dir.join("conflict.grfp.rec.001").exists());
    assert_eq!(
        fs::read(dir.join("conflict.grfp.rec.002")).unwrap(),
        b"keep"
    );
}

fn cli(dir: &Path, args: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_grfp"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "grfp {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn encrypted_signed_tree_recovers_with_a_lost_volume_and_preserves_metadata() {
    let temp = tempdir().unwrap();
    let dir = temp.path();
    let root = dir.join("Flight notes");
    let nested = root.join("logs");
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir(root.join("Empty directory")).unwrap();
    let file = nested.join("reactor é.txt");
    let raw = b"Private hardware notes\n".repeat(1153);
    fs::write(&file, &raw).unwrap();
    let timestamp = FileTime::from_unix_time(1_650_000_003, 123_456_700);
    set_file_mtime(&file, timestamp).unwrap();
    set_file_mtime(&nested, timestamp).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o750)).unwrap();
    }
    cli(dir, &["keygen-encryption", "secret.key"]);
    cli(dir, &["keygen-signing", "signer.key", "signer.pub"]);
    let pack = cli(
        dir,
        &[
            "pack",
            "Flight notes",
            "tree.grfp",
            "--block-size",
            "4KiB",
            "--parity",
            "60",
            "--recovery-volumes",
            "2",
            "--encrypt-key",
            "secret.key",
            "--sign-key",
            "signer.key",
        ],
    );
    assert_eq!(pack["blockSize"], 4096);
    let primary = fs::read(dir.join("tree.grfp")).unwrap();
    let recovered_primary = dir.join("broken.grfp");
    fs::write(
        &recovered_primary,
        cut(&primary, |f| f.kind == 0 || (f.kind == 3 && f.slot <= 2)),
    )
    .unwrap();
    let volumes = [dir.join("tree.grfp.rec.001")];
    let other = fs::read(&volumes[0]).unwrap();
    let name = "reactor é.txt".as_bytes();
    assert!(
        ![primary, other]
            .iter()
            .any(|part| part.windows(name.len()).any(|w| w == name))
    );

    let inspected = cli(
        dir,
        &[
            "inspect",
            "broken.grfp",
            "--volume",
            "tree.grfp.rec.001",
            "--trusted-key",
            "signer.pub",
        ],
    );
    assert_eq!(inspected["signature"]["trusted"], true);
    assert!(inspected["catalog"]["originalSha256"].is_null());
    assert!(inspected["catalog"]["groups"][0][1].is_null());
    assert!(inspected["catalog"]["encryption"].is_object());
    let key = dir.join("secret.key");
    let trusted = dir.join("signer.pub");
    let options = archive::ReadOptions {
        volumes: &volumes,
        key: Some(&key),
        trusted_key: Some(&trusted),
    };
    let output = dir.join("restored");
    let other_key = dir.join("wrong.key");
    archive::generate_encryption_key(&other_key).unwrap();
    assert!(
        archive::extract(
            &recovered_primary,
            &output,
            &archive::ReadOptions {
                key: Some(&other_key),
                ..options
            }
        )
        .is_err()
    );
    assert!(!output.exists());
    assert!(
        archive::extract(
            &recovered_primary,
            &output,
            &archive::ReadOptions {
                key: None,
                ..options
            }
        )
        .is_err()
    );
    assert!(!output.exists());
    cli(dir, &["keygen-signing", "other.key", "other.pub"]);
    assert!(
        archive::extract(
            &recovered_primary,
            &output,
            &archive::ReadOptions {
                trusted_key: Some(&dir.join("other.pub")),
                ..options
            }
        )
        .is_err()
    );
    assert!(!output.exists());

    let extracted = cli(
        dir,
        &[
            "extract",
            "broken.grfp",
            "restored",
            "--volume",
            "tree.grfp.rec.001",
            "--key",
            "secret.key",
            "--trusted-key",
            "signer.pub",
        ],
    );
    assert_eq!(extracted["entries"], 4);
    assert_eq!(extracted["recipeGroupsFromParity"], 2);
    assert_eq!(extracted["signature"]["trusted"], true);
    let restored = output.join("Flight notes");
    assert!(restored.join("Empty directory").is_dir());
    let restored_file = restored.join("logs/reactor é.txt");
    assert_eq!(fs::read(&restored_file).unwrap(), raw);
    for path in [&restored_file, &restored.join("logs")] {
        assert_eq!(
            FileTime::from_last_modification_time(&fs::metadata(path).unwrap()),
            timestamp
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(restored_file).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }
    assert!(archive::extract(&recovered_primary, &output, &options).is_err());
    assert!(
        archive::verify(&recovered_primary, &options)
            .unwrap()
            .signature
            .unwrap()
            .trusted
    );
}

#[test]
fn verified_content_rejects_catalog_tampering_and_unsigned_archives() {
    let temp = tempdir().unwrap();
    let dir = temp.path();
    let source = dir.join("input");
    fs::write(&source, b"signed recipe").unwrap();
    let private = dir.join("signer.key");
    let public = dir.join("signer.pub");
    archive::generate_signing_key(&private, &public).unwrap();
    let signed = dir.join("signed.grfp");
    let options = archive::PackOptions {
        sign_key: Some(&private),
        ..Default::default()
    };
    archive::pack_with(&source, &signed, Profile::default(), &options).unwrap();
    let trusted = archive::ReadOptions {
        trusted_key: Some(&public),
        ..Default::default()
    };
    assert!(
        archive::verify(&signed, &trusted)
            .unwrap()
            .signature
            .unwrap()
            .trusted
    );
    assert!(
        !archive::verify(&signed, &Default::default())
            .unwrap()
            .signature
            .unwrap()
            .trusted
    );
    let unsigned = dir.join("unsigned.grfp");
    archive::pack(&source, &unsigned, Profile::default(), 5).unwrap();
    assert!(archive::verify(&unsigned, &trusted).is_err());

    let bytes = fs::read(&signed).unwrap();
    let parsed = frames(&bytes);
    let tail = parsed.iter().find(|f| f.kind == 0).unwrap();
    let catalog = std::str::from_utf8(&bytes[tail.at + 81..tail.end]).unwrap();
    let tampered = catalog.replacen("\"percent\":5", "\"percent\":6", 1);
    assert_ne!(tampered, catalog);
    let fake = dir.join("fake.grfp");
    fs::write(
        &fake,
        frame_with(
            &bytes,
            tail,
            &Sha256::digest(&tampered),
            tampered.as_bytes(),
        ),
    )
    .unwrap();
    let error = archive::verify(&fake, &trusted).err().unwrap();
    assert_eq!(error.to_string(), "Invalid archive signature");
}

#[test]
fn encrypted_empty_file_requires_the_correct_key() {
    let temp = tempdir().unwrap();
    let dir = temp.path();
    let source = dir.join("empty.bin");
    let target = dir.join("archive.grfp");
    let second = dir.join("second.grfp");
    let key = dir.join("secret.key");
    fs::write(&source, b"").unwrap();
    archive::generate_encryption_key(&key).unwrap();
    let pack = archive::PackOptions {
        encrypt_key: Some(&key),
        ..Default::default()
    };
    archive::pack_with(&source, &target, Profile::default(), &pack).unwrap();
    archive::pack_with(&source, &second, Profile::default(), &pack).unwrap();
    assert_ne!(fs::read(&target).unwrap(), fs::read(second).unwrap());
    let output = dir.join("restored.bin");
    assert!(archive::recover_original(&target, &output, None).is_err());
    assert!(!output.exists());
    let options = archive::ReadOptions {
        key: Some(&key),
        ..Default::default()
    };
    assert_eq!(
        archive::recover_original_with(&target, &output, None, &options)
            .unwrap()
            .original_bytes,
        0
    );
    assert_eq!(fs::read(output).unwrap(), b"");
}

#[test]
fn encrypted_blocks_reject_changes_even_with_matching_outer_checksums() {
    let temp = tempdir().unwrap();
    let dir = temp.path();
    let source = dir.join("original");
    fs::write(&source, b"authenticated content").unwrap();
    let encrypted = dir.join("encrypted.grfp");
    let key = dir.join("secret.key");
    archive::generate_encryption_key(&key).unwrap();
    let pack = archive::PackOptions {
        encrypt_key: Some(&key),
        parity: 0,
        ..Default::default()
    };
    archive::pack_with(&source, &encrypted, Profile::default(), &pack).unwrap();
    let bytes = fs::read(encrypted).unwrap();
    let parsed = frames(&bytes);
    let tail = parsed.iter().find(|f| f.kind == 0).unwrap();
    let data = parsed.iter().find(|f| f.kind == 3 && f.slot == 1).unwrap();
    let mut catalog: serde_json::Value =
        serde_json::from_slice(&bytes[tail.at + 81..tail.end]).unwrap();
    let mut wire = bytes[data.at + 81..data.end].to_vec();
    wire[0] ^= 1;
    catalog["groups"][0][2] = format!("{:x}", Sha256::digest(&wire)).into();
    let catalog = serde_json::to_vec(&catalog).unwrap();
    let id = Sha256::digest(&catalog);
    let fake = dir.join("changed.grfp");
    fs::write(
        &fake,
        [
            frame_with(&bytes, data, &id, &wire),
            frame_with(&bytes, tail, &id, &catalog),
        ]
        .concat(),
    )
    .unwrap();
    let output = dir.join("restored");
    let options = archive::ReadOptions {
        key: Some(&key),
        ..Default::default()
    };
    let error = archive::recover_original_with(&fake, &output, None, &options)
        .err()
        .unwrap();
    assert!(error.to_string().contains("Archive authentication failed"));
    assert!(!output.exists());
}

#[test]
fn gf16_matches_an_independent_field_oracle_with_odd_shards() {
    fn multiply(mut a: u32, mut b: u32) -> u32 {
        let mut sum = 0;
        while b > 0 {
            if b & 1 != 0 {
                sum ^= a;
            }
            b >>= 1;
            a <<= 1;
            if a & 65_536 != 0 {
                a ^= 0x1100b;
            }
        }
        sum
    }
    fn inverse(mut a: u32) -> u32 {
        let mut pow = 65_534;
        let mut out = 1;
        while pow > 0 {
            if pow & 1 != 0 {
                out = multiply(out, a);
            }
            a = multiply(a, a);
            pow >>= 1;
        }
        out
    }
    let d = 318;
    let input: Vec<_> = (0..d)
        .map(|i| [i as u8, (i >> 8) as u8, 197, i as u8 & 127, 11][..(i % 5 + 1)].to_vec())
        .collect();
    let mut parity = Vec::new();
    gf16::encode(
        d,
        5,
        6,
        |i| Ok(input[i].clone()),
        |_, p| {
            parity.push(p.to_vec());
            Ok(())
        },
    )
    .unwrap();
    for (p, bytes) in parity.iter().enumerate() {
        for (j, pair) in bytes.chunks_exact(2).enumerate() {
            let expected = input.iter().enumerate().fold(0, |acc, (i, b)| {
                let low = b.get(j * 2).copied().unwrap_or(0) as u32;
                let high = b.get(j * 2 + 1).copied().unwrap_or(0) as u32;
                acc ^ multiply(inverse(((d + p) ^ i) as u32), low | (high << 8))
            });
            assert_eq!(
                u16::from_le_bytes(pair.try_into().unwrap()) as u32,
                expected
            );
        }
    }
    let lost = [0, 255, 256, 317];
    let targets: Vec<_> = lost.iter().map(|&i| (i, input[i].len())).collect();
    gf16::decode(
        gf16::Recovery {
            systematic: d,
            missing: &lost,
            rows: &[4, 2, 0, 1],
            wanted: &targets,
            width: 6,
        },
        |i| Ok(input[i].clone()),
        |p| Ok(parity[p].clone()),
        |i, b| {
            assert_eq!(b, input[i]);
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn rust_text_windows_round_trip_literal_and_transformed_records() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("source");
    let mut x = 731u32;
    let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ   ";
    let a: Vec<_> = (0..131_072)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            alphabet[((x & 255) as usize) % alphabet.len()]
        })
        .collect();
    let line = [b"001 007 045 ".as_slice(), &a[17..6200], b"\n"].concat();
    let raw =
        [line.repeat(4).as_slice(), &a, b"\n", &a[..65_536]].concat()[..13 * 16_384 + 19].to_vec();
    fs::write(&source, &raw).unwrap();
    for (i, window) in [
        Window::Page,
        Window::Reset64,
        Window::Wide,
        Window::Reset256,
        Window::Group,
    ]
    .into_iter()
    .enumerate()
    {
        let path = temp.path().join(format!("{i}.grfp"));
        let out = temp.path().join(format!("out{i}"));
        let p = Profile {
            width: None,
            text: TextPolicy::Span,
            templates: TemplatePolicy::Auto,
            text_window: window,
        };
        archive::pack(&source, &path, p, 5).unwrap();
        archive::recover(&path, &out, None).unwrap();
        assert_eq!(fs::read(out.join("restored.bin")).unwrap(), raw);
        if window == Window::Group {
            let stats = recipe::inspect(&out.join("recipe.grf")).unwrap();
            assert_eq!(stats["methods"]["text-span-256"], 1);
        }
    }
}
