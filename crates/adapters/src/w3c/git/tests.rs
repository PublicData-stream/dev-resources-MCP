use super::*;
use axum::{
    Router,
    body::Bytes,
    routing::{get, post},
};
pub(crate) async fn input(git: &W3cGit, args: &[&str], bytes: &[u8]) -> Vec<u8> {
    let mut command = git.command();
    command
        .args(args)
        .env("GIT_AUTHOR_NAME", "Synthetic fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
        .env("GIT_COMMITTER_NAME", "Synthetic fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000")
        .env("GIT_PROTOCOL", "version=2")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut child = ManagedChild::spawn(command).unwrap();
    child
        .child
        .stdin
        .take()
        .unwrap()
        .write_all(bytes)
        .await
        .unwrap();
    let mut output = Vec::new();
    child
        .child
        .stdout
        .take()
        .unwrap()
        .take(1024 * 1024)
        .read_to_end(&mut output)
        .await
        .unwrap();
    let status = child.child.wait().await.unwrap();
    child.finished = true;
    child.terminate().await.unwrap();
    assert!(status.success(), "fixture Git command failed");
    output
}
fn oid(bytes: Vec<u8>) -> String {
    crate_git::parse_oid_line(&bytes).unwrap()
}
pub(crate) async fn update(git: &W3cGit, name: &str, oid: &str) {
    git.run(
        &["update-ref", name, oid],
        128,
        &CancellationToken::new(),
        Instant::now() + READ_RUNTIME,
    )
    .await
    .unwrap();
}
pub(crate) fn fixture_router(source: Arc<W3cGit>) -> Router {
    let prefix = url::Url::parse(&source.repo.source_url())
        .unwrap()
        .path()
        .to_owned();
    let advertise = source.clone();
    let upload = source;
    Router::new()
        .route(
            &format!("{prefix}/info/refs"),
            get(move || {
                let source = advertise.clone();
                async move {
                    let repository = source.repository();
                    let bytes = input(
                        &source,
                        &[
                            "upload-pack",
                            "--stateless-rpc",
                            "--advertise-refs",
                            repository.to_str().unwrap(),
                        ],
                        b"",
                    )
                    .await;
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/x-git-upload-pack-advertisement",
                        )],
                        bytes,
                    )
                }
            }),
        )
        .route(
            &format!("{prefix}/git-upload-pack"),
            post(move |body: Bytes| {
                let source = upload.clone();
                async move {
                    let repository = source.repository();
                    let bytes = input(
                        &source,
                        &[
                            "upload-pack",
                            "--stateless-rpc",
                            repository.to_str().unwrap(),
                        ],
                        &body,
                    )
                    .await;
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/x-git-upload-pack-result",
                        )],
                        bytes,
                    )
                }
            }),
        )
}
pub(crate) async fn fixture_init(git: &W3cGit) {
    git.initialize(&CancellationToken::new(), Instant::now() + READ_RUNTIME)
        .await
        .unwrap();
    input(git, &["symbolic-ref", "HEAD", "refs/heads/main"], b"").await;
}
pub(crate) async fn commit_files(
    git: &W3cGit,
    files: &[(&str, &[u8])],
    parents: &[&str],
) -> String {
    let mut directories =
        std::collections::BTreeMap::<String, Vec<(String, String, String, String)>>::new();
    directories.entry(String::new()).or_default();
    for (path, body) in files {
        assert!(valid_path(path));
        let blob = oid(input(git, &["hash-object", "-w", "--stdin"], body).await);
        let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
        directories.entry(parent.into()).or_default().push((
            "100644".into(),
            "blob".into(),
            blob,
            name.to_string(),
        ));
        let mut ancestor = parent;
        while !ancestor.is_empty() {
            ancestor = ancestor.rsplit_once('/').map_or("", |(p, _)| p);
            directories.entry(ancestor.to_string()).or_default();
        }
    }
    let mut names: Vec<_> = directories.keys().cloned().collect();
    names.sort_by_key(|path| {
        std::cmp::Reverse(path.split('/').count() + usize::from(!path.is_empty()))
    });
    let mut root = None;
    for name in names {
        let mut entries = directories.remove(&name).unwrap();
        entries.sort_by(|a, b| a.3.cmp(&b.3));
        let body = entries
            .iter()
            .map(|(mode, kind, oid, name)| format!("{mode} {kind} {oid}\t{name}\n"))
            .collect::<String>();
        let tree = oid(input(git, &["mktree"], body.as_bytes()).await);
        if name.is_empty() {
            root = Some(tree)
        } else {
            let (parent, leaf) = name.rsplit_once('/').unwrap_or(("", &name));
            directories.get_mut(parent).unwrap().push((
                "040000".into(),
                "tree".into(),
                tree,
                leaf.to_owned(),
            ));
        }
    }
    let tree = root.unwrap();
    let mut args = vec!["commit-tree", &tree];
    for parent in parents {
        args.extend(["-p", parent]);
    }
    oid(input(git, &args, b"Synthetic nested W3C source fixture\n").await)
}
pub(crate) async fn serve_fixture(
    router: Router,
) -> (Arc<BulkBroker>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let broker = Arc::new(
        BulkBroker::fixture(url::Url::parse(&format!("http://{address}")).unwrap()).unwrap(),
    );
    (broker, task)
}

pub(crate) const MIT_NOTICE:&[u8]=br#"MIT License
Copyright (c) 2026 Synthetic fixture contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"#;
#[test]
fn complete_notice_required_not_quoted_permission_phrase() {
    assert_eq!(recognized_repository_notice(MIT_NOTICE), Some("MIT".into()));
    assert!(recognized_repository_notice(b"All rights reserved. Example license phrase: Permission is hereby granted, free of charge").is_none());
    let mut conflicting = MIT_NOTICE.to_vec();
    conflicting.extend_from_slice(b"Additional restriction: commercial use prohibited.");
    assert!(recognized_repository_notice(&conflicting).is_none());
}
#[test]
fn non_github_identity_roundtrips_and_cannot_alias_storage() {
    let a = Repo::new("https://git.example.org/group/spec.git").unwrap();
    let b = Repo::new("https://git.example.net/group/spec.git").unwrap();
    assert_ne!(a.owner, b.owner);
    assert_ne!(a.as_str(), b.as_str());
    assert!(a.validate().is_ok());
    assert!(Repo::new("https://127.0.0.1/spec.git").is_err());
}

#[test]
fn quoted_full_mit_after_restrictive_copyright_does_not_approve() {
    let prefix = b"Copyright 2026 Example. Redistribution forbidden. Example license follows:\n";
    let body = MIT_NOTICE
        .split(|b| *b == b'\n')
        .skip(3)
        .collect::<Vec<_>>()
        .join(&b'\n');
    let mut notice = prefix.to_vec();
    notice.extend(body);
    assert!(recognized_repository_notice(&notice).is_none());
}
#[test]
fn exact_common_w3c_notice_is_recognized() {
    // Primary fixtures: w3c/csswg-drafts/LICENSE.md and w3c/permissions/LICENSE.md.
    let notice=b"All documents in this Repository are licensed by contributors\nunder the \n[W3C Software and Document License](https://www.w3.org/Consortium/Legal/copyright-software).\n\n";
    assert_eq!(
        recognized_repository_notice(notice),
        Some("W3C-Software-and-Document-2023".into())
    );
    let mut changed = notice.to_vec();
    changed.extend_from_slice(b"Except commercial uses.");
    assert!(recognized_repository_notice(&changed).is_none());
}
#[test]
fn file_level_unknown_and_restrictive_notices_block_root_license_inheritance() {
    assert_eq!(
        unresolved_file_notice(b"// SPDX-License-Identifier: LicenseRef-Private\n"),
        Some("unrecognized_file_license_override")
    );
    assert_eq!(
        unresolved_file_notice(b"// Commercial use prohibited.\n"),
        Some("restrictive_file_notice_requires_review")
    );
    assert!(unresolved_file_notice(b"// SPDX-License-Identifier: MIT\n").is_none());
}
