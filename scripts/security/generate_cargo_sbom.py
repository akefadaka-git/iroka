#!/usr/bin/env python3
"""Generate a deterministic SPDX 2.3 SBOM from Cargo metadata and Cargo.lock."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import tomllib
import urllib.parse


def spdx_id(name: str, version: str, source: str | None) -> str:
    key = f"{name}\0{version}\0{source or 'workspace'}".encode()
    return "SPDXRef-Package-" + hashlib.sha256(key).hexdigest()[:20]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--lockfile", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    metadata_path = pathlib.Path(args.metadata)
    lock_path = pathlib.Path(args.lockfile)
    output_path = pathlib.Path(args.output)
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))

    if metadata.get("version") != 1 or not isinstance(metadata.get("packages"), list):
        raise SystemExit("unsupported or incomplete Cargo metadata")
    lock_packages = {
        (p["name"], p["version"], p.get("source")): p
        for p in lock.get("package", [])
    }
    packages = metadata["packages"]
    package_by_id = {p["id"]: p for p in packages}
    package_spdx = {
        p["id"]: spdx_id(p["name"], p["version"], p.get("source"))
        for p in packages
    }
    lock_by_key = {
        (p["name"], p["version"], p.get("source")): p
        for p in lock.get("package", [])
    }

    workspace_ids = set(metadata.get("workspace_members", []))
    if not workspace_ids:
        raise SystemExit("Cargo metadata has no workspace members")

    spdx_packages = []
    for package in sorted(packages, key=lambda p: (p["name"], p["version"], p["id"])):
        key = (package["name"], package["version"], package.get("source"))
        locked = lock_by_key.get(key)
        if locked is None:
            raise SystemExit(f"package missing from Cargo.lock: {key}")
        source = package.get("source")
        is_workspace = package["id"] in workspace_ids
        download = "NOASSERTION"
        if source and source.startswith("registry+"):
            crate = urllib.parse.quote(package["name"], safe="-_.")
            version = urllib.parse.quote(package["version"], safe="-_.")
            download = f"https://crates.io/api/v1/crates/{crate}/{version}/download"
        declared_license = package.get("license") or "NOASSERTION"
        # SPDX custom LicenseRef values need extracted license text; proprietary terms
        # are not embedded here, so preserve the manifest declaration as a comment.
        license_declared = "NOASSERTION" if declared_license.startswith("LicenseRef-") else declared_license
        item = {
            "name": package["name"],
            "SPDXID": package_spdx[package["id"]],
            "versionInfo": package["version"],
            "downloadLocation": download,
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": license_declared,
            "copyrightText": "NOASSERTION",
            **({"licenseComments": f"Cargo manifest declares {declared_license}; license text is not included in this SBOM."} if declared_license.startswith("LicenseRef-") else {}),
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": (
                    "pkg:cargo/"
                    + urllib.parse.quote(package["name"], safe="-_.")
                    + "@"
                    + urllib.parse.quote(package["version"], safe="-_.")
                ),
            }],
        }
        if not is_workspace and locked.get("checksum"):
            item["checksums"] = [{
                "algorithm": "SHA256",
                "checksumValue": locked["checksum"],
            }]
        spdx_packages.append(item)

    relationships = []
    for package_id in sorted(workspace_ids):
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package_spdx[package_id],
        })
    resolve = metadata.get("resolve") or {}
    for node in resolve.get("nodes", []):
        source_id = node.get("id")
        if source_id not in package_spdx:
            continue
        for dependency in node.get("deps", []):
            target_id = dependency.get("pkg")
            if target_id in package_spdx:
                relationships.append({
                    "spdxElementId": package_spdx[source_id],
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": package_spdx[target_id],
                })
    relationships.sort(key=lambda r: (
        r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"]
    ))

    lock_digest = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    created = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "IROKA ZERO Cargo workspace",
        "documentNamespace": f"https://iroka.dev/spdx/cargo-lock/{lock_digest}",
        "creationInfo": {
            "created": created.isoformat().replace("+00:00", "Z"),
            "creators": ["Tool: IROKA Cargo SPDX generator 1.0.0"],
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"SPDX 2.3 generated: {len(spdx_packages)} packages, "
        f"{len(relationships)} relationships, Cargo.lock sha256={lock_digest}"
    )


if __name__ == "__main__":
    main()
