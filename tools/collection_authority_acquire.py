#!/usr/bin/env python3
"""Acquire the exact three collection-evidence artifacts from one GitHub run.

The merge workflow uses this producer-side transport tool. The Rust
``collection-authority verify`` command remains the offline semantic authority.
This tool retains the complete paginated provider response, selected API
objects, original ZIP bytes, exact producer workflow, and a safely extracted
tree for each platform.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from typing import Any


API_ROOT = "https://api.github.com"
PLATFORMS = ("linux-amd64", "macos-arm64", "windows-amd64")
PRODUCER_JOBS = {
    "linux-amd64": "Collection authority / Linux amd64",
    "macos-arm64": "Collection authority / macOS arm64",
    "windows-amd64": "Collection authority / Windows amd64",
}
PER_PAGE = 100
MAX_PAGES = 100
MAX_ARCHIVE_ENTRIES = 250_000
MAX_UNCOMPRESSED_BYTES = 8 * 1024 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")


class AcquisitionError(RuntimeError):
    """Fail-closed provider acquisition error."""


@dataclass(frozen=True)
class ArtifactSpec:
    platform: str
    name: str
    artifact_id: int


@dataclass(frozen=True)
class ApiResponse:
    body: bytes
    headers: dict[str, str]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True, type=positive_int)
    parser.add_argument("--run-attempt", required=True, type=positive_int)
    parser.add_argument("--provider-head", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--artifact",
        action="append",
        required=True,
        type=parse_artifact_spec,
        metavar="PLATFORM:NAME:ID",
    )
    return parser.parse_args()


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("identifier must be positive")
    return parsed


def parse_artifact_spec(value: str) -> ArtifactSpec:
    try:
        platform, name, artifact_id = value.split(":", 2)
    except ValueError as error:
        raise argparse.ArgumentTypeError("artifact must be PLATFORM:NAME:ID") from error
    if platform not in PLATFORMS or not name or any(char.isspace() for char in name):
        raise argparse.ArgumentTypeError("artifact platform or name is noncanonical")
    return ArtifactSpec(platform, name, positive_int(artifact_id))


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AcquisitionError(f"{label} is not an object")
    return value


def require_array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AcquisitionError(f"{label} is not an array")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AcquisitionError(f"{label} is not a nonempty string")
    return value


def require_integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise AcquisitionError(f"{label} is not a positive integer")
    return value


def api_request(token: str, endpoint: str, accept: str = "application/vnd.github+json") -> ApiResponse:
    if not endpoint.startswith("/") or ".." in endpoint:
        raise AcquisitionError("GitHub API endpoint is not repository-confined")
    request = urllib.request.Request(
        API_ROOT + endpoint,
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "User-Agent": "hell-rs-collection-authority/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status != 200:
                raise AcquisitionError(f"GitHub API returned HTTP {response.status}")
            body = response.read()
            if not body:
                raise AcquisitionError("GitHub API returned an empty response")
            return ApiResponse(body, {key.lower(): value for key, value in response.headers.items()})
    except (urllib.error.URLError, TimeoutError) as error:
        raise AcquisitionError(f"GitHub API request failed: {error}") from error


def parse_json_response(response: ApiResponse, label: str) -> dict[str, Any]:
    try:
        decoded = json.loads(response.body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcquisitionError(f"{label} is not UTF-8 JSON") from error
    return require_object(decoded, label)


def acquire_complete_artifact_set(
    token: str, repository: str, run_id: int, output: pathlib.Path
) -> tuple[list[dict[str, Any]], list[pathlib.Path]]:
    artifacts: list[dict[str, Any]] = []
    pages: list[pathlib.Path] = []
    expected_total: int | None = None
    page = 1
    while True:
        if page > MAX_PAGES:
            raise AcquisitionError("artifact pagination exceeds the reviewed page bound")
        endpoint = (
            f"/repos/{repository}/actions/runs/{run_id}/artifacts"
            f"?per_page={PER_PAGE}&page={page}"
        )
        response = api_request(token, endpoint)
        document = parse_json_response(response, f"artifact API page {page}")
        total = require_integer(document.get("total_count"), "artifact total_count")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise AcquisitionError("artifact pagination total changed during acquisition")
        entries = require_array(document.get("artifacts"), "artifact page entries")
        remaining = expected_total - len(artifacts)
        expected_page_length = min(PER_PAGE, remaining)
        if len(entries) != expected_page_length:
            raise AcquisitionError("artifact page does not cover the exact complete set")
        page_path = output / "artifact-api-pages" / f"page-{page:04}.json"
        write_exclusive(page_path, response.body)
        pages.append(page_path)
        artifacts.extend(require_object(entry, "artifact entry") for entry in entries)
        if len(artifacts) == expected_total:
            break
        page += 1
    identifiers = [require_integer(item.get("id"), "artifact id") for item in artifacts]
    if len(set(identifiers)) != len(identifiers) or any(
        left <= right for left, right in zip(identifiers, identifiers[1:])
    ):
        raise AcquisitionError("artifact pagination IDs are not unique and strictly descending")
    return artifacts, pages


def acquire_complete_job_set(
    token: str,
    repository: str,
    run_id: int,
    run_attempt: int,
    output: pathlib.Path,
) -> tuple[list[dict[str, Any]], list[pathlib.Path]]:
    jobs: list[dict[str, Any]] = []
    pages: list[pathlib.Path] = []
    expected_total: int | None = None
    page = 1
    while True:
        if page > MAX_PAGES:
            raise AcquisitionError("job pagination exceeds the reviewed page bound")
        endpoint = (
            f"/repos/{repository}/actions/runs/{run_id}/attempts/{run_attempt}/jobs"
            f"?per_page={PER_PAGE}&page={page}"
        )
        response = api_request(token, endpoint)
        document = parse_json_response(response, f"job API page {page}")
        total = require_integer(document.get("total_count"), "job total_count")
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise AcquisitionError("job pagination total changed during acquisition")
        entries = require_array(document.get("jobs"), "job page entries")
        remaining = expected_total - len(jobs)
        if len(entries) != min(PER_PAGE, remaining):
            raise AcquisitionError("job page does not cover the exact complete set")
        page_path = output / "job-api-pages" / f"page-{page:04}.json"
        write_exclusive(page_path, response.body)
        pages.append(page_path)
        jobs.extend(require_object(entry, "job entry") for entry in entries)
        if len(jobs) == expected_total:
            break
        page += 1
    identifiers = [require_integer(item.get("id"), "job id") for item in jobs]
    if len(set(identifiers)) != len(identifiers):
        raise AcquisitionError("job pagination identifiers are not unique")
    return jobs, pages


def parse_timestamp(value: Any, label: str) -> datetime.datetime:
    text = require_string(value, label)
    try:
        parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise AcquisitionError(f"{label} is not an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise AcquisitionError(f"{label} lacks a timezone")
    return parsed


def validate_run(
    run: dict[str, Any], repository: str, run_id: int, run_attempt: int,
    provider_head: str, workflow_path: str,
) -> None:
    repository_object = require_object(run.get("repository"), "run repository")
    if (
        require_integer(run.get("id"), "run id") != run_id
        or require_integer(run.get("run_attempt"), "run attempt") != run_attempt
        or require_string(run.get("head_sha"), "run head_sha") != provider_head
        or require_string(run.get("path"), "run workflow path") != workflow_path
        or require_string(run.get("event"), "run event") != "workflow_dispatch"
        or require_string(run.get("head_branch"), "run head branch") != "main"
        or require_string(repository_object.get("full_name"), "run repository name") != repository
    ):
        raise AcquisitionError("provider run identity differs from the requested campaign")
    if require_string(run.get("status"), "run status") not in ("in_progress", "completed"):
        raise AcquisitionError("provider run is not active or complete")


def select_producer_jobs(jobs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for platform, expected_name in PRODUCER_JOBS.items():
        matches = [job for job in jobs if job.get("name") == expected_name]
        if len(matches) != 1:
            raise AcquisitionError(f"producer job {expected_name} is not unique")
        job = matches[0]
        if (
            require_string(job.get("status"), "producer job status") != "completed"
            or require_string(job.get("conclusion"), "producer job conclusion") != "success"
        ):
            raise AcquisitionError(f"producer job {expected_name} did not complete successfully")
        selected[platform] = job
    return selected


def select_artifacts(
    artifacts: list[dict[str, Any]], specs: list[ArtifactSpec], run_id: int,
    provider_head: str,
) -> dict[str, dict[str, Any]]:
    if {spec.platform for spec in specs} != set(PLATFORMS) or len(specs) != len(PLATFORMS):
        raise AcquisitionError("artifact arguments are not the exact three-platform inventory")
    if len({spec.artifact_id for spec in specs}) != len(specs):
        raise AcquisitionError("selected artifact IDs are not unique")
    selected: dict[str, dict[str, Any]] = {}
    now = datetime.datetime.now(datetime.timezone.utc)
    for spec in specs:
        name_matches = [item for item in artifacts if item.get("name") == spec.name]
        if len(name_matches) != 1:
            raise AcquisitionError(f"artifact {spec.name} is not unique in the complete run set")
        artifact = name_matches[0]
        workflow_run = require_object(artifact.get("workflow_run"), "artifact workflow_run")
        created = parse_timestamp(artifact.get("created_at"), "artifact created_at")
        expires = parse_timestamp(artifact.get("expires_at"), "artifact expires_at")
        if (
            require_integer(artifact.get("id"), "artifact id") != spec.artifact_id
            or require_integer(workflow_run.get("id"), "artifact run id") != run_id
            or require_string(workflow_run.get("head_sha"), "artifact head_sha")
            != provider_head
            or artifact.get("expired") is not False
            or created >= expires
            or expires <= now
        ):
            raise AcquisitionError(f"artifact {spec.name} identity or lifetime is invalid")
        selected[spec.platform] = artifact
    return selected


def validated_archive_digest(artifact: dict[str, Any], archive: bytes) -> str:
    digest = require_string(artifact.get("digest"), "artifact digest")
    expected = digest.removeprefix("sha256:")
    if not SHA256_RE.fullmatch(expected):
        raise AcquisitionError("artifact digest is not SHA-256")
    actual = sha256_bytes(archive)
    if actual != expected or len(archive) != require_integer(
        artifact.get("size_in_bytes"), "artifact archive size"
    ):
        raise AcquisitionError("artifact ZIP bytes differ from provider identity")
    return actual


def safe_zip_parts(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        raise AcquisitionError("artifact ZIP contains a noncanonical path")
    raw = name[:-1] if name.endswith("/") else name
    if not raw.isascii() or any(
        not (character.isalnum() or character in "._-/") for character in raw
    ):
        raise AcquisitionError("artifact ZIP path is outside the canonical ASCII alphabet")
    parts = tuple(raw.split("/"))
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise AcquisitionError("artifact ZIP contains an escaping or ambiguous path")
    return parts


def zip_mode(info: zipfile.ZipInfo) -> int:
    mode = info.external_attr >> 16
    if info.is_dir():
        if mode not in (0o040755, 0o40755):
            raise AcquisitionError(f"artifact ZIP directory {info.filename!r} has invalid mode")
        return 0o040755
    if stat.S_IFMT(mode) != stat.S_IFREG or stat.S_IMODE(mode) not in (0o644, 0o755):
        raise AcquisitionError(f"artifact ZIP file {info.filename!r} has invalid mode")
    return stat.S_IFREG | stat.S_IMODE(mode)


def extract_validated_archive(archive_path: pathlib.Path, destination: pathlib.Path) -> tuple[str, int]:
    destination.mkdir(parents=True, exist_ok=False)
    inventory: list[dict[str, Any]] = []
    names: set[str] = set()
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ARCHIVE_ENTRIES:
            raise AcquisitionError("artifact ZIP entry count is outside the reviewed bound")
        total_uncompressed = sum(info.file_size for info in infos)
        if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise AcquisitionError("artifact ZIP expands beyond the reviewed byte bound")
        folded_names: set[str] = set()
        for info in infos:
            if info.flag_bits & 1 or info.compress_type not in (
                zipfile.ZIP_STORED,
                zipfile.ZIP_DEFLATED,
            ):
                raise AcquisitionError("artifact ZIP uses an unreviewed encoding")
            parts = safe_zip_parts(info.filename)
            canonical_name = "/".join(parts) + ("/" if info.is_dir() else "")
            folded = canonical_name.casefold()
            if canonical_name in names or folded in folded_names:
                raise AcquisitionError("artifact ZIP contains a duplicate path")
            names.add(canonical_name)
            folded_names.add(folded)
            mode = zip_mode(info)
            path = destination.joinpath(*parts)
            if info.is_dir():
                path.mkdir(parents=True, exist_ok=False)
                os.chmod(path, 0o755)
                inventory.append({"mode": "040755", "path": canonical_name, "type": "directory"})
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            data = archive.read(info)
            if len(data) != info.file_size:
                raise AcquisitionError("artifact ZIP entry size changed while extracting")
            with path.open("xb") as handle:
                handle.write(data)
            os.chmod(path, stat.S_IMODE(mode))
            inventory.append(
                {
                    "mode": f"{mode:06o}",
                    "path": canonical_name,
                    "sha256": sha256_bytes(data),
                    "size": len(data),
                    "type": "file",
                }
            )
    inventory.sort(key=lambda entry: entry["path"].encode())
    return sha256_bytes(canonical_json(inventory)), len(inventory)


def write_exclusive(path: pathlib.Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(body)


def copy_tree_exact(source: pathlib.Path, destination: pathlib.Path) -> None:
    if destination.exists():
        raise AcquisitionError(f"destination already exists: {destination}")
    shutil.copytree(source, destination, copy_function=shutil.copy2)


def acquire() -> None:
    arguments = parse_arguments()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise AcquisitionError("GITHUB_TOKEN is required")
    if not COMMIT_RE.fullmatch(arguments.provider_head):
        raise AcquisitionError("provider head is not a lowercase full SHA-1")
    if not COMMIT_RE.fullmatch(arguments.candidate_commit):
        raise AcquisitionError("candidate commit is not a lowercase full SHA-1")
    if arguments.workflow_path != ".github/workflows/collection-authority.yml":
        raise AcquisitionError("collection provider workflow path is not exact")
    repository_parts = arguments.repository.split("/")
    if len(repository_parts) != 2 or any(not part for part in repository_parts):
        raise AcquisitionError("repository is not OWNER/NAME")
    arguments.output.mkdir(parents=True, exist_ok=False)

    run_endpoint = f"/repos/{arguments.repository}/actions/runs/{arguments.run_id}"
    run_response = api_request(token, run_endpoint)
    run = parse_json_response(run_response, "provider run")
    validate_run(
        run,
        arguments.repository,
        arguments.run_id,
        arguments.run_attempt,
        arguments.provider_head,
        arguments.workflow_path,
    )
    artifacts, pages = acquire_complete_artifact_set(
        token, arguments.repository, arguments.run_id, arguments.output
    )
    jobs, job_pages = acquire_complete_job_set(
        token,
        arguments.repository,
        arguments.run_id,
        arguments.run_attempt,
        arguments.output,
    )
    selected_jobs = select_producer_jobs(jobs)
    selected = select_artifacts(
        artifacts, arguments.artifact, arguments.run_id, arguments.provider_head
    )

    encoded_workflow = urllib.parse.quote(arguments.workflow_path, safe="/")
    workflow_response = api_request(
        token,
        f"/repos/{arguments.repository}/contents/{encoded_workflow}?ref={arguments.provider_head}",
        "application/vnd.github.raw+json",
    )
    if not workflow_response.body.startswith(b"name: Collection Authority\n"):
        raise AcquisitionError("provider workflow bytes are not the reviewed collection workflow")

    observed_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for spec in arguments.artifact:
        artifact = selected[spec.platform]
        directory = arguments.output / spec.platform
        directory.mkdir()
        write_exclusive(directory / "provider-selected-run.json", run_response.body)
        write_exclusive(directory / "provider-selected-artifact.json", canonical_json(artifact))
        write_exclusive(directory / "provider-workflow.yml", workflow_response.body)
        expected_url = (
            f"{API_ROOT}/repos/{arguments.repository}/actions/artifacts/{spec.artifact_id}/zip"
        )
        if require_string(artifact.get("archive_download_url"), "archive URL") != expected_url:
            raise AcquisitionError("artifact archive URL is not exact and repository-confined")
        archive_response = api_request(
            token,
            f"/repos/{arguments.repository}/actions/artifacts/{spec.artifact_id}/zip",
            "application/vnd.github+json",
        )
        archive_path = directory / "provider-archive.zip"
        write_exclusive(archive_path, archive_response.body)
        archive_sha256 = validated_archive_digest(artifact, archive_response.body)
        extracted = directory / "extracted" / spec.platform
        tree_sha256, inventory_count = extract_validated_archive(archive_path, extracted)
        collection_subject = extracted / "collection-evidence" / "provider-subject.json"
        observations = extracted / "collection-evidence" / "observations"
        if not collection_subject.is_file() or not observations.is_dir():
            raise AcquisitionError("artifact lacks its canonical collection authority subject")
        case_count = sum(1 for entry in observations.iterdir() if entry.is_dir())
        if case_count != 1191:
            raise AcquisitionError("artifact lacks the exact 1191-case collection inventory")
        page_index = next(
            index
            for index, page in enumerate(pages, start=1)
            if json.loads(page.read_bytes()).get("artifacts")
            and any(item.get("id") == spec.artifact_id for item in json.loads(page.read_bytes())["artifacts"])
        )
        job_page_index = next(
            index
            for index, page in enumerate(job_pages, start=1)
            if any(
                item.get("id") == selected_jobs[spec.platform].get("id")
                for item in json.loads(page.read_bytes()).get("jobs", [])
            )
        )
        selection = {
            "artifact": spec.name,
            "candidateCommit": arguments.candidate_commit,
            "canonicalShardRoot": spec.platform,
            "inventoryCount": inventory_count,
            "observedAt": observed_at,
            "platform": spec.platform,
            "providerArchiveSha256": archive_sha256,
            "providerArchiveSize": len(archive_response.body),
            "providerArtifactApiPage": f"../artifact-api-pages/page-{page_index:04}.json",
            "providerArtifactId": spec.artifact_id,
            "providerJobApiPage": f"../job-api-pages/page-{job_page_index:04}.json",
            "providerJobId": require_integer(
                selected_jobs[spec.platform].get("id"), "producer job id"
            ),
            "providerJobName": PRODUCER_JOBS[spec.platform],
            "providerHeadCommit": arguments.provider_head,
            "providerRunAttempt": arguments.run_attempt,
            "providerRunId": arguments.run_id,
            "providerTreeSha256": tree_sha256,
            "schemaVersion": 1,
            "workflowPath": arguments.workflow_path,
        }
        write_exclusive(directory / "selection.json", canonical_json(selection))

    for platform in PLATFORMS:
        copy_tree_exact(
            arguments.output / platform / "extracted" / platform,
            arguments.output.parent / "native-shards" / platform,
        )


def main() -> int:
    try:
        acquire()
    except (AcquisitionError, OSError, zipfile.BadZipFile) as error:
        print(f"collection authority acquisition failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
