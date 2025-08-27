
import click
import toml
import re
import requests
import base64
from typing import Optional, Dict, Set

from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

#CONVENTIONAL_COMMIT_PATTERN = re.compile(r"(feat|fix)\((TNG-\d+)\)")


@click.command()
@click.option("--repo-url", required=True, help="GitHub repo URL (SSH or HTTPS)")
@click.option(
    "--current-ref",
    default="HEAD",
    help="Branch, tag, or commit SHA to release (defaults to HEAD)",
)
@click.option(
    "--github-token",
    envvar="GITHUB_TOKEN",
    required=True,
    help="GitHub token (can use Actions built-in)",
)
@click.option("--prev-ref")
@click.option(
    "--depth",
    default=1,
    show_default=True,
    help="How many levels of git dependencies to scan recursively",
)
@click.option(
    "--commit-pattern",
    default=r"(feat|fix)\((TNG-\d+)\)",
    help="Regex pattern to extract ticket IDs from commit messages",
)
def draft_release_notes(
    repo_url: str,
    current_ref: str,
    github_token: str,
    prev_ref: str,
    depth: int,
    commit_pattern: str,
) -> Optional[Dict[str, str]]:
    """
    Draft release notes for a repo and its git dependencies using GitHub API only.
    """
    headers = {"Authorization": f"token {github_token}"}

    owner, repo_name = extract_owner_repo(repo_url)

    pattern = re.compile(commit_pattern)


    # Step 1: resolve previous reference
    latest_tag_name = prev_ref or get_latest_release_tag(owner, repo_name, headers)
    prev_ref_sha = None
    if latest_tag_name:
        prev_ref_sha = get_tag_commit_sha(owner, repo_name, latest_tag_name, headers)

    # Step 2: fetch root pyproject + poetry.lock
    pyproject_toml = fetch_file(
        owner, repo_name, "pyproject.toml", current_ref, headers
    )
    poetry_lock = fetch_file(owner, repo_name, "poetry.lock", current_ref, headers)

    pyproject_data = toml.loads(pyproject_toml)
    current_lock_data = toml.loads(poetry_lock)

    prev_lock_data = {}
    if prev_ref_sha:
        try:
            prev_lock_content = fetch_file(
                owner, repo_name, "poetry.lock", prev_ref_sha, headers
            )
            prev_lock_data = toml.loads(prev_lock_content)
        except Exception as e:
            print(
                f"Warning: Could not fetch poetry.lock at previous release {latest_tag_name}: {e}"
            )

    # Step 3: scan recursively — always use root lockfiles for SHAs
    visited: Set[str] = set()
    release_notes = scan_dependencies(
        pyproject_data,
        prev_lock_data,
        current_lock_data,
        headers,
        depth,
        visited,
        pattern
    )

    def generate_release_notes(output_dict):
        """
        Convert ticket dictionary to Markdown table for release notes.
        """
        release_notes = "| Repo | Compare URL | Tickets |\n"
        release_notes += "|--------|-------------|--------|\n"

        for service, info in output_dict.items():
            tickets = ", ".join(info.get("tickets", []))
            url = info.get("compare_url", "")
            release_notes += f"| {service} | [Link]({url}) | {tickets} |\n"
        print(release_notes)
        return release_notes

    return generate_release_notes(release_notes)


# ---------------- Recursive Dependency Scanner ----------------
def scan_dependencies(
    pyproject_data: dict,
    root_prev_lock: dict,
    root_curr_lock: dict,
    headers: Dict[str, str],
    depth: int,
    visited: Set[str],
    pattern
) -> Dict[str, list]:
    if depth <= 0:
        return {}

    deps = pyproject_data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    git_deps = {
        name: info["git"]
        for name, info in deps.items()
        if isinstance(info, dict) and "git" in info
    }

    release_notes = {}

    for dep_name, dep_git_url in git_deps.items():
        if dep_git_url in visited:
            continue
        visited.add(dep_git_url)

        old_sha = extract_git_commit_from_lock(root_prev_lock, dep_git_url)
        new_sha = extract_git_commit_from_lock(root_curr_lock, dep_git_url)

        if not new_sha or old_sha == new_sha:
            continue

        dep_owner, dep_repo = extract_owner_repo(dep_git_url)

        if old_sha:
            compare_url = f"https://api.github.com/repos/{dep_owner}/{dep_repo}/compare/{old_sha}...{new_sha}"
        else:
            compare_url = (
                f"https://api.github.com/repos/{dep_owner}/{dep_repo}/commits/{new_sha}"
            )

        resp = requests.get(compare_url, headers=headers)
        if resp.status_code != 200:
            print(f"⚠️ Failed to fetch commits for {dep_name}: {resp.text}")
            continue

        commits = resp.json().get("commits", [])
        tickets = []
        for c in commits:
            msg = c["commit"]["message"]
            matches = pattern.findall(msg)
            tickets.extend([ticket for _, ticket in matches])

        if tickets:
            release_notes[dep_name] = {
                "compare_url": f"https://github.com/{dep_owner}/{dep_repo}/compare/{old_sha}...{new_sha}"
                if old_sha
                else None,
                "tickets": sorted(set(tickets)),
            }

        # Recursive step ↓ — fetch only pyproject.toml, but always resolve SHAs via root lock
        if depth > 1:
            try:
                dep_pyproject = fetch_file(
                    dep_owner, dep_repo, "pyproject.toml", new_sha, headers
                )
                dep_py_data = toml.loads(dep_pyproject)
                nested_notes = scan_dependencies(
                    dep_py_data,
                    root_prev_lock,
                    root_curr_lock,
                    headers,
                    depth - 1,
                    visited,
                    pattern
                )
                release_notes.update(nested_notes)
            except Exception:
                pass  # dependency may not have pyproject.toml

    return release_notes


# ---------------- Helper Functions ----------------
def extract_owner_repo(git_url: str):
    if git_url.startswith("git@github.com:"):
        path = git_url.split(":", 1)[1]
    elif git_url.startswith("ssh://git@github.com/"):
        path = git_url.split("github.com/", 1)[1]
    elif git_url.startswith("https://github.com/"):
        path = git_url.split("github.com/", 1)[1]
    else:
        raise ValueError(f"Unsupported git URL: {git_url}")
    owner, repo = path.replace(".git", "").split("/")
    return owner, repo


def fetch_file(
    owner: str, repo: str, path: str, ref: str, headers: Dict[str, str]
) -> str:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}?ref={ref}"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        raise ValueError(f"Failed to fetch {path}@{ref}: {resp.text}")
    content_b64 = resp.json()["content"]
    return base64.b64decode(content_b64).decode()


def get_latest_release_tag(
    owner: str, repo: str, headers: Dict[str, str]
) -> Optional[str]:
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        return resp.json()["tag_name"]
    return None


def get_tag_commit_sha(
    owner: str, repo: str, tag_or_sha: str, headers: Dict[str, str]
) -> str:
    import re

    if re.fullmatch(r"[0-9a-f]{40}", tag_or_sha):
        return tag_or_sha

    url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{tag_or_sha}"
    resp = requests.get(url, headers=headers)
    resp.raise_for_status()
    ref_data = resp.json()
    if ref_data["object"]["type"] == "tag":
        tag_obj = requests.get(ref_data["object"]["url"], headers=headers).json()
        return tag_obj["object"]["sha"]
    else:
        return ref_data["object"]["sha"]


def extract_git_commit_from_lock(lock_data: dict, git_url: str) -> Optional[str]:
    for package in lock_data.get("package", []):
        source = package.get("source", {})
        if source.get("url") == git_url:
            return source.get("resolved_reference")
    return None


if __name__ == "__main__":
    draft_release_notes()
