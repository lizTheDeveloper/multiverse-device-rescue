"""Configuration for where the content repository lives locally, which
remote it tracks, and the trust parameters (how many distinct
maintainer-signed tags are required before a commit is accepted).
"""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ContentRepoConfig:
    remote_url: str
    local_path: Path
    trusted_signers_path: Path
    revoked_signers_path: Path
    required_approvals: int = 2
    tag_prefix: str = "approved/"


def default_config() -> ContentRepoConfig:
    """Production defaults. The remote URL and required-approvals
    threshold are pinned at release time by the actual maintainers, not
    generated here."""
    data_dir = Path.home() / ".local" / "share" / "rescue"
    config_dir = Path.home() / ".config" / "rescue"
    return ContentRepoConfig(
        remote_url="https://github.com/multiverse-device-rescue/content.git",
        local_path=data_dir / "content",
        trusted_signers_path=Path(__file__).parent.parent / "security" / "trusted_signers.json",
        revoked_signers_path=config_dir / "revoked_signers.json",
        required_approvals=2,
        tag_prefix="approved/",
    )
