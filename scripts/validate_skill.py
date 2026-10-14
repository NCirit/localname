"""Validate the shipped skill and its UI metadata in CI."""

from pathlib import Path
import re
import yaml


root = Path(__file__).resolve().parents[1] / "skills" / "localname"
text = (root / "SKILL.md").read_text(encoding="utf-8")
assert text.startswith("---\n"), "Missing YAML frontmatter"
_, header, body = text.split("---", 2)
metadata = yaml.safe_load(header)
assert metadata["name"] == root.name
assert re.fullmatch(r"[a-z0-9-]{1,63}", metadata["name"])
assert isinstance(metadata["description"], str) and metadata["description"].strip()
assert body.strip(), "Empty skill instructions"
interface = yaml.safe_load((root / "agents" / "openai.yaml").read_text(encoding="utf-8"))["interface"]
assert 25 <= len(interface["short_description"]) <= 64
assert "$localname" in interface["default_prompt"]
print("Localname skill and UI metadata are valid")
