#!/usr/bin/env python3
"""Read-only report tooling. No model calls, target imports, or network access."""

import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import shlex
import sys
from datetime import datetime

HOME = Path(__file__).resolve().parent


class ReportError(ValueError):
    pass


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReportError(f"Cannot read JSON {path}: {exc}") from exc


def schema_errors(value, rule, schema, where="$", errors=None):
    """Validate the JSON Schema subset used by the shipped schema, fail closed."""
    if errors is None:
        errors = []
    if "$ref" in rule:
        target = schema
        for key in rule["$ref"].removeprefix("#/").split("/"):
            target = target[key]
        return schema_errors(value, target, schema, where, errors)
    types = {"object": dict, "array": list, "string": str, "integer": int}
    expected = rule.get("type")
    if expected and (not isinstance(value, types[expected]) or
                     (expected == "integer" and isinstance(value, bool))):
        errors.append(f"{where}: expected {expected}")
        return errors
    if "enum" in rule and value not in rule["enum"]:
        errors.append(f"{where}: expected one of {rule['enum']}")
    if isinstance(value, dict):
        properties = rule.get("properties", {})
        for key in rule.get("required", []):
            if key not in value:
                errors.append(f"{where}.{key}: required")
        for key, child in value.items():
            if key in properties:
                schema_errors(child, properties[key], schema, f"{where}.{key}", errors)
            elif rule.get("additionalProperties") is False:
                errors.append(f"{where}.{key}: unknown field")
    if isinstance(value, list):
        if len(value) < rule.get("minItems", 0):
            errors.append(f"{where}: requires at least {rule['minItems']} items")
        for index, child in enumerate(value):
            schema_errors(child, rule.get("items", {}), schema, f"{where}[{index}]", errors)
    if isinstance(value, str):
        if len(value.strip()) < rule.get("minLength", 0):
            errors.append(f"{where}: requires nonempty text")
        if "pattern" in rule and not re.search(rule["pattern"], value):
            errors.append(f"{where}: invalid format")
    if isinstance(value, int) and "minimum" in rule and value < rule["minimum"]:
        errors.append(f"{where}: below minimum {rule['minimum']}")
    return errors


def safe_file(root, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not relative:
        raise ReportError(f"Evidence path must be relative without '..': {relative}")
    resolved_root = Path(root).resolve(strict=True)
    resolved = (resolved_root / path).resolve(strict=True)
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise ReportError(f"Evidence escapes its root or is not a file: {relative}")
    return resolved


def evidence_record(root, path, start, end, evidence_id, source="repository"):
    file = safe_file(root, path)
    data = file.read_bytes()
    lines = data.decode("utf-8").splitlines()
    if not 1 <= start <= end <= len(lines):
        raise ReportError(f"Invalid line range {start}-{end} for {path} ({len(lines)} lines)")
    return {"id": evidence_id, "kind": "repository", "root": source, "path": path,
            "start_line": start, "end_line": end,
            "sha256": hashlib.sha256(data).hexdigest(), "captured_at": "", "notes": ""}


def validate(report, report_path, repo):
    schema = read_json(HOME / "report.schema.json")
    errors = schema_errors(report, schema, schema)
    if errors:
        return errors
    collections = {}
    for name in ("steps", "boundaries", "evidence"):
        records = report[name]
        ids = [r["id"] for r in records]
        if len(set(ids)) != len(ids):
            errors.append(f"{name}: duplicate IDs")
        collections[name] = {r["id"]: r for r in records}
    evidence = collections["evidence"]
    boundaries = collections["boundaries"]

    def refs(ids, available, where):
        for item in ids:
            if item not in available:
                errors.append(f"{where}: unknown reference {item}")
        if len(ids) != len(set(ids)):
            errors.append(f"{where}: duplicate references")

    for item in evidence.values():
        try:
            root = repo if item["root"] == "repository" else Path(report_path).parent
            checked = evidence_record(root, item["path"], item["start_line"],
                                      item["end_line"], item["id"], item["root"])
            if checked["sha256"] != item["sha256"]:
                errors.append(f"{item['id']}: evidence hash does not match {item['path']}")
        except (ReportError, OSError, UnicodeError) as exc:
            errors.append(f"{item['id']}: {exc}")
        if item["kind"] != "repository":
            try:
                stamp = datetime.fromisoformat(item["captured_at"].replace("Z", "+00:00"))
                if stamp.tzinfo is None or not item["notes"].strip():
                    raise ValueError("timezone and provenance notes required")
            except ValueError:
                errors.append(f"{item['id']}: snapshot/attestation needs ISO timestamp with timezone and provenance notes")
    used = set()
    for step in report["steps"]:
        refs(step["boundary_ids"], boundaries, step["id"])
        refs(step["evidence_ids"], evidence, step["id"])
        used.update(step["boundary_ids"])
    for boundary in boundaries.values():
        bid = boundary["id"]
        refs(boundary["evidence_ids"], evidence, bid)
        if bid not in used:
            errors.append(f"{bid}: not connected to an operation step")
        for path in boundary["change_paths"]:
            refs(path["evidence_ids"], evidence, bid + " change path")
            if path["attacker_control"] != "unknown" and not path["evidence_ids"]:
                errors.append(f"{bid}: known change-path control requires evidence")
        if boundary["evidence_basis"] == "source_only" and not boundary["production_checks"]:
            errors.append(f"{bid}: source-only assessment requires production checks")
        if boundary["evidence_basis"] == "deployment_snapshot" and not any(
                evidence.get(e, {}).get("kind") == "deployment_snapshot" for e in boundary["evidence_ids"]):
            errors.append(f"{bid}: deployment basis requires referenced deployment snapshot")
        if boundary["status"] == "survives":
            if boundary["enforcement_location"] != "outside":
                errors.append(f"{bid}: survives requires enforcement outside the compromise")
            if not boundary["change_paths"] or any(p["attacker_control"] != "no" for p in boundary["change_paths"]):
                errors.append(f"{bid}: survives requires documented change/bypass paths outside attacker control")
            if not any(evidence.get(e, {}).get("kind") in ("repository", "deployment_snapshot")
                       for e in boundary["evidence_ids"]):
                errors.append(f"{bid}: survives needs evidence beyond attestation")
        if any(p["attacker_control"] == "yes" for p in boundary["change_paths"]) and boundary["status"] != "defeated":
            errors.append(f"{bid}: attacker-controlled change/bypass path requires defeated classification")
        if any(p["attacker_control"] == "unknown" for p in boundary["change_paths"]) and boundary["status"] == "survives":
            errors.append(f"{bid}: unresolved change authority cannot support survives")
    challenged = set()
    for challenge in report["challenges"]:
        bid = challenge["boundary_id"]
        refs([bid], boundaries, "challenge")
        refs(challenge["evidence_ids"], evidence, "challenge")
        if bid in challenged:
            errors.append(f"{bid}: duplicate challenge")
        challenged.add(bid)
        if bid in boundaries:
            unknown = boundaries[bid]["status"] == "unverified"
            if unknown != (challenge["outcome"] == "unresolved"):
                errors.append(f"{bid}: challenge outcome contradicts boundary classification")
    for bid in boundaries.keys() - challenged:
        errors.append(f"{bid}: missing challenge pass")
    for question in report["open_questions"]:
        if question["boundary_id"] != "scope":
            refs([question["boundary_id"]], boundaries, "open question")
    for bid, boundary in boundaries.items():
        if boundary["status"] == "unverified" and not any(q["boundary_id"] == bid for q in report["open_questions"]):
            errors.append(f"{bid}: unverified boundary needs an open question")
    return errors


def clean(text):
    return html.escape(text, quote=False).replace("|", "\\|").replace("\n", " ")


def render(report):
    s = report["scope"]
    lines = ["# Security boundary map", "", "> Artifact validation does not establish system security. "
             "Source-only conclusions are conditional on deployment matching the inspected material.", "",
             f"**Operation:** {clean(s['operation'])}", "",
             f"**Assumed compromise:** {clean(s['compromised_component'])}", ""]
    for name, label in [("attacker_capabilities", "Attacker capabilities"),
                        ("excluded_capabilities", "Excluded capabilities / assumptions"),
                        ("evidence_limits", "Evidence limits")]:
        lines.extend([f"## {label}", ""] + ["- " + clean(x) for x in s[name]] + [""])
    lines += ["## Money movement", ""]
    for i, step in enumerate(report["steps"], 1):
        lines += [f"### {i}. {clean(step['action'])} ({clean(step['id'])})", "",
                  f"- Actor: {clean(step['actor'])}", f"- Authority: {clean(step['authority'])}",
                  f"- Credential references: {clean(', '.join(step['credential_refs'])) or 'None identified'}",
                  f"- Inputs: {clean(step['inputs'])}", f"- Outputs: {clean(step['outputs'])}",
                  f"- Boundaries: {clean(', '.join(step['boundary_ids'])) or 'None identified'}",
                  f"- Evidence: {clean(', '.join(step['evidence_ids']))}", ""]
    lines += ["## Boundary inventory", "", "| Boundary | Restriction | Enforcement | Status | Basis |",
              "| --- | --- | --- | --- | --- |"]
    for b in report["boundaries"]:
        lines.append("| " + " | ".join(clean(x) for x in [b["id"], b["restriction"],
                     b["enforced_by"] + " (" + b["enforcement_location"] + ")", b["status"], b["evidence_basis"]]) + " |")
    lines.append("")
    for b in report["boundaries"]:
        lines += [f"### {clean(b['id'])}: {clean(b['restriction'])}", "", clean(b["reason"]), "",
                  "Change and bypass authority:", ""]
        for p in b["change_paths"]:
            lines.append(f"- {clean(p['principal'])}: {clean(p['mechanism'])}. "
                         f"Attacker control: **{p['attacker_control']}**. Evidence: {clean(', '.join(p['evidence_ids'])) or 'Unresolved'}.")
        lines += ["", "Production checks:", ""] + ["- " + clean(x) for x in b["production_checks"]]
        lines += ["", "Evidence: " + clean(", ".join(b["evidence_ids"])), ""]
    lines += ["## Challenge pass", ""]
    for c in report["challenges"]:
        lines.append(f"- **{clean(c['boundary_id'])} / {c['outcome']}**: {clean(c['check'])} "
                     f"{clean(c['result'])} Evidence: {clean(', '.join(c['evidence_ids'])) or 'Unresolved'}.")
    lines += ["", "## Open questions", ""]
    for q in report["open_questions"]:
        lines.append(f"- **{clean(q['boundary_id'])}**: {clean(q['question'])} "
                     f"Needed: {clean(q['needed_evidence'])}")
    lines += ["", "## Limitations", ""] + ["- " + clean(x) for x in report["limitations"]]
    lines += ["", "## Evidence", ""]
    for e in report["evidence"]:
        lines += [f"- **{clean(e['id'])}** ({e['kind']}): {e['root']}/{clean(e['path'])}, "
                  f"lines {e['start_line']}-{e['end_line']}. SHA-256: {e['sha256']}.",
                  f"  Captured: {clean(e['captured_at']) or 'Repository file; no deployment observation'}. {clean(e['notes'])}"]
    return "\n".join(lines) + "\n"


def initialize(args):
    repo = Path(args.repo).resolve(strict=True)
    if not repo.is_dir():
        raise ReportError("--repo must be a directory")
    out = Path(args.out).resolve()
    scope = read_json(HOME / "scope.example.json")
    scope.update(operation=args.operation, compromised_component=args.compromised)
    # Never overwrite a previous review, including its supplied evidence.
    out.mkdir(parents=True, exist_ok=False)
    (out / "scope.json").write_text(json.dumps(scope, indent=2) + "\n", encoding="utf-8")
    report = {"report_version": "1", "scope": scope, "steps": [], "boundaries": [],
              "evidence": [], "challenges": [], "open_questions": [], "limitations": []}
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    header = ("# Run a boundary review\n\nRepository: " + str(repo) + "\n\n"
              "Output folder: " + str(out) + "\n\n"
              "Read scope.json here. Write report.json here. Read the format and schema at " + str(HOME) + ". "
              "This template is intentionally incomplete and must fail validation until investigated.\n\n")
    (out / "RUN.md").write_text(header + (HOME / "prompts/map.md").read_text(encoding="utf-8"), encoding="utf-8")
    (out / "CHALLENGE.md").write_text((HOME / "prompts/challenge.md").read_text(encoding="utf-8"), encoding="utf-8")
    print(f"Review initialized: {out}\nGive RUN.md to your coding agent. No investigation has run.")
    print(shlex.join([sys.executable, str(HOME / "boundary_map.py"), "validate", str(out / "report.json"), "--repo", str(repo)]))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create a private investigation workspace")
    for name in ("repo", "operation", "compromised", "out"):
        init.add_argument("--" + name, required=True)
    for name in ("validate", "render"):
        sub = commands.add_parser(name)
        sub.add_argument("report")
        sub.add_argument("--repo", required=True)
        if name == "render":
            sub.add_argument("--out", required=True)
    ev = commands.add_parser("evidence", help="Hash a selected file and check its line range")
    for name in ("root", "path", "id"):
        ev.add_argument("--" + name, required=True)
    for name in ("start", "end"):
        ev.add_argument("--" + name, required=True, type=int)
    ev.add_argument("--source", choices=["repository", "artifacts"], default="repository")
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            initialize(args)
        elif args.command == "evidence":
            print(json.dumps(evidence_record(args.root, args.path, args.start, args.end, args.id, args.source), indent=2))
        else:
            report = read_json(args.report)
            errors = validate(report, args.report, args.repo)
            if errors:
                print("Report contract/evidence errors:\n" + "\n".join("- " + e for e in errors), file=sys.stderr)
                return 1
            if args.command == "render":
                output = Path(args.out).resolve()
                if output == Path(args.report).resolve():
                    raise ReportError("Refusing to overwrite the JSON report with Markdown")
                with output.open("x", encoding="utf-8") as file:
                    file.write(render(report))
                print(f"Rendered: {output}")
            else:
                print("Report structure and evidence checks complete. This is not a system-security verdict.")
        return 0
    except (ReportError, OSError, UnicodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
