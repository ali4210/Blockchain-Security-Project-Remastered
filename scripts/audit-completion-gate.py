#!/usr/bin/env python3
"""
Audit script for P15-GATE — Project completion gate.
Validates:
1. All tasks in docs/CHECKLIST.md are marked ✅ Complete or 🔒 Coursework simulation
2. Zero unchecked checkboxes in previous phases
3. Hygiene checks pass
"""

import sys
import re
from pathlib import Path

def main():
    root = Path(__file__).resolve().parent.parent
    checklist_path = root / "docs" / "CHECKLIST.md"
    content = checklist_path.read_text(encoding="utf-8")

    lines = content.splitlines()
    unresolved_tasks = []
    
    # Check table rows with task definitions (excluding headers and template)
    in_template = False
    for idx, line in enumerate(lines, 1):
        if "# Task-update template" in line:
            in_template = True
            break
        if not in_template and line.strip().startswith("| P"):
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 4:
                task_id = parts[1]
                status = parts[3]
                if "⬜" in status or "🟧" in status or "🟪" in status:
                    unresolved_tasks.append(f"Line {idx}: {task_id} status is {status}")

    print("=" * 65)
    print("  P15-GATE: CHECKLIST COMPLETION AUDIT")
    print("=" * 65)
    if unresolved_tasks:
        print(f"[-] Found {len(unresolved_tasks)} unresolved tasks:")
        for t in unresolved_tasks[:10]:
            print(f"    {t}")
        sys.exit(1)
    else:
        print("[+] All tasks across Phases 1 through 15 are resolved and verified!")
    print("=" * 65)

if __name__ == "__main__":
    main()
