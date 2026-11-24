"""Regenerate tests/fixtures from the fake tenant: python tests/make_fixtures.py"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path[:0] = [str(HERE.parent), str(HERE)]
from apimtk import assess, inventory  # noqa: E402
from fake_arm import SINCE, FakeArm  # noqa: E402

arm = FakeArm()
rows = assess.run(arm, None, "MZK9-GH0")
inv = inventory.run(arm, rows, since=SINCE)
(HERE / "fixtures").mkdir(exist_ok=True)
(HERE / "fixtures" / "assess.json").write_text(json.dumps(rows, indent=2, default=str))
(HERE / "fixtures" / "inventory.json").write_text(json.dumps(inv, indent=2, default=str))
print("fixtures written")
