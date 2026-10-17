"""Smoke test of the Streamlit flow (no browser): detect → transform → rehydrate."""

from pathlib import Path

import pytest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest
APP = str(Path(__file__).resolve().parent.parent / "app" / "streamlit_app.py")


def test_app_flow():
    at = AppTest.from_file(APP, default_timeout=120)
    at.run()
    at.multiselect[0].set_value(["L1", "L2", "L3"])
    at.text_area(key="input").set_value('{"name": "Jane Doe", "email": "jane@corp.test", "token": "sk-proj-Q1w2E3r4T5y6U7i8O9p0AsDf"}')
    at.button[0].click()  # Detect
    at.run()
    assert not at.exception
    code = at.code[0].value
    assert "Jane Doe" not in code and "jane@corp.test" not in code and "sk-proj" not in code
    assert "Person_1" in code and "[SECRET_REMOVED]" in code
    at.text_area(key="response_box").set_value("Contact Person_1 at user_1@example.com; Person_9 unknown.")
    at.run()
    rendered = " ".join(m.value for m in at.markdown)
    assert "Contact Jane Doe at jane@corp.test" in rendered
    assert any("Person_9" in w.value for w in at.warning)
