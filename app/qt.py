"""PySide6 desktop UI for the local PII scrubber (replaces the Streamlit app).

    pip install PySide6
    python app/qt_app.py

Same flow as the Streamlit version: paste text -> review detected spans (accept / reject / add)
-> see exactly what the model will receive -> copy it or send it -> paste the response ->
re-hydrated answer with warnings. Everything runs locally; only the scrubbed prompt is ever
sent, and only when you press Send.

Detection and sending run in worker threads so the window never freezes (the first detection
loads the local NER model, which takes a few seconds).
"""

from __future__ import annotations

import bisect
import re
import sys
from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFontDatabase, QKeySequence, QShortcut, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSplitter,
    QTableWidget, QTableWidgetItem, QTabWidget, QTextEdit, QToolTip, QVBoxLayout, QWidget,
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scrubber import Session, Span  # noqa: E402
from scrubber.llm_client import LLMClient  # noqa: E402
from scrubber.pipeline import Scrubber  # noqa: E402
from scrubber.policy import default_policy  # noqa: E402
from scrubber.rehydrate import rehydrate  # noqa: E402

COLOURS = {
    "secret": "#ff6b6b", "card": "#ff8787", "iban": "#ffa8a8", "nhs_number": "#ffc9c9", "ni_number": "#fcc2d7",
    "person": "#74c0fc", "email": "#63e6be", "phone": "#8ce99a", "username": "#a9e34b", "user_id": "#d8f5a2",
    "uuid": "#e9ecef", "ip": "#ffd43b", "address": "#b197fc", "postcode": "#d0bfff", "date_of_birth": "#ffa94d",
    "date": "#ffe8cc", "organisation": "#99e9f2", "location": "#c5f6fa", "quasi_identifier": "#f783ac",
}
TYPES = sorted(set(COLOURS) | set(default_policy().modes["balanced"]))
LAYER_NAMES = ["L1", "L2", "L3", "L4", "L5"]
LAYER_HELP = "L1 secrets · L2 structured · L3 key-aware · L4 local NER (GLiNER) · L5 local LLM (Ollama)"
KNOWN_LIMITS = """\
- English text and UK identifier formats only.
- Quasi-identifiers in free text ("the only female professor in…") are only partially covered (L5, optional).
- Unknown custom ID formats (e.g. `CUST-88231`) are missed unless the key name matches or a custom pattern is added in `config/policy.yaml`.
- **Pseudonymised data is still personal data.** This tool reduces risk; it does not make data anonymous or compliant.
"""
EXAMPLE = """Hi team, I'm Jane Doe (jane.doe+shop@gmail.com, 07911 123456). Ms Doe's NHS number is 943 476 5919.
2024-05-01T10:00:00Z WARN auth failed user=jdoe92 src=10.0.0.12 token=sk-proj-Q1w2E3r4T5y6U7i8O9p0AsDfGhJk
{"customer": "Jane Doe", "dob": "03/05/1988", "address": "12 High Street, Southampton SO17 1BJ", "note": "Jane asked about her refund"}"""

T_INPUT, T_REVIEW, T_PREVIEW, T_RESPONSE = range(4)
SURROGATE_SHAPES = [r"\[[A-Z_]+(?:_\d+)?(?:_REMOVED)?\]", r"\[AGE \d+-\d+\]"]

STYLE = """
QWidget { background:#1e1f22; color:#dfe1e5; font-size:13px; }
QPlainTextEdit, QTextEdit, QTableWidget, QLineEdit, QComboBox {
    background:#2b2d30; border:1px solid #3c3f41; border-radius:6px; padding:3px; }
QScrollArea { border:none; }
QPushButton { background:#3574f0; color:white; border:none; border-radius:6px; padding:7px 16px; }
QPushButton:hover { background:#4a85f5; }
QPushButton:disabled { background:#3c3f41; color:#7a7e85; }
QPushButton#secondary { background:#3c3f41; color:#dfe1e5; }
QPushButton#secondary:hover { background:#4a4d50; }
QTabWidget::pane { border:1px solid #3c3f41; border-radius:6px; }
QTabBar::tab { background:#2b2d30; padding:8px 18px; border-top-left-radius:6px; border-top-right-radius:6px; margin-right:2px; }
QTabBar::tab:selected { background:#3574f0; color:white; }
QTabBar::tab:disabled { color:#6b6f76; }
QHeaderView::section { background:#2b2d30; border:none; border-bottom:1px solid #3c3f41; padding:5px; }
QTableWidget { gridline-color:#33363a; }
QGroupBox { border:1px solid #3c3f41; border-radius:6px; margin-top:10px; padding-top:8px; }
QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; }
QToolTip { background:#2b2d30; color:#dfe1e5; border:1px solid #555; }
QSplitter::handle { background:#2b2d30; }
"""
WARN_STYLE = "color:#ffd43b;"
OK_STYLE = "color:#69db7c;"
MUTED_STYLE = "color:#9a9da3;"


# ---- highlighting ---------------------------------------------------------------------------------


class _Offsets:
    """Python str indices are code points; Qt document positions are UTF-16 units. Convert."""

    def __init__(self, text: str) -> None:
        self.identity = all(ord(c) <= 0xFFFF for c in text)
        self.prefix: list[int] = []
        if not self.identity:
            self.prefix = [0]
            for c in text:
                self.prefix.append(self.prefix[-1] + (2 if ord(c) > 0xFFFF else 1))

    def to_qt(self, i: int) -> int:
        return i if self.identity else self.prefix[min(i, len(self.prefix) - 1)]

    def from_qt(self, j: int) -> int:
        return j if self.identity else bisect.bisect_right(self.prefix, j) - 1


class HighlightView(QPlainTextEdit):
    """Read-only text view with coloured regions and a hover tooltip per region."""

    def __init__(self) -> None:
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self.viewport().setMouseTracking(True)
        self._hl: list[tuple[int, int, str, str]] = []
        self._starts: list[int] = []
        self._map = _Offsets("")

    def set_content(self, text: str, highlights: list[tuple[int, int, str, str]]) -> None:
        """highlights: (start, end, colour, tooltip) in code-point offsets into `text`."""
        self.setPlainText(text)
        self._map = _Offsets(text)
        self._hl = sorted(_non_overlapping(highlights), key=lambda h: h[0])
        self._starts = [h[0] for h in self._hl]
        selections = []
        for start, end, colour, _ in self._hl:
            fmt = QTextCharFormat()
            fmt.setBackground(QColor(colour))
            fmt.setForeground(QColor("#111111"))
            cur = QTextCursor(self.document())
            cur.setPosition(self._map.to_qt(start))
            cur.setPosition(self._map.to_qt(end), QTextCursor.MoveMode.KeepAnchor)
            sel = QTextEdit.ExtraSelection()
            sel.cursor, sel.format = cur, fmt
            selections.append(sel)
        self.setExtraSelections(selections)

    def reveal(self, start: int) -> None:
        cur = QTextCursor(self.document())
        cur.setPosition(self._map.to_qt(start))
        self.setTextCursor(cur)
        self.ensureCursorVisible()

    def mouseMoveEvent(self, e) -> None:  # noqa: N802
        super().mouseMoveEvent(e)
        i = self._map.from_qt(self.cursorForPosition(e.position().toPoint()).position())
        k = bisect.bisect_right(self._starts, i) - 1
        if k >= 0 and self._hl[k][0] <= i < self._hl[k][1]:
            QToolTip.showText(e.globalPosition().toPoint(), self._hl[k][3], self)
        else:
            QToolTip.hideText()


def _non_overlapping(items: list[tuple[int, int, str, str]]) -> list[tuple[int, int, str, str]]:
    out, pos = [], 0
    for h in sorted(items, key=lambda x: x[0]):
        if h[0] < pos or h[1] <= h[0]:
            continue
        out.append(h)
        pos = h[1]
    return out


def span_highlights(spans: list[dict]) -> list[tuple[int, int, str, str]]:
    return [(s["start"], s["end"], COLOURS.get(s["type"], "#dee2e6"), f"{s['type']} · {s['source']} · {s['reason']}")
            for s in spans if s["keep"]]


def output_highlights(text: str, session: Session) -> list[tuple[int, int, str, str]]:
    keys = sorted(session.vault.reverse, key=len, reverse=True)
    rx = re.compile("|".join([re.escape(k) for k in keys] + SURROGATE_SHAPES))
    out = []
    for m in rx.finditer(text):
        tip = "surrogate (restored locally)" if m.group() in session.vault.reverse else "removed / generalised value"
        out.append((m.start(), m.end(), "#a5d8ff", tip))
    return out


# ---- workers --------------------------------------------------------------------------------------


class DetectWorker(QThread):
    done = Signal(object, object, object)  # scrubber, spans, warnings
    failed = Signal(str)

    def __init__(self, layers: tuple[str, ...], cached: Scrubber | None, text: str) -> None:
        super().__init__()
        self.layers, self.cached, self.text = layers, cached, text

    def run(self) -> None:
        try:
            scrubber = self.cached or Scrubber(list(self.layers))
            spans, warnings = scrubber.detect(self.text)
            self.done.emit(scrubber, spans, warnings)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class SendWorker(QThread):
    done = Signal(str)
    failed = Signal(str)

    def __init__(self, client: LLMClient, prompt: str, meta: dict) -> None:
        super().__init__()
        self.client, self.prompt, self.meta = client, prompt, meta

    def run(self) -> None:
        try:
            self.done.emit(self.client.send(self.prompt, self.meta))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"{type(exc).__name__}: {exc}")


# ---- main window ----------------------------------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Local PII scrubber")
        self.policy = default_policy()
        self.session = Session()
        self.scrubbers: dict[tuple[str, ...], Scrubber] = {}
        self.spans: list[dict] = []  # span fields + "keep"
        self.text: str | None = None  # the text the spans were detected on
        self.detected_layers: tuple[str, ...] = ()
        self.result = None
        self._filling = False
        self._pending: tuple[tuple[str, ...], str] | None = None
        self.worker: QThread | None = None
        try:
            self.client = LLMClient()
        except Exception:  # noqa: BLE001 - bad LLM_PROVIDER in .env: fall back to dry-run
            self.client = LLMClient("dryrun")

        root = QWidget()
        self.setCentralWidget(root)
        lay = QHBoxLayout(root)
        lay.addWidget(self._build_sidebar())
        main = QVBoxLayout()
        title = QLabel("🛡️  Local PII scrubber")
        title.setStyleSheet("font-size:20px;font-weight:600;")
        sub = QLabel("Detection runs on this machine. Only the scrubbed text is ever sent to a model.")
        sub.setStyleSheet(MUTED_STYLE)
        main.addWidget(title)
        main.addWidget(sub)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_input_tab(), "1 · Input")
        self.tabs.addTab(self._build_review_tab(), "2 · Review")
        self.tabs.addTab(self._build_preview_tab(), "3 · Preview & send")
        self.tabs.addTab(self._build_response_tab(), "4 · Response")
        self._set_review_enabled(False)
        self.tabs.currentChanged.connect(self._tab_changed)
        main.addWidget(self.tabs, 1)
        lay.addLayout(main, 1)
        self._refresh_session_label()
        self.statusBar().showMessage("Paste text and press Detect.")

    # ---- UI construction -------------------------------------------------------------------------
    def _build_sidebar(self) -> QWidget:
        inner = QWidget()
        v = QVBoxLayout(inner)
        h = QLabel("Settings")
        h.setStyleSheet("font-size:16px;font-weight:600;")
        v.addWidget(h)

        v.addWidget(QLabel("Mode"))
        self.mode = QComboBox()
        self.mode.addItems(["balanced", "strict"])
        self.mode.setToolTip("strict generalises more (shifted dates, IPs removed, …)")
        self.mode.currentTextChanged.connect(self._mode_changed)
        v.addWidget(self.mode)

        box = QGroupBox("Detector layers")
        box.setToolTip(LAYER_HELP)
        bl = QVBoxLayout(box)
        self.layer_boxes: dict[str, QCheckBox] = {}
        for name in LAYER_NAMES:
            cb = QCheckBox(name)
            cb.setChecked(name in self.policy.enabled_layers)
            self.layer_boxes[name] = cb
            bl.addWidget(cb)
        note = QLabel(LAYER_HELP)
        note.setWordWrap(True)
        note.setStyleSheet(MUTED_STYLE + "font-size:11px;")
        bl.addWidget(note)
        v.addWidget(box)

        self.session_label = QLabel()
        self.session_label.setStyleSheet(MUTED_STYLE)
        self.session_label.setWordWrap(True)
        v.addWidget(self.session_label)
        new = QPushButton("New session (forget mappings)")
        new.setObjectName("secondary")
        new.clicked.connect(self._new_session)
        v.addWidget(new)

        limits = QGroupBox("Known limits")
        limits.setCheckable(True)
        limits.setChecked(False)
        ll = QVBoxLayout(limits)
        lab = QLabel(KNOWN_LIMITS)
        lab.setTextFormat(Qt.TextFormat.MarkdownText)
        lab.setWordWrap(True)
        lab.setVisible(False)
        ll.addWidget(lab)
        limits.toggled.connect(lab.setVisible)
        v.addWidget(limits)

        legend = QGroupBox("Legend")
        grid = QGridLayout(legend)
        for i, (t, c) in enumerate(COLOURS.items()):
            sw = QLabel(t)
            sw.setStyleSheet(f"background:{c};color:#111;border-radius:3px;padding:1px 6px;font-size:11px;")
            grid.addWidget(sw, i // 2, i % 2)
        v.addWidget(legend)
        v.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(inner)
        scroll.setFixedWidth(290)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        return scroll

    def _build_input_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel("Paste text (prose, logs, JSON, key=value…)"))
        self.input = QPlainTextEdit()
        self.input.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.input.setPlainText(EXAMPLE)
        self.input.textChanged.connect(self._input_changed)
        v.addWidget(self.input, 1)
        row = QHBoxLayout()
        self.detect_btn = QPushButton("Detect")
        self.detect_btn.clicked.connect(self._detect)
        QShortcut(QKeySequence("Ctrl+Return"), self, activated=self._detect)
        row.addWidget(self.detect_btn)
        self.input_note = QLabel()
        self.input_note.setStyleSheet(WARN_STYLE)
        row.addWidget(self.input_note, 1)
        v.addLayout(row)
        self.detect_warnings = QLabel()
        self.detect_warnings.setStyleSheet(WARN_STYLE)
        self.detect_warnings.setWordWrap(True)
        v.addWidget(self.detect_warnings)
        return w

    def _build_review_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel("Detected spans — hover a highlight for the type, detector layer and reason."))
        split = QSplitter(Qt.Orientation.Vertical)
        self.review_view = HighlightView()
        split.addWidget(self.review_view)

        lower = QWidget()
        lv = QVBoxLayout(lower)
        lv.setContentsMargins(0, 0, 0, 0)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["scrub?", "type", "text", "source", "conf.", "reason"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.itemChanged.connect(self._item_changed)
        self.table.currentCellChanged.connect(self._row_selected)
        lv.addWidget(self.table, 1)

        add = QHBoxLayout()
        self.manual_text = QLineEdit()
        self.manual_text.setPlaceholderText("Add a span manually: exact text (every occurrence is added)")
        self.manual_text.returnPressed.connect(self._add_manual)
        self.manual_type = QComboBox()
        self.manual_type.addItems(TYPES)
        self.manual_type.setCurrentText("person")
        btn = QPushButton("Add")
        btn.clicked.connect(self._add_manual)
        add.addWidget(self.manual_text, 1)
        add.addWidget(self.manual_type)
        add.addWidget(btn)
        lv.addLayout(add)
        split.addWidget(lower)
        split.setSizes([220, 380])
        v.addWidget(split, 1)

        nxt = QPushButton("Next: preview what the model will see →")
        nxt.clicked.connect(lambda: self.tabs.setCurrentIndex(T_PREVIEW))
        v.addWidget(nxt, 0, Qt.AlignmentFlag.AlignRight)
        return w

    def _build_preview_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        split = QSplitter(Qt.Orientation.Horizontal)
        for attr, title in (("orig_view", "Original (stays here)"), ("out_view", "Scrubbed prompt (sent)")):
            box = QWidget()
            bv = QVBoxLayout(box)
            bv.setContentsMargins(0, 0, 0, 0)
            lab = QLabel(title)
            lab.setStyleSheet("font-weight:600;")
            view = HighlightView()
            setattr(self, attr, view)
            bv.addWidget(lab)
            bv.addWidget(view, 1)
            split.addWidget(box)
        v.addWidget(split, 1)

        self.report_label = QLabel()
        self.report_label.setStyleSheet(MUTED_STYLE)
        self.report_label.setWordWrap(True)
        self.preview_warnings = QLabel()
        self.preview_warnings.setStyleSheet(WARN_STYLE)
        self.preview_warnings.setWordWrap(True)
        v.addWidget(self.report_label)
        v.addWidget(self.preview_warnings)

        self.instruction = QLineEdit()
        self.instruction.setPlaceholderText("Instruction to prepend (optional)")
        v.addWidget(self.instruction)

        row = QHBoxLayout()
        copy = QPushButton("Copy scrubbed prompt")
        copy.setObjectName("secondary")
        copy.clicked.connect(self._copy)
        self.send_btn = QPushButton(f"Send via {self.client.provider}")
        self.send_btn.setEnabled(self.client.provider != "dryrun")
        self.send_btn.setToolTip("Set LLM_PROVIDER and an API key in .env to enable")
        self.send_btn.clicked.connect(self._send)
        info = QLabel(f"provider `{self.client.provider}` · model `{self.client.model}` · "
                      f"exact payload logged to `{self.client.log_path.name}`")
        info.setStyleSheet(MUTED_STYLE)
        row.addWidget(copy)
        row.addWidget(self.send_btn)
        row.addWidget(info, 1)
        v.addLayout(row)
        return w

    def _build_response_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel("Paste (or receive) the model's response"))
        self.response_box = QPlainTextEdit()
        self.response_box.textChanged.connect(self._rehydrate)
        v.addWidget(self.response_box, 1)
        lab = QLabel("Re-hydrated (local only)")
        lab.setStyleSheet("font-weight:600;")
        v.addWidget(lab)
        self.restored_view = QPlainTextEdit()
        self.restored_view.setReadOnly(True)
        v.addWidget(self.restored_view, 1)
        self.rehydrate_note = QLabel()
        self.rehydrate_note.setWordWrap(True)
        v.addWidget(self.rehydrate_note)
        return w

    # ---- helpers ---------------------------------------------------------------------------------
    def _set_review_enabled(self, on: bool) -> None:
        for i in (T_REVIEW, T_PREVIEW, T_RESPONSE):
            self.tabs.setTabEnabled(i, on)

    def _selected_layers(self) -> tuple[str, ...]:
        return tuple(sorted(n for n, cb in self.layer_boxes.items() if cb.isChecked()))

    def _refresh_session_label(self) -> None:
        self.session_label.setText(f"Session {self.session.id} · {len(self.session.vault.reverse)} mappings in memory")

    def _kept_spans(self) -> list[Span]:
        return [Span(**{k: v for k, v in s.items() if k != "keep"}) for s in self.spans if s["keep"]]

    def _build_prompt(self) -> str:
        ins = self.instruction.text().strip()
        return (ins + "\n\n" if ins else "") + (self.result.scrubbed_text if self.result else "")

    # ---- slots: input / detect -------------------------------------------------------------------
    def _input_changed(self) -> None:
        stale = self.text is not None and self.input.toPlainText() != self.text
        self.input_note.setText("Input edited since the last detection — press Detect to refresh." if stale else "")

    def _detect(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        text = self.input.toPlainText()
        if not text.strip():
            self.statusBar().showMessage("Nothing to detect — paste some text first.", 4000)
            return
        layers = self._selected_layers()
        if not layers:
            self.statusBar().showMessage("Select at least one detector layer.", 4000)
            return
        self._pending = (layers, text)
        self.detect_btn.setEnabled(False)
        self.statusBar().showMessage("Detecting… (the first run loads the local NER model)")
        self.worker = DetectWorker(layers, self.scrubbers.get(layers), text)
        self.worker.done.connect(self._detected)
        self.worker.failed.connect(self._detect_failed)
        self.worker.start()

    def _detected(self, scrubber: Scrubber, spans: list[Span], warnings: list[str]) -> None:
        assert self._pending is not None
        layers, text = self._pending
        self.scrubbers[layers] = scrubber
        self.detected_layers, self.text = layers, text
        self.spans = [{**s.model_dump(), "keep": True} for s in sorted(spans, key=lambda s: s.start)]
        self.result = None
        self.detect_warnings.setText("\n".join(f"⚠ {w}" for w in warnings))
        self.detect_btn.setEnabled(True)
        self._input_changed()
        self._set_review_enabled(True)
        self._fill_table()
        self._refresh_review_view()
        self.statusBar().showMessage(f"Found {len(self.spans)} spans.", 5000)
        self.tabs.setCurrentIndex(T_REVIEW)

    def _detect_failed(self, msg: str) -> None:
        self.detect_btn.setEnabled(True)
        self.statusBar().clearMessage()
        QMessageBox.critical(self, "Detection failed", msg)

    # ---- slots: review ---------------------------------------------------------------------------
    def _refresh_review_view(self) -> None:
        self.review_view.set_content(self.text or "", span_highlights(self.spans))

    def _fill_table(self) -> None:
        self._filling = True
        t = self.table
        t.setRowCount(0)
        t.setRowCount(len(self.spans))
        for r, s in enumerate(self.spans):
            chk = QTableWidgetItem()
            chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            chk.setCheckState(Qt.CheckState.Checked if s["keep"] else Qt.CheckState.Unchecked)
            t.setItem(r, 0, chk)

            combo = QComboBox()
            combo.addItems(TYPES)
            if s["type"] not in TYPES:
                combo.addItem(s["type"])
            combo.setCurrentText(s["type"])
            combo.currentTextChanged.connect(lambda val, row=r: self._type_changed(row, val))
            t.setCellWidget(r, 1, combo)

            shown = s["text"] if s["type"] != "secret" else "•" * min(8, len(s["text"]))
            for c, val in ((2, shown), (3, s["source"]), (4, f"{s['confidence']:.2f}"), (5, s["reason"])):
                t.setItem(r, c, QTableWidgetItem(val))
        self._filling = False

    def _item_changed(self, item: QTableWidgetItem) -> None:
        if self._filling or item.column() != 0 or item.row() >= len(self.spans):
            return
        self.spans[item.row()]["keep"] = item.checkState() == Qt.CheckState.Checked
        self._refresh_review_view()

    def _type_changed(self, row: int, value: str) -> None:
        if not self._filling and row < len(self.spans):
            self.spans[row]["type"] = value
            self._refresh_review_view()

    def _row_selected(self, row: int, *_: int) -> None:
        if 0 <= row < len(self.spans):
            self.review_view.reveal(self.spans[row]["start"])

    def _add_manual(self) -> None:
        manual = self.manual_text.text()
        if not manual or self.text is None:
            return
        found = 0
        for m in re.finditer(re.escape(manual), self.text):
            self.spans.append({"start": m.start(), "end": m.end(), "text": manual, "type": self.manual_type.currentText(),
                               "source": "manual", "confidence": 1.0, "reason": "added by reviewer", "keep": True})
            found += 1
        if not found:
            self.statusBar().showMessage("Not found in the text.", 4000)
            return
        self.spans.sort(key=lambda s: s["start"])
        self.manual_text.clear()
        self._fill_table()
        self._refresh_review_view()
        self.statusBar().showMessage(f"Added {found} span(s).", 4000)

    # ---- slots: preview / send -------------------------------------------------------------------
    def _mode_changed(self, _: str) -> None:
        if self.text is not None and self.tabs.currentIndex() == T_PREVIEW:
            self._apply()

    def _tab_changed(self, index: int) -> None:
        if index == T_PREVIEW and self.text is not None:
            self._apply()

    def _apply(self) -> None:
        if self.text is None:
            return
        rejected = frozenset(s["text"] for s in self.spans if not s["keep"])
        try:
            self.result = self.scrubbers[self.detected_layers].apply(
                self.text, self._kept_spans(), self.session, self.mode.currentText(), allow=rejected)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Transform failed", f"{type(exc).__name__}: {exc}")
            return
        self.orig_view.set_content(self.text, span_highlights(self.spans))
        self.out_view.set_content(self.result.scrubbed_text, output_highlights(self.result.scrubbed_text, self.session))
        rep = self.result.report
        self.report_label.setText(f"actions: {rep['counts_by_action']} · leak-check fixes: {len(rep['leak_fixes'])}")
        self.preview_warnings.setText("\n".join(f"⚠ {w}" for w in rep["warnings"]))
        self._refresh_session_label()
        self._rehydrate()

    def _copy(self) -> None:
        if self.result is None:
            self._apply()
        QApplication.clipboard().setText(self._build_prompt())
        self.statusBar().showMessage("Scrubbed prompt copied to clipboard.", 4000)

    def _send(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            return
        if self.result is None:
            self._apply()
        if self.result is None:
            return
        self.send_btn.setEnabled(False)
        self.statusBar().showMessage(f"Calling {self.client.provider}:{self.client.model}…")
        self.worker = SendWorker(self.client, self._build_prompt(), {"purpose": "app", "session_id": self.session.id})
        self.worker.done.connect(self._sent)
        self.worker.failed.connect(self._send_failed)
        self.worker.start()

    def _sent(self, response: str) -> None:
        self.send_btn.setEnabled(self.client.provider != "dryrun")
        self.statusBar().showMessage("Response received.", 4000)
        self.response_box.setPlainText(response)
        self.tabs.setCurrentIndex(T_RESPONSE)

    def _send_failed(self, msg: str) -> None:
        self.send_btn.setEnabled(self.client.provider != "dryrun")
        self.statusBar().clearMessage()
        QMessageBox.critical(self, "LLM call failed", msg)

    # ---- slots: response -------------------------------------------------------------------------
    def _rehydrate(self) -> None:
        response = self.response_box.toPlainText()
        if not response:
            self.restored_view.clear()
            self.rehydrate_note.clear()
            return
        restored, warnings = rehydrate(response, self.session)
        self.restored_view.setPlainText(restored)
        if warnings:
            self.rehydrate_note.setStyleSheet(WARN_STYLE)
            self.rehydrate_note.setText("\n".join(f"⚠ {w}" for w in warnings))
        else:
            self.rehydrate_note.setStyleSheet(OK_STYLE)
            self.rehydrate_note.setText("All surrogates restored. Removed values (secrets, cards…) are never restored.")

    # ---- session ---------------------------------------------------------------------------------
    def _new_session(self) -> None:
        self.session = Session()
        self.spans, self.text, self.result = [], None, None
        self.table.setRowCount(0)
        self.review_view.set_content("", [])
        self.orig_view.set_content("", [])
        self.out_view.set_content("", [])
        self.response_box.clear()
        self.detect_warnings.clear()
        self._set_review_enabled(False)
        self.tabs.setCurrentIndex(T_INPUT)
        self._input_changed()
        self._refresh_session_label()
        self.statusBar().showMessage("New session — all mappings forgotten.", 4000)

    def closeEvent(self, event) -> None:  # noqa: N802
        if self.worker is not None and self.worker.isRunning():
            self.worker.wait(3000)
        super().closeEvent(event)


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    win = MainWindow()
    win.resize(1280, 820)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()