"""PySide6 desktop UI for the local PII scrubber.

    pip install PySide6
    python app/qt_app.py

Two pages, chosen in the left sidebar:

  Scrub Text  Paste text into "Original Text" and press Update. The scrubbed text appears on the
              right and every hidden item is listed in the table below (untick a row to leave that
              text as it is). Pick a model from the dropdown and press Send.
  Chat        A chat with the chosen model. Everything you type is scrubbed on this computer first,
              and the model's replies have the real details put back before you see them.

Only scrubbed text ever leaves the machine. API keys are read from the .env file in the repo root
(ANTHROPIC_API_KEY / OPENAI_API_KEY); every payload sent is logged by the LLM client.
"""

from __future__ import annotations

import bisect
import os
import re
import sys
from pathlib import Path

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, QThread, QTimer, Signal
from PySide6.QtGui import (
    QColor, QFontDatabase, QIcon, QKeySequence, QPainter, QPalette, QPen, QPixmap, QShortcut, QTextCharFormat,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QCheckBox, QComboBox, QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSplitter, QStackedWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QToolButton, QToolTip, QVBoxLayout, QWidget,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

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
BASE_LAYERS = ("L1", "L2", "L3", "L4")
ADVANCED_LAYER = "L5"  # local LLM, switched on by the "use advanced local LLM" tick box
MODE = "balanced"
WARMUP_TEXT = "Hi, I'm Jane Doe from Southampton. Email jane.doe@example.com or call 07911 123456."
SURROGATE_SHAPES = [r"\[[A-Z_]+(?:_\d+)?(?:_REMOVED)?\]", r"\[AGE \d+-\d+\]"]
PAGE_SCRUB, PAGE_CHAT = 0, 1

# (label shown in the dropdown, provider, model). The list is extended with whatever .env selects.
MODEL_CHOICES = [
    ("Claude Opus 5.5", "anthropic", "claude-opus-5-5"),
    ("Claude Sonnet 5.5", "anthropic", "claude-sonnet-5-5"),
    ("Claude Haiku 5.5", "anthropic", "claude-haiku-5-5"),
    ("GPT-4o", "openai", "gpt-4o"),
    ("GPT-4o mini", "openai", "gpt-4o-mini"),
    ("Local model (Ollama · qwen3:8b)", "ollama", "qwen3:8b"),
    ("Preview only (nothing is sent)", "dryrun", "none"),
]
KEY_VARS = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}

STYLE = """
QToolTip { background:#2b2d31; color:#dfe1e5; border:1px solid #555; padding:3px; }
QLabel { background:transparent; }
QCheckBox { background:transparent; spacing:7px; }

QFrame#sidebar { background:#1b1c20; border:none; border-right:1px solid #2a2c31; }
QPushButton#nav { background:#2b2d31; color:#dfe1e5; border:none; border-top-right-radius:4px;
    border-bottom-right-radius:4px; padding:9px 18px; font-size:18px; text-align:left; }
QPushButton#nav:hover { background:#34363b; }
QPushButton#nav:checked { background:#2f7bff; color:white; }
QPushButton#ghost { background:transparent; color:#8b8e95; border:none; padding:8px 18px; text-align:left; }
QPushButton#ghost:hover { color:#dfe1e5; }
QPushButton#primary { background:#1f6bd6; color:white; border:none; border-radius:4px; padding:6px 22px;
    font-size:16px; }
QPushButton#primary:hover { background:#2f7bff; }
QPushButton#primary:disabled { background:#2b2d31; color:#6f7379; }

QLabel#tabLabel { background:#131418; color:#b4b7bd; font-size:18px; padding:4px 22px;
    border-top-left-radius:8px; border-top-right-radius:8px; }
QPlainTextEdit#pane { background:#131418; border:none; padding:6px; font-size:13px; color:#dfe1e5; }

QTableWidget { background:#27292d; border:1px solid #34373c; font-size:12px; outline:none; color:#dfe1e5; }
QTableWidget::item { padding-left:4px; }
QTableWidget::item:selected { background:#33415c; color:#ffffff; }
QTableWidget QComboBox { font-size:12px; padding:1px 6px; min-height:20px; }
QHeaderView::section { background:#27292d; color:#c9ccd1; border:none; padding:6px; font-size:11px; }

QLineEdit { background:#26282c; border:1px solid #34373c; border-radius:4px; padding:7px 10px; color:#dfe1e5; }
QComboBox { background:#2b2d31; border:1px solid #3c3f44; border-radius:4px; padding:5px 10px; color:#dfe1e5; }
QComboBox QAbstractItemView { background:#2b2d31; color:#dfe1e5; selection-background-color:#2f7bff; }

QSplitter::handle:horizontal { background:#232833; }
QSplitter::handle:vertical { background:#202226; }

QScrollBar:vertical { background:#1d1e22; width:14px; margin:0; border:none; }
QScrollBar::handle:vertical { background:#5b5e64; min-height:30px; margin:2px; border-radius:5px; }
QScrollBar::handle:vertical:hover { background:#7a7d84; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background:none; }
QScrollBar:horizontal { background:#1d1e22; height:14px; margin:0; border:none; }
QScrollBar::handle:horizontal { background:#5b5e64; min-width:30px; margin:2px; border-radius:5px; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width:0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background:none; }

QStatusBar { border-top:1px solid #2f3136; color:#9a9da3; }
QStatusBar::item { border:none; }

QScrollArea#chatScroll { background:transparent; border:none; }
QWidget#chatHolder { background:transparent; }
QLabel#userBubble { background:#26364f; color:#e8eefc; border-radius:16px; padding:12px 16px; font-size:14px; }
QLabel#assistantText { color:#e6e8eb; font-size:14px; }
QLabel#caption { color:#7d8189; font-size:11px; }
QLabel#thinking { color:#8b8e95; font-size:14px; }
QLabel#chatError { color:#ff8787; font-size:14px; }
QLabel#emptyChat { color:#9a9da3; font-size:22px; padding-top:140px; }
QLabel#chatModel { color:#9a9da3; font-size:13px; }
QFrame#pill { background:#2b2d31; border:1px solid #3a3d42; border-radius:22px; }
QTextEdit#chatInput { background:transparent; border:none; font-size:15px; color:#e6e8eb; padding-top:6px; }
QPushButton#chatSend { background:#2f7bff; color:white; border:none; border-radius:18px; font-size:18px;
    font-weight:bold; min-width:36px; max-width:36px; min-height:36px; max-height:36px; padding:0; }
QPushButton#chatSend:disabled { background:#3a3d42; color:#6f7379; }
QToolButton#iconBtn { background:transparent; border:none; border-radius:6px; padding:4px; }
QToolButton#iconBtn:hover { background:#34363b; }
"""


def copy_icon(colour: str = "#c9ccd1", size: int = 20) -> QIcon:
    """Two overlapping rounded rectangles, drawn in code so no image files are needed."""
    scale = 2
    pm = QPixmap(size * scale, size * scale)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor(colour))
    pen.setWidthF(1.6 * scale)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    s = size * scale
    p.drawRoundedRect(QRectF(s * 0.38, s * 0.10, s * 0.50, s * 0.56), 2 * scale, 2 * scale)
    p.drawRoundedRect(QRectF(s * 0.12, s * 0.32, s * 0.50, s * 0.56), 2 * scale, 2 * scale)
    p.end()
    return QIcon(pm)


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


def _non_overlapping(items: list[tuple[int, int, str, str]]) -> list[tuple[int, int, str, str]]:
    out, pos = [], 0
    for h in sorted(items, key=lambda x: x[0]):
        if h[0] < pos or h[1] <= h[0]:
            continue
        out.append(h)
        pos = h[1]
    return out


class HighlightView(QPlainTextEdit):
    """Text box with coloured regions and a hover tooltip per region.

    Read-only (scrubbed text) or editable (the Original Text box). In the editable box the user's
    text is never replaced; only the highlights are refreshed, and right-clicking a selection offers
    "Scrub selection as …" for anything the detectors missed.
    """

    addRequested = Signal(str, str)  # selected text, type

    def __init__(self, editable: bool = False, placeholder: str = "") -> None:
        super().__init__()
        self.setObjectName("pane")
        self.setReadOnly(not editable)
        self.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        if placeholder:
            self.setPlaceholderText(placeholder)
        self.viewport().setMouseTracking(True)
        self.can_add = False  # set by the window: True while the highlights match the text
        self._hl: list[tuple[int, int, str, str]] = []
        self._starts: list[int] = []
        self._map = _Offsets("")

    def _paint(self, highlights: list[tuple[int, int, str, str]]) -> None:
        text = self.toPlainText()
        self._map = _Offsets(text)
        valid = [h for h in highlights if 0 <= h[0] < h[1] <= len(text)]
        self._hl = sorted(_non_overlapping(valid), key=lambda h: h[0])
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

    def set_content(self, text: str, highlights: list[tuple[int, int, str, str]]) -> None:
        """Replace the text and highlight it. highlights: (start, end, colour, tooltip) code-point offsets."""
        scroll = self.verticalScrollBar().value()  # keep the reader's place when the view refreshes
        self.setPlainText(text)
        self._paint(highlights)
        self.verticalScrollBar().setValue(scroll)

    def set_highlights(self, highlights: list[tuple[int, int, str, str]]) -> None:
        """Highlight the text as it currently is, without touching it."""
        self._paint(highlights)

    def clear_highlights(self) -> None:
        self._hl, self._starts = [], []
        self.setExtraSelections([])

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

    def contextMenuEvent(self, e) -> None:  # noqa: N802
        menu = self.createStandardContextMenu()
        sel = self.textCursor().selectedText().replace("\u2029", "\n").strip()
        if not self.isReadOnly() and self.can_add and sel:
            menu.addSeparator()
            sub = menu.addMenu("Scrub selection as")
            for t in TYPES:
                act = sub.addAction(t)
                act.triggered.connect(lambda _=False, t=t, s=sel: self.addRequested.emit(s, t))
        menu.exec(e.globalPos())
        menu.deleteLater()


def span_highlights(spans: list[dict]) -> list[tuple[int, int, str, str]]:
    return [(s["start"], s["end"], COLOURS.get(s["type"], "#dee2e6"), f"{s['type']} · {s['source']} · {s['reason']}")
            for s in spans if s["keep"]]


def output_highlights(text: str, session: Session) -> list[tuple[int, int, str, str]]:
    keys = sorted(session.vault.reverse, key=len, reverse=True)
    rx = re.compile("|".join([re.escape(k) for k in keys] + SURROGATE_SHAPES))
    out = []
    for m in rx.finditer(text):
        tip = "stand-in (the real value is restored locally)" if m.group() in session.vault.reverse else "removed or generalised"
        out.append((m.start(), m.end(), "#a5d8ff", tip))
    return out


def build_prompt(turns: list[tuple[str, str]]) -> str:
    """One scrubbed message is sent as-is; a longer conversation is sent as a transcript."""
    if len(turns) == 1:
        return turns[0][1]
    lines = ["Here is the conversation so far. Reply as the assistant to the last user message.", ""]
    for role, text in turns:
        lines += [f"{'User' if role == 'user' else 'Assistant'}: {text}", ""]
    lines.append("Assistant:")
    return "\n".join(lines)


# ---- workers --------------------------------------------------------------------------------------


class LoadWorker(QThread):
    """Builds the default pipeline at launch so the first Update is instant."""

    done = Signal(object, object)  # layers, scrubber
    failed = Signal(str)

    def __init__(self, layers: tuple[str, ...]) -> None:
        super().__init__()
        self.layers = layers

    def run(self) -> None:
        try:
            scrubber = Scrubber(list(self.layers))
            scrubber.detect(WARMUP_TEXT)  # forces any lazily-loaded model to load now, not on first use
            self.done.emit(self.layers, scrubber)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"{type(exc).__name__}: {exc}")


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


class ChatWorker(QThread):
    """Scrub (if needed) -> send -> re-hydrate, all off the UI thread.

    `scrub_text` is raw text that still needs scrubbing (a typed chat message, or the instruction box);
    `pre_scrubbed` is text that has already been scrubbed (the Scrub Text page output). History holds
    scrubbed text only, so nothing unscrubbed is ever re-sent.
    """

    done = Signal(object, str, str, str, int, object)  # scrubber, sent message, raw reply, restored, n scrubbed, warnings
    failed = Signal(str)

    def __init__(self, layers, cached, scrub_text, pre_scrubbed, history, client, session, meta) -> None:
        super().__init__()
        self.layers, self.cached = layers, cached
        self.scrub_text, self.pre_scrubbed = scrub_text, pre_scrubbed
        self.history, self.client, self.session, self.meta = history, client, session, meta

    def run(self) -> None:
        try:
            parts: list[str] = []
            n = 0
            scrubber = self.cached
            if self.scrub_text.strip():
                scrubber = scrubber or Scrubber(list(self.layers))
                spans, _ = scrubber.detect(self.scrub_text)
                res = scrubber.apply(self.scrub_text, spans, self.session, MODE)
                parts.append(res.scrubbed_text)
                n = len(spans)
            if self.pre_scrubbed:
                parts.append(self.pre_scrubbed)
            message = "\n\n".join(parts)
            prompt = build_prompt(self.history + [("user", message)])
            raw = self.client.send(prompt, self.meta)
            restored, warnings = rehydrate(raw, self.session)
            self.done.emit(scrubber, message, raw, restored, n, warnings)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class ChatInput(QTextEdit):
    """Auto-growing message box: Enter sends, Shift+Enter starts a new line."""

    submitted = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("chatInput")
        self.setAcceptRichText(False)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setFixedHeight(40)
        self.document().documentLayout().documentSizeChanged.connect(self._resize)

    def _resize(self, size) -> None:
        self.setFixedHeight(int(max(40, min(150, size.height() + 14))))

    def keyPressEvent(self, e) -> None:  # noqa: N802
        if e.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and not (e.modifiers() & Qt.KeyboardModifier.ShiftModifier):
            self.submitted.emit()
            return
        super().keyPressEvent(e)


# ---- main window ----------------------------------------------------------------------------------


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Local PII scrubber")
        self.session = Session()
        self.scrubbers: dict[tuple[str, ...], Scrubber] = {}
        self.spans: list[dict] = []  # span fields + "keep"
        self.text: str | None = None  # the text the spans were detected on
        self.detected_layers: tuple[str, ...] = ()
        self.result = None
        self.history: list[tuple[str, str]] = []  # (role, scrubbed text) sent to the model so far
        self._filling = False
        self._loading = True
        self._detecting = False
        self._busy = False
        self._detect_warn = ""
        self._pending: tuple[tuple[str, ...], str] | None = None
        self._pending_bubble: tuple[QLabel, QLabel] | None = None
        self._thinking: QWidget | None = None
        self._chat_widgets: list[QWidget] = []
        self.worker: QThread | None = None

        # ---- model choices (anything configured in .env is added / pre-selected) ----
        self.clients: dict[tuple[str, str], LLMClient] = {}
        try:
            env_client = LLMClient()
        except Exception:  # noqa: BLE001 - bad LLM_PROVIDER in .env: fall back to preview-only
            env_client = LLMClient("dryrun")
        self.choices = list(MODEL_CHOICES)
        env_key = (env_client.provider, env_client.model)
        idx = next((i for i, (_, p, m) in enumerate(self.choices) if (p, m) == env_key), None)
        if idx is None:
            self.choices.insert(0, (f"{env_key[0]} · {env_key[1]} (from .env)", *env_key))
            idx = 0
        self.clients[env_key] = env_client
        self.client = env_client

        # ---- layout: sidebar | pages ----
        root = QWidget()
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._build_sidebar())
        self.pages = QStackedWidget()
        self.pages.addWidget(self._build_scrub_page())
        self.pages.addWidget(self._build_chat_page())
        outer.addWidget(self.pages, 1)

        for label, _, _ in self.choices:
            self.model_combo.addItem(label)
        self.model_combo.setCurrentIndex(idx)
        self.model_combo.currentIndexChanged.connect(self._model_changed)
        self._model_changed(idx)

        QShortcut(QKeySequence("Ctrl+Return"), self, activated=self._update)

        # ---- load the detection model in the background; note it in the bottom-right corner ----
        self.model_status = QLabel("⏳ Loading detection model…")
        self.model_status.setStyleSheet("color:#ffd43b;")
        self.statusBar().addPermanentWidget(self.model_status)
        self.update_btn.setToolTip("Available once the detection model has finished loading")
        self.loader = LoadWorker(tuple(sorted(BASE_LAYERS)))
        self.loader.done.connect(self._preloaded)
        self.loader.failed.connect(self._preload_failed)
        self.loader.start()
        self._sync_controls()

    # ---- UI construction -------------------------------------------------------------------------
    def _build_sidebar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("sidebar")
        bar.setFixedWidth(185)
        v = QVBoxLayout(bar)
        v.setContentsMargins(0, 52, 0, 12)
        v.setSpacing(28)

        self.nav_scrub = QPushButton("Scrub Text")
        self.nav_chat = QPushButton("Chat")
        group = QButtonGroup(self)
        for i, b in enumerate((self.nav_scrub, self.nav_chat)):
            b.setObjectName("nav")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            group.addButton(b)
            b.clicked.connect(lambda _=False, i=i: self._show_page(i))
            v.addWidget(b, 0, Qt.AlignmentFlag.AlignLeft)
        self.nav_scrub.setChecked(True)
        # Both buttons share one resting width (wide enough for the longer label); the selected one is stretched.
        self._nav_buttons = (self.nav_scrub, self.nav_chat)
        self._nav_base = max(b.sizeHint().width() for b in self._nav_buttons)
        for b in self._nav_buttons:
            b.toggled.connect(self._restyle_nav)
        self._restyle_nav()
        v.addStretch(1)

        new = QPushButton("New session")
        new.setObjectName("ghost")
        new.setToolTip("Forget every replacement made so far and start fresh")
        new.clicked.connect(self._new_session)
        v.addWidget(new)
        return bar

    def _build_scrub_page(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(14, 10, 12, 6)
        v.setSpacing(8)

        split = QSplitter(Qt.Orientation.Vertical)
        split.setHandleWidth(6)

        # top: Original Text | Update + copy + scrubbed text
        panes = QSplitter(Qt.Orientation.Horizontal)
        panes.setHandleWidth(26)

        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.setSpacing(0)
        head = QHBoxLayout()
        head.setContentsMargins(0, 0, 0, 0)
        title = QLabel("Original Text")
        title.setObjectName("tabLabel")
        head.addWidget(title)
        head.addStretch(1)
        lv.addLayout(head)
        self.orig_view = HighlightView(
            editable=True,
            placeholder="Paste your text here, then press Update.\n\n"
                        "Tip: select something the detector missed, right-click and choose “Scrub selection as”.")
        self.orig_view.textChanged.connect(self._orig_changed)
        self.orig_view.addRequested.connect(self._add_selection)
        lv.addWidget(self.orig_view, 1)
        panes.addWidget(left)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(0)
        bar = QHBoxLayout()
        bar.setContentsMargins(0, 0, 0, 4)
        bar.setSpacing(12)
        self.update_btn = QPushButton("Update")
        self.update_btn.setObjectName("primary")
        self.update_btn.clicked.connect(self._update)
        self.copy_btn = QToolButton()
        self.copy_btn.setObjectName("iconBtn")
        self.copy_btn.setIcon(copy_icon())
        self.copy_btn.setIconSize(QSize(22, 22))
        self.copy_btn.setToolTip("Copy the scrubbed text")
        self.copy_btn.clicked.connect(self._copy)
        self.advanced = QCheckBox("use advanced local LLM")
        self.advanced.setToolTip("Slower, but can spot more subtle details. Runs entirely on this computer.")
        bar.addWidget(self.update_btn)
        bar.addWidget(self.copy_btn)
        bar.addStretch(1)
        bar.addWidget(self.advanced)
        rv.addLayout(bar)
        self.out_view = HighlightView(placeholder="The scrubbed text will appear here.")
        rv.addWidget(self.out_view, 1)
        panes.addWidget(right)
        panes.setSizes([520, 520])
        split.addWidget(panes)

        # bottom: the table of hidden items, extended to fill the space above the instruction row
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["scrub?", "type", "text", "source", "conf.", "reason"])
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hdr = self.table.horizontalHeader()
        hdr.setDefaultAlignment(Qt.AlignmentFlag.AlignCenter)
        for col, width in ((0, 62), (1, 118), (3, 64), (4, 56)):
            hdr.setSectionResizeMode(col, QHeaderView.ResizeMode.Fixed)
            self.table.setColumnWidth(col, width)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.itemChanged.connect(self._item_changed)
        self.table.currentCellChanged.connect(self._row_selected)
        split.addWidget(self.table)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setSizes([390, 280])
        v.addWidget(split, 1)

        self.instruction = QLineEdit()
        self.instruction.setPlaceholderText("Instruction to add in front of the text (optional)")
        v.addWidget(self.instruction)

        row = QHBoxLayout()
        row.setSpacing(8)
        self.model_combo = QComboBox()
        self.model_combo.setMinimumHeight(34)
        self.model_combo.setToolTip("Choose which AI model the scrubbed text is sent to")
        self.send_btn = QPushButton("Send")
        self.send_btn.setObjectName("primary")
        self.send_btn.setMinimumHeight(34)
        self.send_btn.setMinimumWidth(140)
        self.send_btn.clicked.connect(self._send)
        row.addWidget(self.model_combo, 1)
        row.addWidget(self.send_btn)
        v.addLayout(row)
        return page

    def _build_chat_page(self) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        head = QHBoxLayout()
        head.setContentsMargins(24, 10, 18, 0)
        self.chat_model_label = QLabel()
        self.chat_model_label.setObjectName("chatModel")
        new = QPushButton("New chat")
        new.setObjectName("ghost")
        new.clicked.connect(self._new_chat)
        head.addWidget(self.chat_model_label)
        head.addStretch(1)
        head.addWidget(new)
        v.addLayout(head)

        self.chat_scroll = QScrollArea()
        self.chat_scroll.setObjectName("chatScroll")
        self.chat_scroll.setWidgetResizable(True)
        self.chat_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.chat_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        holder = QWidget()
        holder.setObjectName("chatHolder")
        hl = QHBoxLayout(holder)
        hl.setContentsMargins(24, 8, 24, 16)
        column = QWidget()
        column.setMaximumWidth(780)
        self.chat_layout = QVBoxLayout(column)
        self.chat_layout.setContentsMargins(0, 0, 0, 0)
        self.chat_layout.setSpacing(18)
        self.chat_empty = QLabel("What would you like to ask?\nEverything you type is scrubbed on this computer first.")
        self.chat_empty.setObjectName("emptyChat")
        self.chat_empty.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        self.chat_layout.addWidget(self.chat_empty)
        self.chat_layout.addStretch(1)
        hl.addStretch(1)
        hl.addWidget(column, 100)
        hl.addStretch(1)
        self.chat_scroll.setWidget(holder)
        v.addWidget(self.chat_scroll, 1)

        bottom = QVBoxLayout()
        bottom.setContentsMargins(24, 0, 24, 14)
        bottom.setSpacing(6)
        note = QLabel("Messages are scrubbed on this computer before they are sent. Check important info.")
        note.setObjectName("caption")
        note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bottom.addWidget(note)
        pill = QFrame()
        pill.setObjectName("pill")
        pill.setMaximumWidth(780)
        ph = QHBoxLayout(pill)
        ph.setContentsMargins(20, 4, 8, 4)
        self.chat_input = ChatInput()
        self.chat_input.submitted.connect(self._chat_submit)
        self.chat_input.textChanged.connect(self._sync_controls)
        self.chat_send = QPushButton("↑")
        self.chat_send.setObjectName("chatSend")
        self.chat_send.clicked.connect(self._chat_submit)
        ph.addWidget(self.chat_input, 1)
        ph.addWidget(self.chat_send, 0, Qt.AlignmentFlag.AlignBottom)
        pill_row = QHBoxLayout()
        pill_row.setContentsMargins(0, 0, 0, 0)
        pill_row.addStretch(1)
        pill_row.addWidget(pill, 100)
        pill_row.addStretch(1)
        bottom.addLayout(pill_row)
        v.addLayout(bottom)
        return page

    # ---- navigation / state ----------------------------------------------------------------------
    def _restyle_nav(self, *_: object) -> None:
        for b in self._nav_buttons:
            b.setFixedWidth(self._nav_base + (24 if b.isChecked() else 0))

    def _show_page(self, i: int) -> None:
        self.pages.setCurrentIndex(i)
        (self.nav_scrub, self.nav_chat)[i].setChecked(True)

    def _layers(self) -> tuple[str, ...]:
        return tuple(sorted(BASE_LAYERS + ((ADVANCED_LAYER,) if self.advanced.isChecked() else ())))

    def _sync_controls(self) -> None:
        idle = not self._busy and not self._detecting
        can_send = self.client.provider != "dryrun"
        self.update_btn.setEnabled(not self._loading and idle)
        self.send_btn.setEnabled(can_send and idle and self.result is not None and not self._loading)
        self.send_btn.setToolTip(
            "Choose a model first (the preview-only option never sends anything)" if not can_send
            else "Press Update first" if self.result is None else f"Send the scrubbed text to {self._model_label()}")
        self.chat_send.setEnabled(can_send and idle and not self._loading and bool(self.chat_input.toPlainText().strip()))

    def _model_label(self) -> str:
        return self.choices[self.model_combo.currentIndex()][0]

    def _model_changed(self, i: int) -> None:
        _, provider, model = self.choices[i]
        if (provider, model) not in self.clients:
            self.clients[(provider, model)] = LLMClient(provider, model)
        self.client = self.clients[(provider, model)]
        label = self.choices[i][0]
        if provider == "dryrun":
            self.chat_model_label.setText("No model chosen. Pick one on the Scrub Text page to start chatting.")
            self.chat_input.setPlaceholderText("Choose a model on the Scrub Text page first")
        else:
            self.chat_model_label.setText(f"Chatting with {label}")
            self.chat_input.setPlaceholderText(f"Message {label}")
        self._sync_controls()

    def _missing_key(self) -> bool:
        var = KEY_VARS.get(self.client.provider)
        if var and not os.environ.get(var):
            QMessageBox.information(
                self, "API key needed",
                f"To use {self._model_label()}, add your API key to the file\n{ROOT / '.env'}\n\n"
                f"{var}=your-key-here\n\nthen restart the app.")
            return True
        return False

    # ---- background model loading ----------------------------------------------------------------
    def _preloaded(self, layers: tuple[str, ...], scrubber: Scrubber) -> None:
        self.scrubbers[layers] = scrubber
        self._loading = False
        self.update_btn.setToolTip("")
        self.model_status.setStyleSheet("color:#69db7c;")
        self.model_status.setText("✓ Model ready")
        QTimer.singleShot(4000, self.model_status.clear)
        self._sync_controls()

    def _preload_failed(self, msg: str) -> None:
        # Not fatal: Update falls back to loading the model on first use.
        self._loading = False
        self.update_btn.setToolTip("")
        self.model_status.setText("⚠ Model will load on first Update")
        self.statusBar().showMessage(f"Preload failed: {msg}", 10000)
        self._sync_controls()

    # ---- scrub page: input / detect --------------------------------------------------------------
    def _orig_changed(self) -> None:
        if self.text is None:
            return
        fresh = self.orig_view.toPlainText() == self.text
        self.orig_view.can_add = fresh
        if fresh:
            self.orig_view.set_highlights(span_highlights(self.spans))
        else:
            self.orig_view.clear_highlights()
            self.statusBar().showMessage("The text has changed. Press Update to refresh.")

    def _update(self) -> None:
        if self._loading or self._detecting or self._busy:
            return
        text = self.orig_view.toPlainText()
        if not text.strip():
            self.statusBar().showMessage("Paste some text into Original Text first.", 4000)
            return
        layers = self._layers()
        self._pending = (layers, text)
        self._detecting = True
        self._sync_controls()
        self.statusBar().showMessage("Detecting…")
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
        self._detect_warn = " · ".join(warnings)
        self._detecting = False
        self._fill_table()
        self._apply()
        self._orig_changed()

    def _detect_failed(self, msg: str) -> None:
        self._detecting = False
        self._sync_controls()
        self.statusBar().clearMessage()
        QMessageBox.critical(self, "Detection failed", msg)

    # ---- scrub page: review table ----------------------------------------------------------------
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
                item = QTableWidgetItem(val)
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                t.setItem(r, c, item)
        self._filling = False

    def _item_changed(self, item: QTableWidgetItem) -> None:
        if self._filling or item.column() != 0 or item.row() >= len(self.spans):
            return
        self.spans[item.row()]["keep"] = item.checkState() == Qt.CheckState.Checked
        self._apply()
        self._orig_changed()

    def _type_changed(self, row: int, value: str) -> None:
        if not self._filling and row < len(self.spans):
            self.spans[row]["type"] = value
            self._apply()
            self._orig_changed()

    def _row_selected(self, row: int, *_: int) -> None:
        if 0 <= row < len(self.spans) and self.text is not None and self.orig_view.can_add:
            self.orig_view.reveal(self.spans[row]["start"])

    def _add_selection(self, selected: str, type_: str) -> None:
        """Right-click > Scrub selection as <type>: add every occurrence of the selected text."""
        if self.text is None or not selected:
            return
        found = 0
        for m in re.finditer(re.escape(selected), self.text):
            self.spans.append({"start": m.start(), "end": m.end(), "text": selected, "type": type_,
                               "source": "manual", "confidence": 1.0, "reason": "added by reviewer", "keep": True})
            found += 1
        if not found:
            self.statusBar().showMessage("That text wasn't found in the original.", 4000)
            return
        self.spans.sort(key=lambda s: s["start"])
        self._fill_table()
        self._apply()
        self._orig_changed()

    def _apply(self) -> None:
        """Re-run the transform for the current selection and refresh both text boxes."""
        if self.text is None:
            return
        kept = [Span(**{k: v for k, v in s.items() if k != "keep"}) for s in self.spans if s["keep"]]
        rejected = frozenset(s["text"] for s in self.spans if not s["keep"])
        try:
            self.result = self.scrubbers[self.detected_layers].apply(self.text, kept, self.session, MODE, allow=rejected)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Something went wrong", f"{type(exc).__name__}: {exc}")
            return
        self.out_view.set_content(self.result.scrubbed_text, output_highlights(self.result.scrubbed_text, self.session))
        rep = self.result.report
        msg = f"{len(kept)} item(s) will be hidden from the AI."
        if rep["leak_fixes"]:
            msg += f" {len(rep['leak_fixes'])} repeated mention(s) elsewhere in the text were caught as well."
        warns = ([self._detect_warn] if self._detect_warn else []) + list(rep["warnings"])
        if warns:
            msg += "   ⚠ " + " · ".join(warns)
        self.statusBar().showMessage(msg)
        self._sync_controls()

    def _copy(self) -> None:
        text = self.out_view.toPlainText()
        if not text:
            self.statusBar().showMessage("Nothing to copy yet. Press Update first.", 4000)
            return
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage("Scrubbed text copied to the clipboard.", 4000)

    # ---- sending / chat --------------------------------------------------------------------------
    def _ready_to_send(self, need_scrubber: bool) -> bool:
        if self.client.provider == "dryrun":
            self.statusBar().showMessage("Choose a model first. The preview-only option never sends anything.", 5000)
            return False
        if self._missing_key():
            return False
        if need_scrubber and self.tuple_base() not in self.scrubbers and self._loading:
            self.statusBar().showMessage("Still loading the detection model. One moment…", 4000)
            return False
        return True

    @staticmethod
    def tuple_base() -> tuple[str, ...]:
        return tuple(sorted(BASE_LAYERS))

    def _send(self) -> None:
        """Send button on the Scrub Text page: the scrubbed text (plus a scrubbed instruction) goes to the model."""
        if self._busy or self._detecting or self.result is None:
            return
        if not self._ready_to_send(need_scrubber=True):
            return
        if self.text is not None and self.orig_view.toPlainText() != self.text:
            self.statusBar().showMessage("The original text has changed. Press Update before sending.", 5000)
            return
        self._start_send(display=None, scrub_text=self.instruction.text().strip(), pre_scrubbed=self.result.scrubbed_text)

    def _chat_submit(self) -> None:
        text = self.chat_input.toPlainText().strip()
        if not text or self._busy or self._detecting:
            return
        if not self._ready_to_send(need_scrubber=True):
            return
        self.chat_input.clear()
        self._start_send(display=text, scrub_text=text, pre_scrubbed="")

    def _start_send(self, display: str | None, scrub_text: str, pre_scrubbed: str) -> None:
        self._busy = True
        self._sync_controls()
        self._show_page(PAGE_CHAT)
        self._pending_bubble = self._add_user_bubble(display) if display is not None else None
        self._thinking = self._add_text_block("Thinking…", "thinking")
        base = self.tuple_base()
        meta = {"purpose": "app", "session_id": self.session.id}
        self.statusBar().showMessage(f"Waiting for {self._model_label()}…")
        self.worker = ChatWorker(base, self.scrubbers.get(base), scrub_text, pre_scrubbed, list(self.history),
                                 self.client, self.session, meta)
        self.worker.done.connect(self._chat_done)
        self.worker.failed.connect(self._chat_failed)
        self.worker.start()

    def _chat_done(self, scrubber, message: str, raw: str, restored: str, n: int, warnings: list[str]) -> None:
        if scrubber is not None:
            self.scrubbers.setdefault(self.tuple_base(), scrubber)
        self._remove_widget(self._thinking)
        self._thinking = None
        if self._pending_bubble is None:  # sent from the Scrub Text page: show what the model actually received
            self._pending_bubble = self._add_user_bubble(message)
            self._pending_bubble[1].setText("🛡 Sent scrubbed")
        else:
            bubble, caption = self._pending_bubble
            caption.setText(f"🛡 {n} item(s) scrubbed before sending" if n else "🛡 Checked: nothing to scrub")
            bubble.setToolTip("What the model received:\n\n" + message)
        self._pending_bubble = None
        if restored.strip():
            self._add_assistant(restored, warnings)
            self.history += [("user", message), ("assistant", raw)]
        else:
            self._add_text_block("The model returned an empty reply.", "chatError")
        self.statusBar().clearMessage()
        self._busy = False
        self._sync_controls()

    def _chat_failed(self, msg: str) -> None:
        self._remove_widget(self._thinking)
        self._thinking = None
        self._pending_bubble = None
        self._add_text_block(f"Couldn't get a reply: {msg}", "chatError")
        self.statusBar().clearMessage()
        self._busy = False
        self._sync_controls()

    # ---- chat widgets ----------------------------------------------------------------------------
    def _chat_add(self, widget: QWidget) -> None:
        self.chat_empty.hide()
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, widget)
        self._chat_widgets.append(widget)
        QTimer.singleShot(60, self._scroll_chat)

    def _scroll_chat(self) -> None:
        bar = self.chat_scroll.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _remove_widget(self, widget: QWidget | None) -> None:
        if widget is None:
            return
        if widget in self._chat_widgets:
            self._chat_widgets.remove(widget)
        self.chat_layout.removeWidget(widget)
        widget.deleteLater()

    def _label(self, text: str, name: str) -> QLabel:
        lab = QLabel(text)
        lab.setObjectName(name)
        lab.setWordWrap(True)
        lab.setTextFormat(Qt.TextFormat.PlainText)  # model output is shown literally, never as HTML
        lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        return lab

    def _add_user_bubble(self, text: str) -> tuple[QLabel, QLabel]:
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        box = QVBoxLayout()
        box.setSpacing(4)
        bubble = self._label(text, "userBubble")
        bubble.setMaximumWidth(620)
        caption = QLabel("")
        caption.setObjectName("caption")
        box.addWidget(bubble)
        box.addWidget(caption, 0, Qt.AlignmentFlag.AlignRight)
        h.addStretch(1)
        h.addLayout(box)
        self._chat_add(row)
        return bubble, caption

    def _add_text_block(self, text: str, name: str) -> QWidget:
        lab = self._label(text, name)
        self._chat_add(lab)
        return lab

    def _add_assistant(self, text: str, warnings: list[str]) -> None:
        block = QWidget()
        v = QVBoxLayout(block)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        v.addWidget(self._label(text, "assistantText"))
        if warnings:
            v.addWidget(self._label("⚠ " + " · ".join(warnings), "caption"))
        actions = QHBoxLayout()
        actions.setContentsMargins(0, 0, 0, 0)
        copy = QToolButton()
        copy.setObjectName("iconBtn")
        copy.setIcon(copy_icon("#9a9da3"))
        copy.setIconSize(QSize(18, 18))
        copy.setToolTip("Copy")
        copy.clicked.connect(lambda _=False, t=text: self._copy_text(t))
        actions.addWidget(copy)
        actions.addStretch(1)
        v.addLayout(actions)
        self._chat_add(block)

    def _copy_text(self, text: str) -> None:
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage("Copied.", 3000)

    def _chat_clear(self) -> None:
        for w in list(self._chat_widgets):
            self._remove_widget(w)
        self.history = []
        self.chat_empty.show()

    def _new_chat(self) -> None:
        if self._busy:
            return
        self._chat_clear()

    # ---- session ---------------------------------------------------------------------------------
    def _new_session(self) -> None:
        if self._busy or self._detecting:
            self.statusBar().showMessage("Please wait for the current request to finish.", 4000)
            return
        self.session = Session()
        self.spans, self.text, self.result = [], None, None
        self._detect_warn = ""
        self.table.setRowCount(0)
        self.orig_view.clear_highlights()
        self.orig_view.can_add = False
        self.out_view.set_content("", [])
        self._chat_clear()
        self._show_page(PAGE_SCRUB)
        self.statusBar().showMessage("New session started. Earlier replacements have been forgotten.", 4000)
        self._sync_controls()

    def closeEvent(self, event) -> None:  # noqa: N802
        for t in (self.loader, self.worker):
            if t is not None and t.isRunning():
                t.wait(3000)
        super().closeEvent(event)


def checkbox_qss() -> str:
    """Dark-theme checkbox boxes with a white tick (the tick is drawn in code and saved to a temp file)."""
    import tempfile

    image = ""
    try:
        path = Path(tempfile.gettempdir()) / "pii_scrubber_check.png"
        pm = QPixmap(14, 14)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor("#ffffff"))
        pen.setWidthF(1.8)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.drawPolyline([QPointF(3.2, 7.4), QPointF(6.0, 10.0), QPointF(10.8, 4.2)])
        p.end()
        if pm.save(str(path)):
            image = f"image:url({path.as_posix()});"
    except Exception:  # noqa: BLE001 - cosmetic only
        pass
    return (
        "QCheckBox::indicator, QTableView::indicator { width:14px; height:14px; border:1px solid #6b6e73;"
        " border-radius:3px; background:#1b1c20; }"
        f"QCheckBox::indicator:checked, QTableView::indicator:checked {{ background:#2f7bff; border-color:#2f7bff; {image} }}"
    )


def apply_theme(app: QApplication) -> None:
    app.setStyle("Fusion")
    pal = QPalette()
    for role, colour in (
        (QPalette.ColorRole.Window, "#202226"), (QPalette.ColorRole.WindowText, "#dfe1e5"),
        (QPalette.ColorRole.Base, "#131418"), (QPalette.ColorRole.AlternateBase, "#27292d"),
        (QPalette.ColorRole.Text, "#dfe1e5"), (QPalette.ColorRole.Button, "#2b2d31"),
        (QPalette.ColorRole.ButtonText, "#dfe1e5"), (QPalette.ColorRole.Highlight, "#2f7bff"),
        (QPalette.ColorRole.HighlightedText, "#ffffff"), (QPalette.ColorRole.ToolTipBase, "#2b2d31"),
        (QPalette.ColorRole.ToolTipText, "#dfe1e5"), (QPalette.ColorRole.PlaceholderText, "#7d8189"),
    ):
        pal.setColor(role, QColor(colour))
    app.setPalette(pal)
    app.setStyleSheet(STYLE + checkbox_qss())


def main() -> None:
    app = QApplication(sys.argv)
    apply_theme(app)
    win = MainWindow()
    win.resize(1280, 800)
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
    