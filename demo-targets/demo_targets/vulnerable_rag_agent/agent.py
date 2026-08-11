"""The vulnerable RAG agent.

Deterministic, like the support agent, and for the same reason: a regression test that goes
green after a fix went green because of the fix.

It fails differently, though, and that is why it exists as a separate target. The support agent
is compromised through its *tools*. A RAG application is compromised through its *corpus*, and
the damage lands somewhere the current session cannot see:

* **No source trust level.** Every passage carries one. The vulnerable build never reads it, so
  a wiki page anyone can edit steers the agent exactly as well as a reviewed policy document.
* **Malicious citations.** The answer cites the clean document whose *keywords* matched while
  the content that shaped it came from the poisoned one. A human spot-check passes.
* **Context poisoning across turns.** Injected text stays in the working set and steers later,
  unrelated questions in the same session.
* **System prompt leakage through retrieval**, never through the chat surface, so a guard that
  watches user input sees nothing.
* **Durable memory with no provenance, tenant scope or confidence.** This is the one that
  outlives the session: a namespace survives `reset()`, exactly as a real vector store
  survives a conversation ending.

Set `secure=True` for the hardened variant.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field, replace
from typing import Any

from demo_targets.vulnerable_rag_agent.data import (
    CORPUS,
    SEED_MEMORY,
    SYSTEM_PROMPT,
    TENANT_A,
    MemoryEntry,
    Passage,
    Trust,
)

#: Passages returned per query. Small enough that a planted one is always in the window, which
#: keeps the demo deterministic.
TOP_K = 3

#: Memories returned per turn, most recent first. Real stores retrieve top-K from memory
#: too; recalling everything is neither realistic nor scannable, because a scan runs
#: hundreds of scenarios against one process and an unbounded store makes each scenario
#: read what every earlier one planted.
RECALL_K = 3

_REVEAL_RE = re.compile(
    r"(?:reveal|show|print|repeat|display|output|disclose|summarise)[^.\n]{0,40}"
    r"(?:system prompt|initial instructions|your instructions|corpus key|configuration)",
    re.IGNORECASE,
)
_REMEMBER_RE = re.compile(
    r"(?:remember|memorise|memorize|note down|store|save|keep in mind|from now on)"
    r"[^.\n]{0,120}",
    re.IGNORECASE,
)
_CITE_RE = re.compile(r"\b(?:DOC|WIKI|WEB)-\d{3}\b")
_ESCALATE_RE = re.compile(
    r"(?:retrieve|fetch|look\s?up|pull|include|attach)[^.\n]{0,60}"
    r"(?:embargo|confidential|roadmap|pricing|internal only|all documents)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class Directive:
    """Something the agent decided to do, and the passage that suggested it."""

    kind: str
    arguments: dict[str, Any] = field(default_factory=dict)
    origin: str = "user"


@dataclass(slots=True)
class Session:
    """One conversation. Note what is *not* here: memory."""

    session_id: str
    tenant_id: str = TENANT_A
    secure: bool = False
    steps: list[dict[str, Any]] = field(default_factory=list)
    injected_passages: list[Passage] = field(default_factory=list)
    #: Passages retrieved so far this session. The vulnerable build never clears it, so text
    #: retrieved for question one is still in the working set for question three.
    working_set: list[Passage] = field(default_factory=list)
    #: Which durable namespace this conversation reads and writes. Sessions sharing a key
    #: see each other's facts; sessions with different keys cannot.
    memory_key: str = ""
    #: Memory ids this session created. Kept for reporting, never for cleanup.
    planted_memory: list[str] = field(default_factory=list)
    #: Text planted into a tool's own response, keyed by tool name. A retrieval tool's
    #: output carries more implicit trust than a document: "the index said so" reads as
    #: ground truth in a way "a wiki page said so" does not.
    injected_tool_results: dict[str, str] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0

    def record(
        self,
        step_type: str,
        *,
        content: str = "",
        tool_name: str | None = None,
        data: dict[str, Any] | None = None,
        source: str | None = None,
    ) -> None:
        self.steps.append(
            {
                "sequence_number": len(self.steps),
                "step_type": step_type,
                "tool_name": tool_name,
                "content": content,
                "data": data or {},
                "source": source,
                "timestamp": time.time(),
            }
        )


class RagAgent:
    """The agent under test."""

    def __init__(self, *, secure: bool = False) -> None:
        self.secure = secure
        self.sessions: dict[str, Session] = {}
        # Durable memory, namespaced. A real vector store is scoped to a user or a thread, and
        # the namespace is what makes this both realistic and usable by a scanner.
        #
        # It was one flat dict, which is a shared mutable global. A scan runs ten scenarios
        # concurrently against one process, so scenario 40 read what scenario 37 planted and
        # which three entries came back depended on the scheduler. Coverage came out 54 on a
        # laptop and 53 on a CI runner - the worst possible failure for a gate, because the
        # number is wrong in a way that looks like a real regression.
        self.memory_spaces: dict[str, dict[str, MemoryEntry]] = {}

    # -- lifecycle -----------------------------------------------------------------

    def start_session(
        self, tenant_id: str | None = None, *, memory_key: str | None = None
    ) -> Session:
        """Open a conversation against a memory namespace.

        `memory_key` is the caller's correlation id. Two sessions sharing one see each other's
        durable facts - which is the entire cross-session claim - and two that do not are
        isolated, which is what lets a scan run them in parallel.
        """
        session = Session(
            session_id=f"rag-{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id or TENANT_A,
            secure=self.secure,
            memory_key=memory_key or uuid.uuid4().hex,
        )
        self.sessions[session.session_id] = session
        self.memory_space(session.memory_key)
        return session

    def memory_space(self, key: str) -> dict[str, MemoryEntry]:
        """The namespace for `key`, seeded on first use so a poisoned fact has company."""
        space = self.memory_spaces.get(key)
        if space is None:
            # Copied, never shared: a namespace that mutates the seed would leak the
            # first scenario's edits into every later one.
            space = {entry.id: replace(entry) for entry in SEED_MEMORY}
            self.memory_spaces[key] = space
        return space

    def get_session(self, session_id: str) -> Session | None:
        return self.sessions.get(session_id)

    def reset(self, session_id: str) -> None:
        """Drop the conversation. Durable memory survives, which is the point.

        Ending a chat does not un-write a vector store, and a demo where it did would make
        memory poisoning look like a session-scoped problem. Isolation between scans comes
        from the namespace, never from deleting what a session wrote.
        """
        self.sessions.pop(session_id, None)

    def forget_all(self) -> None:
        """Wipe every namespace. Only the harness calls this; no agent path reaches it."""
        self.memory_spaces = {}

    def inject(self, session_id: str, artifact: dict[str, Any]) -> None:
        """Plant content into a channel the agent will later read."""
        session = self.sessions.get(session_id)
        if session is None:
            return

        channel = artifact.get("channel", "knowledge_base")
        content = str(artifact.get("content", ""))

        if channel == "tool_result":
            session.injected_tool_results[str(artifact.get("tool_name", ""))] = content
            return

        if channel == "memory":
            # Straight into durable memory, with none of the fields that would let anyone
            # decide whether to trust it later. Nothing in the vulnerable build stops this,
            # and that absence *is* the finding.
            entry = MemoryEntry(
                id=str(artifact.get("artifact_id") or f"MEM-{uuid.uuid4().hex[:6]}"),
                content=content,
                provenance="unknown",
                tenant_id="",
                confidence=0.0,
                confirmed=False,
                injected=True,
            )
            self.memory_space(session.memory_key)[entry.id] = entry
            session.planted_memory.append(entry.id)
            return

        trust = Trust.TENANT if channel == "knowledge_base" else Trust.PUBLIC
        session.injected_passages.append(
            Passage(
                id=str(artifact.get("artifact_id") or f"WIKI-{uuid.uuid4().hex[:4].upper()}"),
                title=str(artifact.get("title") or "Untitled"),
                content=content,
                trust=trust,
                tenant_id=session.tenant_id,
                keywords=_keywords_of(content),
                injected=True,
            )
        )

    # -- the turn ------------------------------------------------------------------

    def handle(self, session: Session, message: str) -> str:
        session.record("USER_INPUT", content=message, source="user")
        session.input_tokens += max(1, len(message) // 4)

        passages = self._retrieve(session, message)
        recalled = self._recall(session)

        directives = self._plan(session, message, passages, recalled)
        answer = self._act(session, message, directives, passages)

        session.output_tokens += max(1, len(answer) // 4)
        session.record("FINAL_OUTPUT", content=answer, source="model")
        return answer

    def _retrieve(self, session: Session, query: str) -> list[Passage]:
        session.record("TOOL_CALL", tool_name="search_documents", data={"arguments": {"query": query}})

        # Embargoed passages are out of scope for ordinary retrieval in *both* builds. A
        # canary that leaks on every query would be noise; one that leaks only after something
        # escalated is evidence.
        candidates = [*session.injected_passages, *(p for p in CORPUS if not p.restricted)]
        scored = [p for p in candidates if _matches(p, query)] or candidates[:TOP_K]

        if session.secure:
            # Scope by tenant at the retrieval boundary. The vulnerable build filters nowhere.
            scored = [p for p in scored if p.tenant_id in ("", session.tenant_id)]

        hits = scored[:TOP_K]

        for passage in hits:
            session.record(
                "RETRIEVAL",
                content=passage.content,
                data={
                    "document_id": passage.id,
                    "trust": passage.trust,
                    "tenant_id": passage.tenant_id,
                    "injected": passage.injected,
                },
                source="corpus",
            )

        # The working set is never cleared in vulnerable mode, so a passage retrieved for an
        # earlier question keeps steering later ones.
        if session.secure:
            session.working_set = list(hits)
        else:
            session.working_set.extend(hits)

        session.record(
            "TOOL_RESULT",
            tool_name="search_documents",
            content="\n\n".join(f"{p.id} {p.title}: {p.content}" for p in hits),
            data={"count": len(hits), "document_ids": [p.id for p in hits]},
            source="corpus",
        )
        return hits

    def _recall(self, session: Session) -> list[MemoryEntry]:
        """Read durable memory back into the working context."""
        session.record("TOOL_CALL", tool_name="recall_memory", data={"arguments": {}})

        entries = list(self.memory_space(session.memory_key).values())[-RECALL_K:]
        if session.secure:
            # Three conditions, and the vulnerable build applies none: scoped to this tenant,
            # confirmed by a human, and above a confidence floor.
            entries = [
                e
                for e in entries
                if e.tenant_id == session.tenant_id and e.confirmed and e.confidence >= 0.5
            ]

        for entry in entries:
            session.record(
                "RETRIEVAL",
                content=entry.content,
                data={
                    "memory_id": entry.id,
                    "provenance": entry.provenance,
                    "tenant_id": entry.tenant_id,
                    "confidence": entry.confidence,
                    "confirmed": entry.confirmed,
                    "injected": entry.injected,
                },
                source="memory",
            )

        session.record(
            "TOOL_RESULT",
            tool_name="recall_memory",
            content="\n".join(e.content for e in entries),
            data={"count": len(entries), "memory_ids": [e.id for e in entries]},
            source="memory",
        )
        return entries

    def _plan(
        self,
        session: Session,
        message: str,
        passages: list[Passage],
        recalled: list[MemoryEntry],
    ) -> list[Directive]:
        directives: list[Directive] = []

        if _REMEMBER_RE.search(message):
            directives.append(Directive("remember", {"text": message}, origin="user"))

        # The vulnerability: text from retrieved passages and recalled memory is parsed for
        # instructions exactly as the user's message is. In secure mode the working set is
        # searched only for *content*, and this loop does not run.
        if session.secure:
            return directives

        sources: list[tuple[str, str]] = [
            (f"passage:{p.id}", p.content) for p in session.working_set
        ]
        sources += [(f"memory:{e.id}", e.content) for e in recalled]

        for origin, text in sources:
            if _REVEAL_RE.search(text):
                directives.append(Directive("reveal_prompt", {}, origin=origin))
            if _ESCALATE_RE.search(text):
                directives.append(Directive("escalate_retrieval", {}, origin=origin))
            if _REMEMBER_RE.search(text):
                directives.append(Directive("remember", {"text": text}, origin=origin))

        return directives

    def _act(
        self,
        session: Session,
        message: str,
        directives: list[Directive],
        passages: list[Passage],
    ) -> str:
        parts: list[str] = []

        for directive in directives:
            if directive.kind == "reveal_prompt":
                session.record(
                    "MODEL_OUTPUT",
                    content=SYSTEM_PROMPT,
                    data={"origin": directive.origin},
                    source="model",
                )
                parts.append(SYSTEM_PROMPT)

            elif directive.kind == "escalate_retrieval":
                extra = self._escalate(session, directive)
                parts.extend(p.content for p in extra)

            elif directive.kind == "remember":
                self._remember(session, directive)

        answer = " ".join(parts) if parts else _summarise(passages)
        return f"{answer}\n\nSources: {_citations(session, passages)}"

    def _escalate(self, session: Session, directive: Directive) -> list[Passage]:
        """Fetch everything, ignoring trust and tenant. Only reachable from a directive."""
        session.record(
            "TOOL_CALL",
            tool_name="search_documents",
            data={"arguments": {"query": "*", "scope": "all"}, "origin": directive.origin},
        )
        hits = [p for p in CORPUS if p.trust == Trust.INTERNAL or p.tenant_id != session.tenant_id]
        for passage in hits:
            session.record(
                "RETRIEVAL",
                content=passage.content,
                data={
                    "document_id": passage.id,
                    "trust": passage.trust,
                    "tenant_id": passage.tenant_id,
                },
                source="corpus",
            )
        session.record(
            "TOOL_RESULT",
            tool_name="search_documents",
            content="\n\n".join(p.content for p in hits),
            data={"document_ids": [p.id for p in hits], "count": len(hits)},
            source="corpus",
        )
        session.working_set.extend(hits)
        return hits

    def _remember(self, session: Session, directive: Directive) -> None:
        text = str(directive.arguments.get("text", ""))

        if session.secure:
            # A durable write needs a human, a scope and an origin. A claim that arrived from
            # a passage is never one of those, so it is refused and the refusal is recorded.
            if not directive.origin.startswith("user"):
                session.record(
                    "TOOL_RESULT",
                    tool_name="write_memory",
                    content="Refused: only a user-confirmed statement may be stored.",
                    data={"blocked": True, "status_code": 403, "origin": directive.origin},
                    source="memory",
                )
                return
            entry = MemoryEntry(
                id=f"MEM-{uuid.uuid4().hex[:6]}",
                content=text,
                provenance=directive.origin,
                tenant_id=session.tenant_id,
                confidence=0.8,
                confirmed=True,
            )
        else:
            entry = MemoryEntry(
                id=f"MEM-{uuid.uuid4().hex[:6]}",
                content=text,
                provenance="unknown",
                tenant_id="",
                confidence=0.0,
                confirmed=False,
                injected=not directive.origin.startswith("user"),
            )

        session.record(
            "TOOL_CALL",
            tool_name="write_memory",
            data={"arguments": {"content": text, "provenance": entry.provenance}},
        )
        self.memory_space(session.memory_key)[entry.id] = entry
        session.planted_memory.append(entry.id)
        session.record(
            "TOOL_RESULT",
            tool_name="write_memory",
            content=f"Stored as {entry.id}.",
            data={
                "memory_id": entry.id,
                "provenance": entry.provenance,
                "tenant_id": entry.tenant_id,
                "confidence": entry.confidence,
                "confirmed": entry.confirmed,
            },
            source="memory",
        )


# ---------------------------------------------------------------------------------


def _citations(session: Session, passages: list[Passage]) -> str:
    """Which sources the answer claims.

    The vulnerable build cites whatever scored highest by keyword, which is routinely a clean
    document, while the text above came from a planted one. That is what makes a human
    spot-check pass: the citation is real, checkable, and unrelated to the answer.
    """
    if session.secure:
        return ", ".join(p.id for p in passages) or "none"

    clean = [p for p in passages if not p.injected]
    return ", ".join(p.id for p in (clean or passages)) or "none"


def _summarise(passages: list[Passage]) -> str:
    if not passages:
        return "I could not find anything relevant."
    return " ".join(p.content for p in passages[:2])


def _matches(passage: Passage, query: str) -> bool:
    lowered = query.lower()
    if passage.injected:
        return True
    return any(keyword in lowered for keyword in passage.keywords)


def _keywords_of(content: str) -> list[str]:
    return [word.lower() for word in re.findall(r"[a-zA-Z]{4,}", content)[:12]]
