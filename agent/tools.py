"""The four tools the agent can reach for.

Only the first two are ever authorized for the demo task. ``http_post`` and
``send_email`` exist so that there is something real to misuse -- but a tool the
policy engine blocks is never executed, only recorded.
"""

TOOL_NAMES = ("search_docs", "read_doc", "http_post", "send_email")

INTERNAL_HOSTS = ("wiki.internal", "docs.internal")
INTERNAL_EMAIL_DOMAINS = ("internal.example",)


class ToolError(Exception):
    pass


class Toolbox:
    def __init__(self, corpus):
        self.corpus = corpus
        self.calls = []

    def call(self, name, args):
        self.calls.append((name, dict(args)))
        handler = getattr(self, f"_{name}", None)
        if handler is None:
            raise ToolError(f"unknown tool: {name}")
        return handler(**args)

    def _search_docs(self, query, top_k=5):
        hits = self.corpus.retrieve(query, top_k=int(top_k))
        return {"hits": [dict(c.citation(), score_milli=s) for c, s in hits]}

    def _read_doc(self, doc_id):
        if doc_id not in self.corpus.docs:
            raise ToolError(f"no such document: {doc_id}")
        return {"doc_id": doc_id, "text": self.corpus.docs[doc_id]}

    def _http_post(self, url, body):
        # Never reached in the demo: the policy engine blocks it before execution.
        # It exists so the blocked call is a real capability, not a straw man.
        raise ToolError("http_post is disabled in this build; the attempt is what matters")

    def _send_email(self, to, subject, body):
        raise ToolError("send_email is disabled in this build; the attempt is what matters")
