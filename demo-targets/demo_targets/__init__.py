"""Intentionally vulnerable targets.

These exist so AgentShield can be demonstrated and regression-tested without pointing it at
anyone else's system. Every dangerous action is mocked: no email is sent, no SQL runs, no
money moves. All secrets are synthetic canaries.

**Do not deploy these. Do not copy patterns from them.** The support agent in particular is a
catalogue of exactly what not to do, written the way these systems are actually written - 
which is why it fails the way real ones fail.
"""

__version__ = "0.1.0"
