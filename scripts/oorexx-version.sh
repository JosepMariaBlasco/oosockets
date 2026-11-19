# The ooRexx ooSockets builds and tests against. The CI and the session
# setup both read this file, so the two never differ. Since 19/11/2026 (the
# user: THROW, r13541-r13550) it is ahead of the family's revision
# (oorexx-bridges, CONVENTIONS.md, "Which ooRexx"), and built from
# SourceForge's SVN, not downloaded: scripts/get-oorexx.sh trunk.
OOREXX_REV=13550        # main/trunk r13550 (THROW, the Throw() API, error 4.901)
OOREXX_TEST_REV=13553   # ooRexx's test suite (ooRexxUnit), test/trunk
