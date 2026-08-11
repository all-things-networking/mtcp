# Mechanical renames applied to every seeded infrastructure file.
#
# Two jobs, and only these two:
#
#   1. rule 4 — a symbol this tree *defines* may not name a protocol. mTCP's
#      dev_ioctl commands and its serial-number comparison macro do.
#   2. readability — this is not mTCP, so the per-core stack instance is not
#      called `mtcp_manager`, and the flow record is not called `tcp_stream`.
#
# Everything else stays exactly as the donor wrote it, so `diff` against
# mtcp-donor stays meaningful (see ../PROVENANCE.md).
#
# Order matters only where one pattern is a prefix of another; `\b` on both
# ends makes the CSUM macros order-independent because `_` is a word char.

# --- includes: the donor's central header is split, and psio is not carried --
# unanchored: two of the donor's files (icmp.c, icmp.h) have CRLF line endings,
# so `$` does not match where you would expect it to
s/#include "mtcp\.h"/#include "infra.h"/
/#include "ps\.h"/d

# --- the per-core stack instance ---------------------------------------------
s/\bmtcp_manager_t\b/core_ctx_t/g
s/\bstruct mtcp_manager\b/struct core_ctx/g
s/\bmtcp_thread_context_t\b/thread_ctx_t/g
s/\bstruct mtcp_thread_context\b/struct thread_ctx/g
s/\bstruct mtcp_config\b/struct infra_config/g
s/\bg_mtcp\b/g_core/g
s/\bmtcp_core_affinitize\b/core_affinitize/g

# --- the flow record (target-owned; infra only names the type) ---------------
s/\btcp_stream\b/flow/g

# --- the bare local variable, last, so the compounds above are already gone ---
s/\bmtcp\b/core/g

# --- rule 4: macros mTCP defines that name a protocol ------------------------
s/\bPKT_TX_TCP_CSUM\b/PKT_TX_L4_CSUM/g
s/\bPKT_RX_TCP_CSUM\b/PKT_RX_L4_CSUM/g
s/\bPKT_TX_TCPIP_CSUM_PEEK\b/PKT_TX_L3L4_CSUM_PEEK/g
s/\bPKT_TX_TCPIP_CSUM\b/PKT_TX_L3L4_CSUM/g
s/\bPKT_RX_TCP_LROSEG\b/PKT_RX_L4_LROSEG/g
s/\bTCP_SEQ_GT\b/SEQ_GT/g
s/\bTCP_SEQ_LT\b/SEQ_LT/g
s/\bTCP_SEQ_GEQ\b/SEQ_GEQ/g
s/\bTCP_SEQ_LEQ\b/SEQ_LEQ/g

# the thread context's back-pointer, renamed with its type
s/->mtcp_manager\b/->core/g
