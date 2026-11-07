# N2 — Ghost in the Wire · Solution (organizer copy)

See `docs/solution.md` for the full write-up. The deterministic reproduction is
`organizer/official_solve.py`:

```bash
python3 organizer/official_solve.py          # full trace + integrity check
python3 organizer/official_solve.py --quiet    # prints the two flags only
```

## Flags

| # | Objective | Value |
|---|-----------|-------|
| 1 | MAC attribution of compromised workstation `10.40.2.17` | `VVVFLAG{6a:8c:47:2d:91:b3}` |
| 2 | Recovered exfiltrated artifact (`chimera_phase2_briefing`) | `VVVFLAG{gh0st-in-dns-w1r3-4rs041}` |

These exact strings are written to `organizer/flag_config.json` by
`generate_evidence.py`. They must match the CTFd platform configuration
verbatim.
