# Checklist 3 — Threat identification

Generate first, think second. The script gives the baseline; the workshop gives the judgement.

## Before the workshop

- [ ] `stride-threats.md` and `.csv` generated from the validated model and shared with participants the day before.
- [ ] High-priority threats sorted to the top; participants asked to read only those (usually 40–60 rows).
- [ ] For systems with personal data: LINDDUN categories and the personal-data flow list ready.
- [ ] For PASTA: threat-actor profiles and the weakness list prepared.

## During the workshop (per element, boundary crossings first)

- [ ] For each High threat: keep, merge with another, or delete with a one-line reason.
- [ ] Ask the three questions the generator cannot: *Can a legitimate feature be abused? Is there a race or ordering
      problem? What can an insider with normal access do?*
- [ ] For each AI component: prompt injection paths (direct and via retrieved content), what the model can trigger,
      what the prompt and logs contain, who can change training or retrieval data.
- [ ] For each third party: what happens if it is compromised, unavailable or changes its terms.
- [ ] Rate likelihood and impact (1–5) using the organisation's scales; record the score and band.
- [ ] Threats with no agreed owner are assigned to the system owner by default.

## Quality gates

- [ ] Each kept threat is one sentence an engineer can test ("an unauthenticated caller can read any invoice by changing the ID").
- [ ] No threat is rated High or Critical without a named impact on a security objective from scoping.
- [ ] Deleted threats carry a reason, so the next review does not re-add them.
- [ ] The workshop added at least a few threats the generator did not produce. If it added none, it was too short.

## Output of this phase

Section 3 of the template filled: pruned generated threats plus workshop threats, each with L, I, score and owner.
