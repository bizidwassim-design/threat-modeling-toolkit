# Checklist 5 — Validation and maintenance

A model that is never checked against reality is a story. This phase turns it into evidence.

## Verifying mitigations

- [ ] Each mitigation marked done has evidence attached: merged pull request, passing test, configuration export,
      pen-test retest, alert rule ID.
- [ ] Evidence is reviewed by someone other than the implementer.
- [ ] Residual likelihood and impact are re-scored after verification; residual must not exceed inherent.
- [ ] Threats that turned out to be already mitigated are closed with the evidence, not deleted.

## Testing the model itself

- [ ] At least one Critical or High threat has been turned into a concrete test case (manual or automated) and executed.
- [ ] The pen-test or red-team scope references the model's threat IDs and the testers report against them.
- [ ] Findings from scans, pen-tests and incidents are checked against the model: was the finding predicted? If not,
      add the threat and ask what the model missed.
- [ ] SOC detection coverage is checked for the High threats that cannot be prevented.

## Keeping it alive

- [ ] The YAML model is stored with the code and regenerated in CI, so the threat table cannot silently drift from the diagram.
- [ ] The next review trigger is recorded: date (at least yearly), architecture change, new third party, new data
      category, incident, regulatory change.
- [ ] Architecture decision records or design reviews reference the model ID and state whether the change needs a re-run.
- [ ] Accepted risks are reviewed at their review date; expired acceptances are re-decided, not silently extended.
- [ ] Metrics reported to management: number of open High/Critical threats, median time to mitigate, models older than 12 months.

## Output of this phase

Section 6 (validation record) and section 7 (sign-off) of the template, a dated model, and a review trigger in the calendar.
