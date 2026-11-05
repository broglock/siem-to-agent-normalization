# SIEM normalization and multi-agent systems

Material for the blog post "SIEM architecture skills that carry over to multi-agent systems".

- `index.html`: interactive visual. 1,000 rules and 1,000 agents reading 140 sources, with and without a normalization layer. Security (ASIM) and healthcare (HL7 FHIR) examples, plus an architecture view of each. Live at https://broglock.github.io/siem-to-agent-normalization/
- `post.md`: the blog post.
- `triage_mesh.py`: a standard-library Python sketch of an orchestrator, specialists and an enforcer for alert triage, using a stub model. Run with `python triage_mesh.py`.

Counts in the visual assume each consumer uses one schema and sources are spread evenly across seven schemas. Platform limits cited are from Microsoft and AWS documentation as of November 2026.
