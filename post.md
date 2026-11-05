# Why your SIEM engineer might be your next AI hyperscale engineer

A multi-agent system that processes security events has the same outer shape as a SIEM pipeline. Events are collected, queued, normalized, evaluated and acted on. What changes is the processing node: a deterministic rule is replaced, or supplemented, by a model call that returns structured output and can call tools. The part of SIEM work that matters most at agent scale is normalization. A normalized schema is what lets a thousand correlation rules read hundreds of sources, and it is what lets any number of agents use the same data without each agent handling each source format. As a bonus, I've added an interactive visual that shows 1,000 rules and 1,000 agents on the same normalized layer, with and without it.

## Data normalization is key to hyperscaling agents

A SIEM with 140 sources and 1,000 analytic rules does not have 20,000 integrations, which is what it would take for each rule to read the 20 or so raw sources in its schema directly. Each source has one parser into a common schema such as ASIM or the Splunk CIM, and each rule is written once against the schema. In Microsoft Sentinel a rule that queries `_Im_Authentication` covers Entra ID, Okta, AWS CloudTrail and every other authentication source with a parser, including sources added after the rule was written. The integration count is one parser per source, and the rules add none. (A standard Sentinel workspace allows 512 enabled scheduled rules; 1,000 needs a dedicated cluster, which allows 1,024, or a second workspace.)

Agents are consumers of the same data, and the same arithmetic applies. Without a normalized layer, every agent that investigates sign-ins has to read every raw authentication format, either through source-specific tools or by working out each format from the raw record on every call. With 140 sources spread across seven schemas, that is about 20 source-specific integrations per agent, and about 40,000 across 1,000 rules and 1,000 agents. Each new agent adds 20 more. Each field rename at a source breaks every rule and agent that reads that source directly, and agents that interpret raw formats themselves spend tokens doing it and can reach different conclusions from the same record.

With the normalized layer, the ASIM parsers are KQL functions, so the function an analytic rule calls is the same function an agent's query tool calls. Adding the 1,001st agent requires no new parser and no new integration. Adding a source requires one parser, and every existing rule and agent covers it. A field rename at a source is fixed once, in its parser. The number of agents is then limited by model capacity and query limits, not by integration work. The Log Analytics query API, for example, runs 5 concurrent queries per identity and queues up to 200 before returning HTTP 429, so query load is planned across agent identities the way rule load is planned across workspaces.

A common objection is that MCP already handles this. MCP standardizes how an agent finds and calls a tool: the transport, the tool description, and a JSON schema for each tool's inputs and, optionally, its outputs. Each server author chooses that schema. The protocol has no shared model for a sign-in, a firewall session or a lab result, so an MCP tool that queries a raw table returns that table's field names, and thirty authentication sources behind thirty MCP tools are still thirty formats. In the architecture later in this post, MCP is the tool layer that carries the data to agents; ASIM or FHIR defines its shape.

The work that makes this possible is existing SIEM work: onboarding sources, writing and testing parsers, maintaining schema coverage, and monitoring connector health. That work does not change when the consumers are agents. It becomes the precondition for running them at scale.

## Component mapping

Each part of a SIEM pipeline has a counterpart in a multi-agent pipeline. The table lists them side by side.

| Dimension | SIEM pipeline | Multi-agent pipeline |
|---|---|---|
| Runtime | Collection and indexing tier (Splunk, Elastic, Microsoft Sentinel, with Cribl or Vector in front) | Agent runtime (for example Microsoft Foundry Agent Service or Amazon Bedrock AgentCore), which schedules model calls and tool calls |
| Unit of work | A log event: a structured or semi-structured record of a state change | A message on an agent's input queue: an event, a tool result or a request, with a schema |
| Normalization | Parsers and data models (ASIM, Splunk CIM, grok patterns) | The same parsers and schemas, exposed to agents as query tools, plus a schema contract (a Pydantic model or JSON Schema) on each agent's inputs and outputs |
| Detection | Analytic rule or saved search: a fixed condition | Specialist agent: a system prompt, a scoped set of tools and a typed verdict |
| Transport | Kafka, Event Hubs, a forwarder queue, partitioned by key | Per-investigation input queues, processed in order for each investigation and in parallel across them |
| Response | SOAR playbook or Logic App with a fixed branch tree | Tool calls proposed by agents and approved or rejected by an enforcer |
| Testing | Detection-as-code with sample logs and expected matches | Evaluation sets: replayed incidents with expected verdicts and expected actions |
| Cost control | Ingestion tiers, data lake versus analytics tier, retention | Token budgets, model tiering, and suspending agents while they wait on tools |

The normalization, transport, ordering and cost rows are where SIEM experience transfers almost directly. The detection and response rows are where the work changes.

## Agent data stream schema example

A SIEM rule depends on field names. If a custom application changes `user_id` to `uid`, the parser still runs, the user field comes back empty, and the analytic rule stops matching. Nothing errors. The detection goes quiet and the gap is found later in a coverage review, or after an incident.

In an agent pipeline the same boundary is handled with a schema contract. Every event that enters the pipeline is validated against a typed model, and every verdict an agent returns is validated against another. A Python sketch:

```python
from typing import Literal
from pydantic import BaseModel, Field

class SignInEvent(BaseModel):
    user_principal_name: str
    ip_address: str
    result_code: int
    app_display_name: str | None = None

class TriageVerdict(BaseModel):
    verdict: Literal["benign", "suspicious", "malicious"]
    confidence: float = Field(ge=0, le=1)
    evidence: list[str]
    proposed_actions: list[str]
```

When an event fails validation, the pipeline has a choice a SIEM parser does not have. A mapping step can pass the raw record and the contract to a model and ask which source field corresponds to `user_principal_name`. The model's answer is a proposal, not a fix. It is validated against the contract, written to a log, and used to open a ticket to correct the parser. The model does not remove the need for normalization. It gives the pipeline a fallback path when a source drifts, and it makes the drift visible instead of silent.

The skills that apply here are the ones SIEM engineers already use: knowing the target schema (ASIM or CIM), writing field-level data quality checks, and testing parsers against real samples before a source goes live.

## Correlation rules in SIEM are similar to agent logic

An analytic rule is cheap, fast and deterministic. It runs in milliseconds, costs nothing per evaluation beyond the query, and gives the same answer every time. A model call takes seconds, costs tokens and can return different answers for the same input. Replacing every rule with an agent would raise cost and lower predictability for detections that already work.

A practical design keeps the analytic rules. Rules filter and score the high-volume stream. Agents take over at three points the rules handle poorly:

- Triage of incidents the rules have already raised, where an analyst would normally pull context from several tables before deciding.
- Free-text input, such as a phishing report written by a user, that no field-based rule can parse.
- Sources that fail normalization, where the mapping step described above applies.

Each specialist has one job, its own system prompt, and only the tools that job needs. An identity specialist can query `SigninLogs` and `AuditLogs`. An endpoint specialist can query `DeviceProcessEvents`. An email specialist can query `EmailEvents` and `UrlClickEvents`. The scoping is the same least-privilege work done today for a Logic App's managed identity or a Splunk service account.

## SOAR playbooks vs agentic orchestrator, specialists, and enforcer

A SOAR playbook encodes every branch in advance. The agent version splits that work across three roles:

- The orchestrator reads the incident, decides which specialists are needed, and starts them. It does not take actions itself.
- The specialists investigate in parallel and each return a typed verdict with evidence and proposed actions.
- The enforcer checks every proposed action before anything runs.

The enforcer should be code, not a model. It applies fixed rules: an allowlist of permitted actions per incident type, a list of protected accounts (break-glass accounts, the Entra Connect sync account, executives under a separate process), a blast-radius limit such as no more than five accounts disabled per incident, and a human approval requirement for destructive actions such as soft-deleting mail or isolating a server. These are the approval gates and change-control rules that already sit inside mature SOAR playbooks, moved out of each playbook into one place that every agent passes through.

The enforcer matters more in security than in most agent deployments because log content is attacker-controlled. A user agent string, an email body, a file name or a command line can contain text written to instruct a model. A specialist that reads a phishing email is reading the attacker's words. Treat every field that came from a log as untrusted input, keep it out of system prompts, and rely on the enforcer, not the specialist's judgment, to stop an action the attacker's text talked the model into proposing.

Each agent should also have its own identity, for example a Microsoft Entra Agent ID, so that its queries and actions appear in sign-in and audit logs under a name that can be monitored, scoped by Conditional Access, and disabled. The agent pipeline becomes a log source for the SIEM it supports.

## Testing and operating the pipeline

Detection-as-code practice carries over with one change. A rule test checks that a sample log produces a match. An agent test checks that a replayed incident produces the expected verdict and the expected proposed actions, within a confidence range, across repeated runs, because the output is not deterministic. Build the evaluation set from closed incidents with known outcomes, and rerun it whenever a prompt, a model version or a tool changes.

Operational metrics also carry over. Ingestion volume per day becomes tokens per incident. Rule latency becomes time to verdict. False positive rate stays as it is. Add two that SIEM pipelines do not need: the rate at which the enforcer rejects proposed actions, and the rate at which schema validation fails on agent output. A rising rejection rate means a prompt or a model change has made a specialist less reliable, and it should be visible on a dashboard before it causes a missed action or a wrong one.

## Skills that transfer and skills to add

Skills that transfer with little change:

- Normalization to a common schema and data quality checks at ingestion.
- Queue design, partitioning and ordering.
- Enrichment as an asynchronous lookup.
- Least-privilege service identities for automation.
- Approval gates and change control in response automation.
- Detection testing against known samples.
- Cost management by tier and volume.

Skills to add:

- Writing system prompts as specifications, with the output schema defined first.
- Building and maintaining evaluation sets.
- Choosing models by task, with smaller models for mapping and classification and larger ones for investigation.
- Defending against prompt injection from log content.
- Designing an enforcer as code, separate from the agents it controls.

## A use case: Hyperscale agentic use for healthcare

Hospital networks have the same structure. Patient data arrives from EHR registration, lab systems sending HL7 v2 results, admit, discharge and transfer feeds, pharmacy and e-prescribing systems, radiology and pathology, and claims. HL7 FHIR plays the role ASIM plays in Sentinel: each system is mapped once into FHIR resources such as Patient, Observation, Encounter, MedicationRequest, Condition, Procedure and DiagnosticReport, with standard codes (LOINC, RxNorm, ICD-10). FHIR R4 is the version required for patient access APIs in certified US EHR technology under the ONC Cures Act Final Rule.

The consumers are clinical decision support rules, such as sepsis screening or drug-interaction checks, and agents for prior authorization, care-gap outreach and coding review. The arithmetic is the same as for detections. With FHIR in place, a new agent calls the FHIR API and needs no interface work for any of the source systems. Without it, each agent decodes each feed itself. A source change shows the cost: if a lab system starts sending glucose in mmol/L instead of mg/dL, the FHIR mapping is corrected once, while every rule and agent reading the raw value directly sees results about 18 times too low. In security that is a missed detection; in healthcare it is a patient safety issue.

## The visual

The accompanying page draws 140 raw sources grouped by ASIM schema, the seven schemas in the middle, and two consumer fleets on the right: 1,000 correlation rules and 1,000 agents. With normalization selected, each source has one line to its schema and every consumer reads only the schema. With normalization removed, every consumer needs a line to every source in its schema, and the drawing becomes a dense mesh. Sliders change the number of sources and agents, and a counts table gives both designs side by side: integrations to maintain, work to add one agent, work to add one source, and consumers broken when a FortiGate source renames a field. Adding 1,000 agents to the normalized design adds no integrations; adding them without normalization adds about 20,000. A second button switches the same diagram to the healthcare example, with FHIR resources as the middle layer and decision support rules and clinical agents as the consumers. An Architecture view draws each example as Microsoft services: Sentinel with ASIM, the Sentinel MCP server and Foundry Agent Service for security; the Azure Health Data Services FHIR service, a FHIR MCP server and Foundry Agent Service for healthcare.

The visual is at https://broglock.github.io/siem-to-agent-normalization/ and the source, including this post, is at https://github.com/broglock/siem-to-agent-normalization.


## Security agent use cases by data schema

A second page maps 18 security agent use cases to the data each one reads. The columns are the seven normalized schemas from the visual (Authentication, Process Event, Network Session, DNS, Web Session, Audit Event and File Event), which agents reach through custom Sentinel MCP tools, and six Security Copilot plugin sources: Microsoft Entra, Defender XDR, Intune, Purview, Defender Threat Intelligence and Defender External Attack Surface Management. A solid dot marks the main source for a use case and a ring marks a context source. The bottom row counts the agents that read each source.

Five of the use cases overlap agents Microsoft already ships in Security Copilot: Conditional Access Optimization, Vulnerability Remediation, Phishing Triage, Purview DLP alert triage and Threat Intelligence Briefing. Building your own version is still useful when it needs to read non-Microsoft sources through the normalized schemas. Selecting a row on the page shows its trigger rule, the tools it needs and the actions it proposes. The matrix is at https://broglock.github.io/siem-to-agent-normalization/use-case-matrix.html.

## References

- HL7 FHIR R4: https://hl7.org/fhir/R4/
- ONC Cures Act Final Rule: https://www.healthit.gov/topic/oncs-cures-act-final-rule
- Microsoft Sentinel service limits: https://learn.microsoft.com/en-us/azure/sentinel/sentinel-service-limits
- Azure Monitor log query limits: https://learn.microsoft.com/en-us/azure/azure-monitor/service-limits
