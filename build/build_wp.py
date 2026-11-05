import re,html,json
MONO='font-family:"IBM Plex Mono", "Courier New", monospace'
SERIF='font-family:"Lora", Georgia, serif'
CODE=f'<code style=\'{MONO};font-size:15px;background:#f0ebe0;border:1px solid #e4ddd4;padding:0 4px;color:#1c1917;white-space:nowrap\'>'
A='style="color:#b91c1c;text-decoration:none" target="_blank" rel="noopener"'
PAGES="https://broglock.github.io/siem-to-agent-normalization"
def inl(t):
    t=html.escape(t,quote=False).replace("'","&#8217;")
    t=re.sub(r'`([^`]+)`',lambda m:CODE+m.group(1)+'</code>',t)
    t=re.sub(r'(https?://[^\s<)]+[^\s<).,])',lambda m:f'<a href="{m.group(1)}" {A}>{m.group(1)}</a>',t)
    return t
P=lambda t:f'<p class="body-p" style="font-size:18px;color:#44403c;line-height:1.75;margin-bottom:16px">{inl(t)}</p>'
def UL(items):
    return '<ul class="fact-list" style="margin:0 0 22px 0;padding-left:22px">'+"".join(f'<li class="li" style="padding:5px 0 5px 4px;font-size:18px;color:#44403c;line-height:1.7">{inl(i)}</li>' for i in items)+'</ul>'
def TABLE(rows):
    th=f"{MONO};font-size:12.5px;letter-spacing:0.08em;text-transform:uppercase;color:#78716c;padding:8px 10px;text-align:left;font-weight:500"
    td="padding:9px 10px;vertical-align:top;line-height:1.55;font-size:16.5px;color:#44403c"
    h='<table class="spec-table" style="width:100%;border-collapse:collapse;font-size:16px;margin-bottom:24px" width="100%"><thead><tr style="border-bottom:2px solid #b5aca0">'+"".join(f"<th style='{th}' align=\"left\">{inl(c)}</th>" for c in rows[0])+'</tr></thead><tbody>'
    h+="".join('<tr style="border-bottom:1px solid #e4ddd4">'+"".join(f'<td style="{td}" valign="top">{inl(c)}</td>' for c in r)+'</tr>' for r in rows[1:])
    return h+'</tbody></table>'
def PRE(code):
    return f'<pre style=\'{MONO};font-size:15px;background:#f0ebe0;border:1px solid #e4ddd4;padding:12px 14px;color:#1c1917;line-height:1.55;overflow-x:auto;margin:0 0 20px\'>{html.escape(code)}</pre>'
def IMG(file,alt,read,title,head=None):
    return ((f'<p class="shot-head" style=\'{SERIF};font-size:21px;font-weight:700;color:#1c1917;line-height:1.35;margin:26px 0 8px\'>{html.escape(head)}</p>' if head else '')+f'<img class="shot" src="https://simplesecurityca.wordpress.com/wp-content/uploads/2026/11/{file}" alt="{html.escape(alt)}" style="width:100%;display:block;border:1px solid #d6cfc4;margin:14px 0 6px" width="100%">'
     f'<p class="shot-cap" style=\'{MONO};font-size:13px;color:#78716c;letter-spacing:0.04em;margin-bottom:6px\'>{html.escape(title)}</p>'
     f'<p class="shot-cap" style="font-size:16.5px;color:#44403c;line-height:1.65;margin-bottom:22px">{inl(read)}</p>')
def SEC(n,title,body,num=True):
    bg=f'<div class="section-bg-num" style=\'position:absolute;top:-10px;right:0;{SERIF};font-size:110px;font-weight:700;color:#1c1917;opacity:0.05;line-height:1\'>{n:02d}</div>' if num else ''
    return (f'<section class="section-wrap" style="margin-bottom:52px;position:relative"><div class="section-header" style="position:relative;margin-bottom:20px;padding-bottom:14px;border-bottom:1px solid #e4ddd4">{bg}'
     f'<div class="section-eyebrow" style=\'{MONO};font-size:13px;letter-spacing:0.12em;color:#b91c1c;text-transform:uppercase;margin-bottom:4px\'>{n:02d} /</div>'
     f'<h2 class="section-title" style=\'{SERIF};font-size:30px;font-weight:600;color:#1c1917;line-height:1.25\'>{inl(title)}</h2></div>{body}</section>')

md=open("/home/claude/repo/post.md").read()
title=md.split("\n",1)[0][2:]
parts=re.split(r'\n## ',md.split("\n",1)[1])
intro=parts[0]; secs=[(p.split("\n",1)[0],p.split("\n",1)[1]) for p in parts[1:]]
def blocks(txt):
    out=[];L=txt.strip("\n").split("\n");i=0
    while i<len(L):
        l=L[i]
        if not l.strip(): i+=1;continue
        if l.startswith("```"):
            j=i+1;b=[]
            while not L[j].startswith("```"): b.append(L[j]);j+=1
            out.append(PRE("\n".join(b)));i=j+1;continue
        if l.startswith("|"):
            rows=[]
            while i<len(L) and L[i].startswith("|"):
                if not re.match(r'^\|[-| ]+\|$',L[i]): rows.append([c.strip() for c in L[i].strip("|").split("|")])
                i+=1
            out.append(TABLE(rows));continue
        if re.match(r'^(- |\d+\. )',l):
            it=[]
            while i<len(L) and re.match(r'^(- |\d+\. )',L[i]): it.append(re.sub(r'^(- |\d+\. )','',L[i]));i+=1
            out.append(UL(it));continue
        b=[]
        while i<len(L) and L[i].strip() and not re.match(r'^(\||```|- |\d+\. )',L[i]): b.append(L[i]);i+=1
        out.append(P(" ".join(b)))
    return out

IMGS={
"Agent use cases by data schema":[
 IMG("siem-agent-v2-05-use-case-matrix.jpg","Matrix of 18 agent use cases against seven normalized schemas and six Security Copilot plugin sources",
 "Rows are agent use cases grouped by specialist family: identity, endpoint, network, cloud and audit, and cross-cutting. The blue columns are the seven normalized schemas, reached through custom Sentinel MCP tools; the navy columns are Security Copilot plugin sources. A solid dot is the main source for that agent and a ring is a context source. A lime tag marks a use case Microsoft already ships as a Security Copilot agent.",
 "Figure 5. Agent use cases mapped to normalized schemas and Security Copilot plugins")],
"Data normalization is key to hyperscaling agents":[
 IMG("siem-agent-v2-01-normalized.jpg","140 sources feed seven ASIM schemas, which 1,000 rules and 1,000 agents read",
 "Left to right: 140 raw sources grouped by the ASIM schema they map to, the seven schemas in the middle, then the two consumer fleets, 1,000 analytic rules (navy) and 1,000 agents (blue). Each source has one line into its schema, and every rule and agent reads only the schemas. The agents are grouped into four specialist types, one per schema family. Incidents from the rules start an orchestrator (one per incident), which hands work to the specialists, and everything they propose goes through the enforcer bar on the far right before it can change a system. That is the SOAR playbook split in three. Moving dots are events. Adding agents adds dots on the right and no lines on the left.",
 "Figure 1. With normalization: 140 sources, 7 schemas, 1,000 rules and 1,000 agents",
 "What works: SIEM correlation rules and agents both reading normalized data"),
 IMG("siem-agent-v2-02-not-normalized.jpg","Without the schema layer every consumer connects to every source in its schema",
 "The same 140 sources and 2,000 consumers with the schema layer removed. Every consumer now needs a line to each source in its schema; the drawing shows a sample of the 40,000. Red dots are the rules and agents that read a FortiGate field directly; the field was just renamed, so they are now broken.",
 "Figure 2. Without normalization: every rule and agent wired to every source",
 "What doesn't work: SIEM rules and agents reading every source without normalization")]}
ARCH_TITLE="Practical architecture"
ARCH=[P("In Microsoft terms the design has five layers, and the order matters. Sources are onboarded and normalized first; the rule fleet reads the normalized store directly; agents reach it only through a tool layer; an agent runtime hosts the agent types and their concurrent runs; and an enforcer stands between proposed actions and anything that changes a system. Identity and observability apply to every layer."),
 UL(["Normalized data: Microsoft Sentinel's analytics tier and data lake with ASIM parsers. This is where the 1,000 rules run.",
  "Tool layer: the Sentinel MCP server, with custom tools built from saved KQL queries that call the ASIM functions. Agents call tools and never read raw tables.",
  "Agent runtime: Microsoft Foundry Agent Service for the fleet, which Microsoft documents as having no limit on the number of agents in a project, with rate limits applied at the model deployment. Security Copilot hosts a few agent types embedded in Defender and Entra and is billed in Security Compute Units.",
  "Actions and oversight: Logic Apps playbooks with approval steps, a protected-account watchlist and blast-radius limits, then Defender and Entra response actions.",
  "Identity and observability: an Entra Agent ID per agent group, OpenTelemetry traces to Application Insights, and agent activity written back to Sentinel as a log source."]),
 IMG("siem-agent-v2-03-architecture-security.jpg","Security architecture: sources, Sentinel with ASIM, Sentinel MCP server, Foundry agents, enforcer",
 "Left to right. Six source types feed the normalized store (the lime cylinder: Sentinel analytics tier and data lake with the seven ASIM schemas). The rule fleet reads it directly, and the dashed navy line shows incidents from rules starting agent work. Agents reach the data only through the Sentinel MCP server in the middle. Inside the agent runtime, an orchestrator routes each incident to specialist groups (identity, endpoint, network, cloud and audit), each running many concurrent copies. Proposed actions pass through the enforcer before response actions run; the bracket under the runtime marks orchestrator, specialists and enforcer as the three parts a SOAR playbook used to hold. The two bands at the bottom apply to every layer; the grey dashed line is agent activity logged back to Sentinel.",
 "Figure 3. Security architecture on Microsoft: Sentinel, ASIM, MCP, Foundry"),
 P("The healthcare version uses the same layers. The Azure Health Data Services FHIR service is the normalized store, with $convert-data turning HL7 v2 and C-CDA into FHIR resources and the MedTech service mapping device data to Observation. A FHIR MCP server using SMART Backend Services authentication is the tool layer, alongside reference servers for ICD-10 codes, the NPI Registry and CMS coverage policies. Foundry hosts the agents; Microsoft publishes a prior authorization multi-agent accelerator with four hosted agents as a Foundry template. A clinician approves any order, payer submission or record write-back."),
 IMG("siem-agent-v2-04-architecture-healthcare.jpg","Healthcare architecture: clinical systems, FHIR service, FHIR MCP server, Foundry agents, clinician review",
 "Same layout as the security diagram. Clinical systems on the left feed the FHIR service, which holds seven FHIR resource types. Decision support rules read FHIR directly; agents reach it through the FHIR MCP server. The orchestrator routes work to care-gap, clinical review, medication, and prior auth and coding specialists. Proposed actions stop at clinician review, which plays the enforcer role, and approved changes are written back through the FHIR API. FHIR service audit logs record every agent read and write.",
 "Figure 4. Healthcare architecture on Microsoft: FHIR service, MCP, Foundry")]

out=[];n=0
for t,b in secs:
    if t=="References": continue
    if t=="The visual":
        n+=1;out.append(SEC(n,ARCH_TITLE,"".join(ARCH)))
        t="The visual and the source"
    n+=1
    bl=blocks(b)
    if t in IMGS: bl=bl[:1]+IMGS[t][:1]+bl[1:2]+IMGS[t][1:]+bl[2:]
    out.append(SEC(n,t,"".join(bl)))
refs=[("Service limits for Microsoft Sentinel","https://learn.microsoft.com/en-us/azure/sentinel/sentinel-service-limits","Microsoft Learn"),
("Azure Monitor service limits","https://learn.microsoft.com/en-us/azure/azure-monitor/service-limits","Microsoft Learn"),
("Microsoft Sentinel MCP tools overview","https://learn.microsoft.com/azure/sentinel/datalake/sentinel-mcp-tools-overview","Microsoft Learn"),
("Foundry Agent Service quotas and limits","https://learn.microsoft.com/azure/foundry/agents/concepts/limits-quotas-regions","Microsoft Learn"),
("Automate prior authorization with AI agents","https://techcommunity.microsoft.com/t5/microsoft-foundry-blog/automate-prior-authorization-with-ai-agents-now-available-as-a/ba-p/4513432","Microsoft Foundry Blog"),
("Microsoft Security Copilot plugins overview","https://learn.microsoft.com/en-us/copilot/security/plugin-overview","Microsoft Learn"),
("Security Copilot agents overview","https://learn.microsoft.com/en-us/copilot/security/agents-overview","Microsoft Learn"),
("HL7 FHIR R4","https://hl7.org/fhir/R4/","HL7"),
("ONC Cures Act Final Rule","https://www.healthit.gov/topic/oncs-cures-act-final-rule","HealthIT.gov"),
("Interactive visual","https://broglock.github.io/siem-to-agent-normalization/","GitHub Pages"),
("Project repository: post and visual","https://github.com/broglock/siem-to-agent-normalization","GitHub")]
n+=1
reflist='<ul class="ref-list" style="margin:0;padding-left:22px">'+"".join(f'<li style="padding:6px 0;border-bottom:1px solid #e4ddd4;font-size:16.5px;color:#44403c"><a href="{u}" {A}>{html.escape(t)}</a><span class="ref-src" style=\'{MONO};font-size:12.5px;color:#78716c;margin-left:8px\'>{s}</span></li>' for t,u,s in refs)+'</ul>'
out.append(SEC(n,"References",reflist,num=False))
introP="".join(blocks(intro))
head=(f'<div class="intro-wrap" style="border-bottom:1px solid #e4ddd4;padding-bottom:36px;margin-bottom:44px"><h1 class="intro-title" style=\'{SERIF};font-size:38px;font-weight:700;color:#1c1917;line-height:1.25;margin-bottom:20px;letter-spacing:-0.3px\'>{inl(title)}</h1>'
 f'<div class="intro-body">{introP}</div><div class="intro-meta" style=\'{MONO};font-size:13px;color:#78716c;border-top:1px solid #e4ddd4;padding-top:16px;margin-top:8px;letter-spacing:0.05em\'>DAVID BROGGY  &middot;  2026-11-05</div></div>')
foot=f'<footer class="footer" style=\'border-top:1px solid #e4ddd4;padding:24px 0 0;margin-top:36px;text-align:center;{MONO};font-size:12.5px;color:#78716c;letter-spacing:0.06em\' align="center">FIELD NOTES  &middot;  SIMPLE-SECURITY.CA</footer>'
page=('<div class="bleed" style="width:100%"><main class="main" style="padding:8px 0 50px;background:#f5f0e8"><div class="content-wrap" style="max-width:1400px;margin:0 auto">'+head+"".join(out)+foot+'</div></main></div>')
content="<!-- wp:html -->\n"+page+"\n<!-- /wp:html -->"
open("/home/claude/wp_styled.html","w").write(content)
open("/home/claude/repo/post.html","w").write('<!DOCTYPE html><html><head><meta charset="utf-8"><title>'+html.escape(title)+'</title></head><body style="margin:0">'+page+'</body></html>')
print(len(content), [t for t,_ in secs])
