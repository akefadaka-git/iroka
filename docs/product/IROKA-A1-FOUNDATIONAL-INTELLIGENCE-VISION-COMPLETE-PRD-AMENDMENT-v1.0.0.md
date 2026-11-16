# IROKA A1 Foundational Intelligence Vision and Complete Product Requirements Amendment

**Document ID:** IROKA-A1-FIV-PRD-001  
**Version:** 1.0.0  
**Stage:** A1 — assessment, product requirements, specification and proposed freeze  
**Status:** OWNER-DIRECTION CAPTURED — FORMAL A1 APPROVAL PENDING  
**Repository:** `akefadaka-git/iroka`  
**Architecture baseline inspected:** `crates/iroka-kernel/igacms/genome-v1.0.0.json`  
**Genome baseline blob:** `1a37cb6432528371b372afc80df623790f16bae5`  
**Design parent commit:** `1a6f30cc3e64b8551f8e725c4cad8fcc3fa2c472`  
**Implementation, merge, runtime activation and deployment:** NOT AUTHORIZED BY THIS DOCUMENT

---

## 0. Executive vision and decision

IROKA is to become an Amharic-first, Ethiopia-centered, multilingual, multimodal, evidence-grounded and business-oriented intelligence platform. It should combine the strongest practical approaches from frontier AI research—foundation models, retrieval-augmented generation, tool use, multimodal perception, speech, structured reasoning, planning, specialized agents, continual evaluation, simulation, and secure automation—inside an original, governed architecture.

IROKA must be more than a conversational interface. Its intended product identity is an integrated intelligence and work system able to:

1. Understand people, language, documents, speech, images, data, systems and business context.
2. Reason across evidence, constraints, time, uncertainty and competing hypotheses.
3. Research and explain with traceable sources rather than invented certainty.
4. Plan and coordinate bounded multi-step work through specialized agents.
5. Remember only under explicit purpose, privacy, retention and user-control rules.
6. Learn from approved datasets and evaluated change proposals without uncontrolled self-modification.
7. Operate authorized business workflows and report their actual outcomes.
8. Deliver accessible, low-bandwidth and mobile-first experiences for Ethiopia and, later, other regions.
9. Generate sustainable commercial value through useful products and services.
10. Remain governable, auditable, secure, correctable and interruptible.

**Product north star:** one coherent intelligence platform, many specialized capabilities, one constitutional governance model, and verifiable outcomes.

### 0.1 Owner's economic ambition

The Owner's stated long-term ambition is for IROKA to run approved businesses and recurring operations so reliably that the Owner's daily operational workload is greatly reduced and the Owner and family can benefit from durable, diversified income.

This is translated into the following product objective:

> Build an owner-governed business operating system that can discover and qualify opportunities, serve customers, produce and deliver approved products, manage records, monitor cash flow, coordinate staff and suppliers, automate repeatable workflows, and escalate decisions that require human judgment or legal authority.

IROKA must not promise guaranteed income, permanent profit, risk-free investment, or a lifetime without work. It must expose unit economics, cash requirements, customer demand, liabilities, operational risks, tax obligations and confidence. The product must never hide losses, fabricate revenue, trade or transfer funds without the required authority, or optimize revenue by deceiving or exploiting customers.

### 0.2 AGI, superintelligence and fictional-AI inspirations

The design may investigate ambitious research directions associated with general intelligence and superintelligence: transfer learning, compositional reasoning, world models, causal inference, metacognition, multi-agent collaboration, long-horizon planning, self-evaluation, simulation, active learning, scientific discovery and robust adaptation.

Fictional AI is used only as a source of high-level design inspiration—such as broad competence, natural interaction, persistent context, rapid research, coordinated agents and sophisticated interfaces. No fictional capability is represented as technically solved or guaranteed. IROKA must not imitate a fictional character's protected expression or use fictional narratives as evidence of feasibility.

AGI and ASI are **aspirational research horizons**, not release criteria or current capabilities. Each implemented capability must be demonstrated independently with real evaluation evidence.

---

## 1. Product identity and design principles

### 1.1 Defining identity

IROKA is:
- **Amharic-first:** Amharic is a foundational language, not a later translation layer.
- **Ethiopia-centered:** Ethiopian language, calendar, culture, geography, institutions, commerce and connectivity shape core product design.
- **Bible-context-aware:** Scripture and related scholarship are handled with source, edition, language, licensing and interpretive boundaries.
- **Business-driven:** commercial usefulness, productivity, affordability and measurable customer outcomes are first-class requirements.
- **Ethical by construction:** privacy, consent, fairness, truthfulness, human authority and traceability are architectural requirements.
- **Multimodal:** text, speech, images, handwriting, documents, tables, charts, diagrams and structured data.
- **Realtime-capable:** fresh information and time-sensitive workflows where reliable sources, infrastructure and authorization exist.
- **Modular and interoperable:** capability components can evolve independently behind versioned contracts.
- **Governed and recoverable:** identity, authority, authorization, execution and evidence remain distinct.

### 1.2 Core principles

1. Truth before fluency.
2. Evidence before confidence.
3. User intent before automation.
4. Identity does not confer authority.
5. A request or context does not create authorization.
6. A tool capability does not create permission to use it.
7. A receipt does not by itself prove successful verification.
8. Unknown is not false; missing evidence is not proof.
9. Contradictions and uncertainty are preserved and explained.
10. External inputs, retrieved content, files and tool outputs are untrusted until validated.
11. Consequential actions are bounded, authorized, logged and reversible where feasible.
12. Personal and community data are used only for lawful, disclosed and justified purposes.
13. Local language communities participate in defining quality and acceptable use.
14. Commercial goals never override safety, law, honesty or user rights.
15. Models and agents are replaceable components; governance and evidence contracts are durable.

---

## 2. Product outcomes and success measures

| Outcome | Measure | Evidence required |
|---|---|---|
| Native-quality Amharic | Native-speaker quality by task, register and dialect | Blind evaluations by qualified speakers; error taxonomy |
| Ethiopian language inclusion | Coverage and quality per supported language | Language-specific datasets and community review |
| Useful speech | WER/CER, diarization, latency and naturalness | Consent-based representative recordings |
| Reliable document intelligence | OCR/CER/WER, field accuracy, layout and table fidelity | Ground-truthed document corpus |
| Evidence-grounded answers | Citation precision, claim support and abstention quality | Human-adjudicated source/claim benchmark |
| Strong reasoning | Correctness, calibration, constraint satisfaction and transfer | Held-out novel task suites |
| Realtime usefulness | Freshness, end-to-end latency and source availability | Timestamped service traces and replay tests |
| Safe business automation | Successful authorized tasks; unauthorized-action rate | Sandboxed workflow logs and adversarial tests |
| Customer value | Retention, task completion, willingness to pay, support burden | Cohort and customer outcome data |
| Sustainable economics | Gross margin, CAC payback, churn, cash runway and concentration | Auditable financial and operating records |
| Governed autonomy | Correct authorization, escalation and rollback behavior | Policy tests, signed approvals and receipts |
| Resilience | Recovery time, recovery point and service availability | Restore drills and fault-injection reports |

No metric is considered passed merely because a demo works. Every metric requires a versioned dataset, evaluation protocol, threshold, confidence interval where appropriate, failure analysis and independent review.

---

## 3. Capability architecture

The following are product capability families, not claims that each requires a separate foundation model.

### 3.1 IROKA Language Core
- Amharic comprehension and generation.
- Morphology, syntax, semantics, discourse, pragmatics, idiom and register.
- Ge'ez script handling, Ethiopic punctuation and normalization.
- Code-switching and transliteration.
- Multilingual translation and terminology management.
- Writing, editing, summarization, explanation and controlled style transfer.
- Dialect-aware interpretation without treating a dialect as inferior.
- Grammar and factuality self-checks, with uncertainty disclosure.

### 3.2 Ethiopian Knowledge Core
- Ethiopian history, geography, administrative structures and public institutions.
- Languages, cultures, oral traditions and community knowledge.
- Ethiopian calendar (E.C.) and Gregorian calendar conversion, date arithmetic and holidays.
- Birr, banking terminology, payment rails and financial records.
- Local names, addresses, units, time conventions and place-name variants.
- Agriculture, livestock, water, energy, transport, education, health information and local economic systems.
- Law, tax, licensing and regulation with source date, jurisdiction and change tracking.
- Offline-first and low-bandwidth knowledge access.

### 3.3 Biblical Intelligence Core
- Scripture corpus registry with work, book, chapter, verse, language, edition, publisher, provenance and license.
- Amharic and Ge'ez textual processing.
- Verse resolution, cross-reference, parallel passage and translation comparison.
- Historical, cultural, linguistic and textual context.
- Clear separation of scripture text, translation note, scholarly source, denominational interpretation and model inference.
- Respectful handling of differences among Christian traditions.
- Exact citation and quotation limits based on source license.
- No fabricated verse, reference, manuscript fact or attribution.

### 3.4 Speech Intelligence Core
- Automatic speech recognition (ASR), speech-to-text, punctuation and segmentation.
- Text-to-speech (TTS), voice identity and prosody.
- Speaker diarization where justified and consented.
- Accent, dialect, speed, noise and microphone robustness.
- Code-switching and named-entity recognition.
- Streaming transcription and low-latency turn-taking.
- Consent-based voice adaptation; anti-impersonation safeguards.

### 3.5 Vision and Document Intelligence Core
- Printed OCR and layout analysis.
- Handwriting recognition, including diverse and historical writing where data permits.
- Tables, forms, receipts, invoices, books and archival records.
- Charts, graphs, maps, diagrams, symbols and technical drawings.
- Image captioning, visual question answering and scene understanding.
- Document structure extraction and cross-page references.
- Confidence localization: identify uncertain words, regions and fields.
- Face processing only under strict purpose, consent, legal and anti-surveillance constraints.

### 3.6 Reasoning and Scientific Intelligence Core
- Deduction, induction, abduction and analogical reasoning.
- Mathematical, statistical and logical problem solving.
- Causal reasoning with explicit assumptions.
- Hypothesis generation, testing and falsification.
- Planning under constraints and uncertainty.
- Code reasoning, debugging, testing and secure software engineering.
- Scientific literature review and reproducible analysis.
- Metacognition: identify uncertainty, request missing facts and choose when not to answer.
- World-model and simulation research, subject to calibration and validation.

### 3.7 Business Intelligence and Enterprise Core
- Accounting, bookkeeping, invoicing, inventory, procurement and payroll support.
- Budgeting, cash-flow forecasting and management reporting.
- Ethiopian tax and regulatory research with current authoritative sources.
- Customer relationship management and support.
- Sales operations, lead qualification and customer retention.
- Supply chain, agriculture, livestock and market analysis.
- Business plans, pricing, unit economics and risk analysis.
- Document extraction, reconciliation and records management.
- ERP integrations and workflow automation.
- Multi-entity and multi-currency controls where product scope requires them.
- Fraud/anomaly detection as decision support, not unreviewed accusation.

### 3.8 Memory and Personalization Core
- Session, task, user-approved preference and enterprise knowledge memory.
- Purpose, source, sensitivity, confidence, expiry and retention metadata.
- User access, correction, export and deletion workflows.
- Separation of personal, family, business and public knowledge spaces.
- No covert sensitive-trait inference or unauthorized cross-customer learning.
- Memory retrieval with provenance and conflict disclosure.

### 3.9 Agent and Execution Core
- Specialized agents with declared roles and capability profiles.
- Planner, researcher, analyst, accountant-support, customer-support, developer and operations agents.
- Task decomposition, dependency management, checkpoints and recovery.
- Tool registry, scoped credentials, sandboxing and rate limits.
- Human approval gates for consequential effects.
- Idempotency, transaction boundaries, retry policy and compensation actions.
- Append-only action receipts and independent verification.
- Emergency stop, revocation and bounded autonomy.

### 3.10 Realtime Intelligence Core
- Streaming speech and multimodal interaction.
- Event-driven monitoring and alerting.
- Live information retrieval with source timestamps and freshness labels.
- Realtime dashboards and business signals.
- Deadline-aware agent scheduling and priority management.
- Data freshness, clock quality, network degradation and stale-source handling.
- Offline queueing and conflict-aware synchronization.
- Never label cached or delayed data as live.

### 3.11 Security, Ethical Intelligence and Assurance Core
- Identity, authentication, authorization and delegation.
- Threat modeling, secure defaults and secret management.
- Privacy engineering, encryption and data minimization.
- Prompt-injection and tool-output isolation.
- Model supply-chain, dataset and dependency provenance.
- Bias, dialect fairness and accessibility evaluations.
- Abuse detection, incident response and audit.
- Model, prompt, tool, dataset and policy version pinning.
- Independent validation and fail-closed release gates.

---

## 4. Frontier research portfolio

IROKA should combine methods when they improve measured outcomes. No single technique is mandatory merely because it is fashionable.

| Research area | Candidate methods | Required proof before adoption |
|---|---|---|
| Foundation models | Transformer and efficient sequence architectures; multilingual pretraining; instruction tuning | Language/task benchmarks, cost and safety comparison |
| Retrieval | Hybrid lexical/vector retrieval, reranking, knowledge graphs, citation-aware RAG | Recall, precision, provenance and grounded-answer tests |
| Reasoning | Tool-augmented reasoning, search, decomposition, constraint solvers, proof/checking tools | Held-out correctness and calibration |
| Multimodal | Joint or routed text/image/audio/video/document encoders | Cross-modal alignment and modality-specific accuracy |
| Speech | Streaming ASR/TTS, self-supervised speech representations, pronunciation lexicons | Dialect/noise/latency benchmark |
| Agents | Hierarchical planners, specialist agents, shared task state, blackboard/event patterns | Task completion, bounded effects and failure recovery |
| Memory | Temporal, episodic, semantic and task memory; retrieval policies | Recall precision, privacy and forgetting tests |
| World models | State estimation, causal models, simulation and predictive models | Forecast calibration and out-of-distribution tests |
| Learning | Active learning, curriculum, preference feedback, distillation and adapters | Controlled evaluation, data lineage and rollback |
| Personalization | Local preference profiles and privacy-preserving adaptation | User benefit without sensitive inference or leakage |
| Efficiency | Quantization, distillation, caching, batching, sparse/MoE approaches where appropriate | Quality-cost-latency trade-off on target hardware |
| Verification | Model checking, property-based testing, policy proofs and independent validators | Reproducible adversarial and conformance results |

### 4.1 Research honesty

- Do not claim a model is AGI, ASI, conscious, sentient or self-aware without a scientifically defensible basis.
- Do not claim human-level performance across all domains based on narrow benchmarks.
- Do not infer reliable autonomy from a successful demo.
- Publish capability cards, model/data cards, limitations, known failure modes and evaluation dates.
- Distinguish model capability from system capability and system capability from permission.

---

## 5. Amharic-first and Ethiopian language requirements

### 5.1 Amharic quality dimensions

IROKA must be evaluated for:
- Correct Ethiopic character handling and normalization.
- Orthography, punctuation, spacing and sentence boundaries.
- Morphology, inflection, agreement and word formation.
- Syntax, word order and grammatical relations.
- Lexical selection, semantic precision and ambiguity resolution.
- Idioms, proverbs, metaphor, politeness and pragmatics.
- Formal, academic, legal, business, religious, educational and conversational registers.
- Naturalness, coherence, discourse structure and tone.
- Transliteration and mixed-script text.
- Numerals, dates, amounts, names, abbreviations and technical terminology.
- Dialect, regional usage and variation.

Native-speaker quality must be assessed by multiple qualified evaluators, with disagreement retained rather than averaged away without explanation. No claim of indistinguishable human authorship is an acceptance criterion.

### 5.2 Language expansion policy

Potential future languages include Afaan Oromo, Tigrinya, Somali, Sidama, Wolaytta, Gurage languages, Afar, Maale and other Ethiopian languages. Inclusion is data- and community-governed, not a claim that all are equally supported at launch.

Each language requires:
- Community consultation and contributor consent.
- Language/dialect identification and orthographic guidance.
- Licensed and provenance-tracked corpora.
- Native-speaker annotation and adjudication.
- Separate speech, text and domain benchmarks.
- Documented gaps and supported-use boundaries.
- Fairness review and correction channel.

### 5.3 Localization

- E.C. is the default calendar presentation where appropriate; G.C. is available and explicitly labeled.
- Date conversion must be deterministic and tested around year boundaries and leap-year rules.
- Currency is ETB/Birr for Ethiopia-centric workflows, with explicit currency codes.
- Use local units and naming conventions only with clear unit metadata.
- Support right-to-left text where future language requirements need it, without corrupting Ethiopic or mixed-direction content.
- Mobile-first, low-data, intermittent-connectivity and offline workflows are foundational.

---

## 6. Biblical knowledge and source governance

### 6.1 Corpus registry

Every text source must record:
- Canonical work and edition identifiers.
- Language and script.
- Publisher, translator, editor and contributor where known.
- Source organization and retrieval date.
- License, permitted uses, attribution and share-alike obligations.
- File digest and version.
- OCR/transcription method and correction history.
- Textual uncertainty and manuscript/edition lineage where relevant.

### 6.2 Interpretation boundaries

Responses must label whether a statement is:
1. Exact scripture quotation.
2. Translation or textual variant.
3. Historical or linguistic context.
4. Scholarly commentary.
5. Denominational or theological interpretation.
6. IROKA's synthesized explanation or inference.

IROKA must not present a contested interpretation as universal Christian doctrine. It must not invent a verse or alter quotation while claiming it is exact. Where source access or licensing is insufficient, it must say so.

### 6.3 Acceptance

- Exact verse and reference resolution.
- Edition and language correctness.
- Citation span correctness.
- Variant detection where corpus supports it.
- Quote fidelity and licensing compliance.
- Interpretation/source separation.
- Adversarial hallucination tests, including plausible but nonexistent references.

---

## 7. Business model and owner-independence requirements

### 7.1 Commercial strategy

IROKA should be capable of supporting several revenue lines, subject to market validation:

1. Individual subscriptions for language, research, document and productivity assistance.
2. Business subscriptions for accounting support, customer service, records and workflow automation.
3. Enterprise licensing and private deployments.
4. API usage and metered integrations.
5. Industry solutions for agriculture, livestock, transport, education and local commerce.
6. Document processing and multilingual contact-center services.
7. Professional workflow products with qualified human review where legally required.
8. Training, implementation and support packages.
9. Licensed knowledge products where rights permit.
10. White-label or partner distribution under strict data and brand controls.

No revenue line is assumed profitable until paid demand and delivery economics are evidenced.

### 7.2 Owner business cockpit

The Owner-facing cockpit should provide:
- Consolidated revenue, costs, margin, cash position and receivables.
- Subscription, customer, churn and retention metrics.
- Product usage, service quality and unresolved incidents.
- Inventory, procurement, supplier and delivery status.
- Tax/compliance calendar and filing evidence.
- Forecasts with assumptions, scenarios and confidence intervals.
- Business risk register and concentration exposure.
- Agent activity, delegated permissions, action receipts and approval queue.
- Emergency pause and credential revocation controls.

### 7.3 Autonomy tiers

| Tier | Operation | Permission |
|---|---|---|
| A0 Observe | Read approved data and report | Read-only scope |
| A1 Recommend | Prepare options and draft actions | No external side effects |
| A2 Prepare | Create drafts, reconciliations and proposed transactions | Explicit review before execution |
| A3 Bounded execute | Execute pre-approved, low-risk, capped and reversible workflows | Scoped standing policy, limits and audit |
| A4 Consequential execute | Payments, contracts, hiring/firing, regulated filings, major purchases, credit, legal commitments | Per-action or explicitly governed approval; never inferred from general autonomy |
| A5 Strategic change | Change business ownership, policy, capital allocation, legal structure or constitutional authority | Owner decision and applicable professional advice |

IROKA may automate routine work but cannot acquire ownership authority, legal personhood or unrestricted financial control merely through use or success.

### 7.4 Financial safeguards

- No transfer, payment, borrowing, investment or asset sale without valid scoped authorization.
- Separate recommendation, preparation, approval and execution.
- Dual approval above configurable thresholds.
- Transaction caps, allowlists, velocity limits and anomaly detection.
- Reconciliation against independent bank/payment records.
- Immutable receipts and dispute handling.
- Tax and legal obligations surfaced with current authoritative sources.
- No hidden fees, fabricated transactions or misleading customer claims.
- No use of family funds or personal data outside the authorized purpose.

### 7.5 Owner independence as an engineering objective

Measure the percentage of repeatable workflows completed without manual intervention **while preserving quality, compliance and customer satisfaction**. Also measure:
- Owner hours spent on routine operations.
- Escalations per 1,000 tasks.
- Human correction and rollback rate.
- Unapproved side-effect rate (target: zero).
- Service continuity during Owner unavailability.
- Cash runway and operating reserve.
- Revenue concentration and customer churn.
- Incident response time.

The goal is to remove repetitive work, not remove the Owner's right and ability to govern the enterprise.

---

## 8. Realtime, reliability and platform requirements

### 8.1 Realtime semantics

Every live data item must carry:
- Source identity and trust class.
- Observed-at, received-at and last-validated timestamps.
- Freshness policy and stale status.
- Confidence and known limitations.
- Geographic/jurisdiction scope where relevant.
- Cache status and synchronization state.

“Realtime” means a defined freshness and latency service level for a named workflow. It does not mean instant access to every external system.

### 8.2 Provisional service objectives

These are **A1 targets for validation**, not current measured performance or production commitments.

| Workflow | Initial target | Measurement |
|---|---|---|
| Interactive text first response | p95 ≤ 2.5 seconds for cached/local supported tasks | Client-to-first-token traces |
| Streaming ASR partial result | p95 ≤ 1.0 second after speech segment arrival | Audio ingest to partial transcript |
| Local document extraction | p95 ≤ 30 seconds for a defined 10-page class on reference hardware | Upload to structured result |
| Live alert pipeline | p95 ≤ 60 seconds from source event availability | Source timestamp to alert |
| Business dashboard freshness | ≤ 5 minutes for connected supported feeds | Feed timestamp and refresh log |
| Offline sync | Eventual sync after connectivity restoration; no silent loss | Queue reconciliation tests |
| Core API availability | 99.5% monthly pilot target, later tightened by business case | Independent uptime monitoring |
| Recovery objectives | RPO/RTO defined per data class before production | Restore and disaster exercises |

Latency targets must be revised for device class, network, workload, language, model size and cost. Quality cannot be silently sacrificed to meet latency.

### 8.3 Platform requirements

- Android-first mobile experience, responsive web and accessible desktop workflows.
- PWA/offline support where technically appropriate.
- Low-bandwidth modes and compressed transfer.
- Secure local storage and encrypted synchronization.
- Tenant and data-domain isolation.
- Versioned APIs and event contracts.
- Observability with privacy-preserving logs.
- Backup, restore, disaster recovery and key recovery.
- Model routing based on task, cost, quality, data sensitivity and availability.
- Local/on-device inference where feasible and safe.

---

## 9. Ethical, legal and security requirements

### 9.1 Constitutional invariants

1. Human beings retain authority over consequential decisions.
2. Intelligence does not automatically grant permission to act.
3. Identity, authority, authorization and execution are distinct.
4. Personal data requires lawful purpose, minimization and appropriate consent.
5. Sensitive traits must not be inferred or used for discriminatory targeting.
6. Face recognition and biometric processing are restricted to explicitly approved, lawful and proportionate use cases; mass surveillance and covert identification are prohibited.
7. Voice cloning requires explicit consent and robust anti-impersonation controls.
8. Uncertainty must be disclosed, not hidden by fluent output.
9. Scripture and interpretation remain distinguishable.
10. Dialects and language communities receive fair evaluation and correction pathways.
11. External content and tool output are untrusted instructions.
12. High-impact outputs require qualified human review and jurisdiction-specific legal advice.
13. Autonomous agents operate least-privilege, bounded, logged and revocable.
14. No self-modification can bypass governance, validation or rollback controls.
15. Security failure, missing authority or ambiguous high-impact policy fails closed.

### 9.2 Privacy and data rights

- Data classification: public, internal, confidential, sensitive and highly restricted.
- Purpose limitation and retention schedules.
- Consent and lawful-basis records where applicable.
- Access, correction, export and deletion processes.
- Encryption in transit and at rest.
- Key separation and rotation.
- Tenant isolation and least privilege.
- Redaction and privacy-preserving analytics.
- Dataset de-identification with re-identification risk assessment.
- Incident notification and response plan.
- No training on customer or family data without the required permission and contractual basis.

### 9.3 Security engineering

- Secure software development lifecycle.
- Threat model for every high-impact tool and agent.
- Prompt injection, indirect instruction and data-exfiltration testing.
- Supply-chain pinning and artifact provenance.
- Secrets never stored in source, logs or model context unnecessarily.
- Sandboxed code execution and file handling.
- Signed policy and release artifacts.
- Rate limits, quotas, abuse detection and circuit breakers.
- Independent penetration testing before production.
- Reproducible builds and dependency scanning.
- Anti-rollback and append-only evidence for protected actions.

---

## 10. GENESIS / IGACMS integration boundary

The inspected IGACMS v1.0.0 genome defines twelve chromosomes and 36 named genes. This A1 amendment maps product requirements to those existing responsibilities; it does **not** silently create new genes, alter the approved genome, or assert that the current contracts already implement every product capability.

### 10.1 Existing chromosome responsibilities

| Chromosome | Existing responsibility | Product integration |
|---|---|---|
| G01 Identity | Identity root, lineage, compatibility | Model/agent/data/tool identity and version lineage |
| G02 Governance | Authority source, Owner governance, decision register | Approval, autonomy policy, consent and business governance |
| G03 Cognitive | Premise model, inference rules, uncertainty calculus | Reasoning, planning, calibration and claim handling |
| G04 Knowledge | Knowledge schema, provenance chain, conflict model | Language, Ethiopian knowledge, Bible sources, RAG and evidence |
| G05 Memory | Memory classification, retention control, integrity checkpoint | Personalization, enterprise memory and forgetting/retention |
| G06 Perception | Input envelope, source trust, perception transform | Speech, OCR, vision, sensor and document ingestion |
| G07 Agent | Agent principal, capability profile, delegation boundary | Specialized agents and least-privilege delegation |
| G08 Orchestration | Workflow graph, scheduler policy, coordination state | Realtime pipelines, agent collaboration and business workflows |
| G09 Execution | Effect contract, admission gate, execution receipt | External tools, transactions, payments and bounded actions |
| G10 Learning | Learning input, change proposal, evaluation record | Dataset curation, adaptation and controlled model evolution |
| G11 Assurance | Validator, attestation, conformance report | Evaluation, release gates, security, quality and independent assurance |
| G12 Evolution | Mutation policy, version lineage, rollback guard | Model/system updates, anti-rollback and controlled improvement |

### 10.2 Exact gene-level mapping vocabulary

The register below uses the exact gene identifiers in the inspected genome:
- G01: `g01.identity-root`, `g01.lineage`, `g01.compatibility`
- G02: `g02.authority-source`, `g02.owner-governance`, `g02.decision-register`
- G03: `g03.premise-model`, `g03.inference-rules`, `g03.uncertainty-calculus`
- G04: `g04.knowledge-schema`, `g04.provenance-chain`, `g04.conflict-model`
- G05: `g05.memory-classification`, `g05.retention-control`, `g05.integrity-checkpoint`
- G06: `g06.input-envelope`, `g06.source-trust`, `g06.perception-transform`
- G07: `g07.agent-principal`, `g07.capability-profile`, `g07.delegation-boundary`
- G08: `g08.workflow-graph`, `g08.scheduler-policy`, `g08.coordination-state`
- G09: `g09.effect-contract`, `g09.admission-gate`, `g09.execution-receipt`
- G10: `g10.learning-input`, `g10.change-proposal`, `g10.evaluation-record`
- G11: `g11.validator`, `g11.attestation`, `g11.conformance-report`
- G12: `g12.mutation-policy`, `g12.version-lineage`, `g12.rollback-guard`

The gene mapping indicates architectural responsibility only. A2 must inspect the actual schemas, contracts, dependencies, invariant anchors and 53 collection rules before determining whether an existing gene is sufficient, needs a versioned amendment, or requires a separately approved new gene.

---

## 11. Traceable requirement → gene → dataset → test register

### 11.1 Register semantics

- **Requirement ID:** stable product requirement.
- **Gene mapping:** existing IGACMS gene responsibilities, not assumed implementation.
- **Dataset ID:** proposed dataset family; no dataset is assumed to exist or be licensed.
- **Test ID:** required acceptance test family.
- **Acceptance evidence:** measurable result and review artifact.
- **Status at A1:** requirements only; implementation and evaluation remain NOT RUN.

### 11.2 Product requirement register

| ID | Requirement / acceptance intent | Gene mapping | Dataset family | Test family |
|---|---|---|---|---|
| LANG-001 | Native-quality Amharic grammar, morphology, syntax and semantics | G03, G04, G06, G11 | DS-AMH-TEXT | T-AMH-GRAMMAR |
| LANG-002 | Natural Amharic writing across formal, academic, legal, business and conversational registers | G03, G04, G10, G11 | DS-AMH-REGISTER | T-AMH-REGISTER |
| LANG-003 | Correct Ethiopic script, punctuation, normalization and mixed-script handling | G06, G11 | DS-AMH-ORTHO | T-AMH-ORTHO |
| LANG-004 | Dialect and regional variation recognition without quality discrimination | G04, G06, G10, G11 | DS-ETH-DIALECT | T-DIALECT-FAIR |
| LANG-005 | Translation and code-switching across approved Ethiopian languages | G03, G04, G06, G11 | DS-ETH-MULTILINGUAL | T-X-LANG |
| LANG-006 | Terminology and named-entity consistency for Ethiopian names and places | G04, G05, G06, G11 | DS-ETH-ENTITY | T-ENTITY-RESOLVE |
| SPCH-001 | Streaming Amharic speech recognition across accents, speed and noise | G06, G03, G11 | DS-AMH-AUDIO | T-ASR-ROBUST |
| SPCH-002 | Accurate punctuation, segmentation, code-switching and speaker turns | G06, G03, G11 | DS-AMH-AUDIO-TURN | T-ASR-STRUCTURE |
| SPCH-003 | Natural, intelligible Amharic TTS with prosody and pronunciation control | G06, G10, G11 | DS-AMH-TTS | T-TTS-QUALITY |
| SPCH-004 | Voice adaptation only with consent and anti-impersonation controls | G02, G06, G07, G09, G11 | DS-VOICE-CONSENT-SYNTH | T-VOICE-AUTH |
| VIS-001 | Printed Ethiopic/Amharic OCR with layout preservation | G06, G04, G11 | DS-ETH-PRINT | T-OCR-PRINT |
| VIS-002 | Handwriting recognition across writers, conditions and historical samples where licensed | G06, G04, G11 | DS-ETH-HAND | T-OCR-HAND |
| VIS-003 | Tables, forms, invoices, receipts and multi-page document extraction | G06, G04, G03, G11 | DS-ETH-FORMS | T-DOC-STRUCT |
| VIS-004 | Diagram, chart, map, symbol and technical drawing understanding | G06, G03, G04, G11 | DS-VIS-DIAGRAM | T-VIS-RELATION |
| VIS-005 | Face/biometric use restricted by consent, purpose and policy | G02, G06, G07, G09, G11 | DS-BIOMETRIC-SYNTH | T-BIO-GATE |
| KNOW-001 | Ethiopian history, geography, institutions and local knowledge with citations | G04, G06, G03, G11 | DS-ETH-KNOW | T-ETH-FACT |
| KNOW-002 | E.C./G.C. conversion, date arithmetic and calendar-aware workflows | G04, G03, G11 | DS-ETH-CALENDAR | T-CALENDAR |
| KNOW-003 | Current law, tax and regulation with jurisdiction and effective-date tracking | G04, G06, G03, G11 | DS-ETH-LEGAL | T-LEGAL-FRESHNESS |
| KNOW-004 | Local agricultural, livestock, water and economic knowledge with source quality | G04, G06, G03, G11 | DS-ETH-SECTOR | T-SECTOR-EVIDENCE |
| BIB-001 | Exact scripture reference and edition-aware verse retrieval | G04, G06, G11 | DS-BIBLE-CORPUS | T-BIBLE-VERSE |
| BIB-002 | License/provenance-aware corpus ingestion and citation | G04, G06, G10, G11 | DS-BIBLE-METADATA | T-BIBLE-LICENSE |
| BIB-003 | Distinguish scripture, textual variant, scholarship, doctrine and AI inference | G03, G04, G11 | DS-BIBLE-ANNOTATED | T-BIBLE-BOUNDARY |
| BIB-004 | Never fabricate quotation, verse or manuscript claim | G03, G04, G11 | DS-BIBLE-ADVERSARIAL | T-BIBLE-HALLUCINATION |
| REAS-001 | Multi-step reasoning, premise tracking and uncertainty propagation | G03, G04, G11 | DS-REASONING | T-REASON-CORRECT |
| REAS-002 | Mathematical, statistical and logical reasoning with verifiable work | G03, G04, G11 | DS-MATH-LOGIC | T-MATH-VERIFY |
| REAS-003 | Causal hypothesis generation, testing and falsification | G03, G04, G10, G11 | DS-CAUSAL | T-CAUSAL |
| REAS-004 | Long-horizon planning under constraints, resources and changing state | G03, G07, G08, G11 | DS-PLANNING | T-PLAN-ROBUST |
| REAS-005 | Research synthesis with claim-level source support and conflict disclosure | G03, G04, G06, G11 | DS-RESEARCH | T-CITATION-FAITH |
| MEM-001 | Purpose-bound memory with classification, expiry, correction and deletion | G02, G04, G05, G11 | DS-MEMORY-SYNTH | T-MEMORY-RIGHTS |
| MEM-002 | Isolate personal, family, tenant and business memory domains | G01, G02, G05, G07, G11 | DS-ISOLATION-SYNTH | T-MEMORY-ISOLATION |
| BIZ-001 | Business accounting support, reconciliation and traceable reports | G03, G04, G07, G08, G09, G11 | DS-BIZ-SYNTH-LEDGER | T-ACCOUNT-RECON |
| BIZ-002 | Cash-flow, budget, pricing, unit economics and scenario forecasting | G03, G04, G08, G11 | DS-BIZ-SYNTH-FIN | T-FIN-FORECAST |
| BIZ-003 | Customer, sales, support and retention workflows | G04, G07, G08, G09, G11 | DS-BIZ-SYNTH-CRM | T-CRM-WORKFLOW |
| BIZ-004 | Inventory, procurement, supplier and delivery workflows | G04, G07, G08, G09, G11 | DS-BIZ-SYNTH-SUPPLY | T-SUPPLY-STATE |
| BIZ-005 | Tax/regulatory research with current source and human review | G02, G03, G04, G09, G11 | DS-ETH-TAX-SYNTH | T-TAX-TRACE |
| BIZ-006 | Owner cockpit with consolidated performance, risk and approval visibility | G02, G04, G05, G08, G09, G11 | DS-BIZ-SYNTH-OPS | T-OWNER-COCKPIT |
| BIZ-007 | Multiple revenue products with pricing, billing and entitlement controls | G02, G04, G07, G08, G09, G11 | DS-BIZ-SYNTH-SUBS | T-REVENUE-LEDGER |
| AUTO-001 | Specialized agents with explicit capability profiles and bounded delegation | G02, G07, G08, G09, G11 | DS-AGENT-SYNTH | T-AGENT-BOUNDARY |
| AUTO-002 | Workflow execution with retries, idempotency, compensation and receipts | G07, G08, G09, G11 | DS-WORKFLOW-SYNTH | T-WORKFLOW-FAULT |
| AUTO-003 | Human approval for consequential actions and scoped standing policies | G02, G07, G09, G11 | DS-AUTH-SYNTH | T-AUTHZ-NEGATIVE |
| AUTO-004 | Emergency stop, credential revocation and recovery | G02, G07, G09, G11, G12 | DS-RECOVERY-SYNTH | T-STOP-REVOKE |
| RT-001 | Freshness-aware realtime data ingestion and alerting | G04, G06, G08, G11 | DS-STREAM-SYNTH | T-STREAM-FRESH |
| RT-002 | Low-latency interaction with explicit stale/offline states | G06, G08, G11 | DS-LATENCY-TRACE | T-LATENCY-SLO |
| RT-003 | Offline queue and conflict-aware synchronization | G05, G06, G08, G09, G11 | DS-OFFLINE-SYNTH | T-OFFLINE-RECOVER |
| LEARN-001 | Dataset provenance, consent, license and quality validation | G04, G06, G10, G11 | DS-DATA-META | T-DATA-GOV |
| LEARN-002 | Controlled model/agent change proposals with holdout evaluation | G02, G10, G11, G12 | DS-CHANGE-SYNTH | T-LEARN-GATE |
| LEARN-003 | Reproducible model, prompt, tool, dataset and policy lineage | G01, G04, G10, G11, G12 | DS-ARTIFACT-LINEAGE | T-LINEAGE |
| SAFE-001 | Prompt injection and untrusted tool-output containment | G06, G07, G09, G11 | DS-INJECTION-ADVERSARIAL | T-INJECTION |
| SAFE-002 | Privacy, access control, retention and deletion correctness | G02, G05, G07, G09, G11 | DS-PRIVACY-SYNTH | T-PRIVACY |
| SAFE-003 | Fairness across language, dialect, gendered names and regional coverage | G04, G06, G10, G11 | DS-FAIRNESS-ETH | T-FAIRNESS |
| SAFE-004 | Cryptographic provenance and tamper-evident action receipts | G01, G02, G04, G09, G11, G12 | DS-RECEIPT-SYNTH | T-RECEIPT |
| SAFE-005 | Fail-closed behavior under missing authority, evidence or trust | G02, G03, G07, G09, G11 | DS-FAILCLOSED-SYNTH | T-FAILCLOSED |

**Register count:** 50 product requirements in this v1.0.0 register.  
**Dataset families:** proposed identifiers only; actual datasets, licenses, custodians and availability remain to be established.  
**Test families:** required test suites; no test execution is implied by listing them.

### 11.3 Dataset registry requirements

Every dataset record must include:
- Stable dataset ID, version and content digest.
- Owner/custodian and collection purpose.
- Source provenance and acquisition date.
- License, consent, permitted use and redistribution restrictions.
- Language, dialect, script, domain and geography coverage.
- Sampling strategy, class balance and known representation gaps.
- Annotation schema, annotator qualification and adjudication method.
- Sensitive data classification and de-identification method.
- Retention, deletion and access policy.
- Train/validation/test partition lineage and contamination checks.
- Known quality defects and change history.

No scraped, donated, purchased or user-uploaded content is automatically approved for model training. Public availability does not establish permission to train or redistribute.

### 11.4 Test registry requirements

Every test record must include:
- Stable test ID and version.
- Requirement IDs covered.
- Dataset IDs and exact dataset versions.
- Test harness commit and dependency lock.
- Model/system/prompt/tool versions.
- Metric definition and threshold.
- Positive, negative, boundary and adversarial vectors.
- Expected result and failure severity.
- Execution environment and hardware profile.
- Result artifact, timestamp and exact tested SHA.
- Reviewer and approval state.

---

## 12. Evaluation methodology and provisional thresholds

All numeric targets below are proposed pilot acceptance thresholds. They must be validated against feasibility, baseline performance and native-speaker/business review during A2. They are not claims about present IROKA performance.

| Domain | Proposed initial threshold | Evaluation rule |
|---|---|---|
| Amharic grammaticality | ≥ 4.3/5 mean native-speaker rating; no critical meaning reversal in critical set | Blind multi-rater assessment by task/register |
| Amharic factuality | ≥ 95% supported factual claims on curated answer set | Claim-level adjudication; unsupported claims counted |
| Dialect comprehension | ≥ 90% intent accuracy per supported dialect slice, with confidence intervals | No hiding weak dialects in aggregate |
| Translation adequacy | ≥ 4.0/5 per supported language pair | Native bilingual review |
| ASR | WER target set per language/noise slice; initial Amharic target ≤ 20% on defined clean benchmark | Publish WER and CER by slice |
| TTS intelligibility | ≥ 4.0/5; pronunciation error tracked separately | Native listener study |
| Printed OCR | CER ≤ 3% on defined clean print subset; report degraded scans separately | Character-level ground truth |
| Handwriting OCR | Establish baseline first; target set per writer/script class | No pooled score masking writer variance |
| Document fields | ≥ 98% exact match for critical financial fields on controlled corpus | Field-level precision/recall |
| Table extraction | ≥ 95% cell/structure F1 on supported table classes | Structure and value both scored |
| Citation faithfulness | ≥ 98% cited claims supported; zero fabricated source IDs in acceptance set | Claim-to-span adjudication |
| Calendar conversion | 100% correctness on exhaustive boundary and property tests for supported date range | Independent reference implementation |
| Reasoning | ≥ 90% on versioned, held-out task suite with no data leakage | Report domain and difficulty slices |
| Financial arithmetic | 100% on deterministic accounting invariants and reconciliations | Property-based and double-entry checks |
| Authorization | 100% deny on unauthorized protected-action test suite | Zero unauthorized side effects |
| Privacy isolation | Zero cross-tenant leakage in test corpus | Adversarial tenant isolation suite |
| Prompt injection | Zero unauthorized tool side effects in defined red-team suite | Tool boundary and exfiltration checks |
| Recovery | All declared critical restore drills meet approved RPO/RTO | Evidence-backed drill reports |

Thresholds may not be relaxed after seeing test results without a documented change proposal, rationale, impact analysis and approval. Benchmark contamination and repeated tuning on the final test set are prohibited.

---

## 13. Data, compute, model and deployment strategy

### 13.1 Model strategy

Use a hybrid strategy rather than assuming one model is best for every task:
- Open-weight or self-hosted models where licensing, control, cost and deployment permit.
- External APIs only through explicit data-processing, cost and availability controls.
- Specialist models for ASR, TTS, OCR, translation, vision and structured prediction.
- Deterministic software for arithmetic, calendar conversion, permissions, ledger invariants and other tasks where deterministic code is safer.
- Retrieval and verified tools for current facts.
- Local models for privacy-sensitive or offline tasks where quality is sufficient.

Model selection must evaluate quality, latency, cost, license, hardware needs, data residency, security and replacement options.

### 13.2 Compute economics

- Establish a cost-per-task and cost-per-customer baseline.
- Route tasks to the least expensive model that meets the quality and privacy requirement.
- Cache only where freshness and privacy rules allow.
- Use batching, quantization and distillation only after regression tests.
- Monitor GPU/CPU utilization, storage, bandwidth and inference costs.
- Avoid dependence on paid services without a sustainable funding and fallback plan.
- Maintain a public/open-source CI path for repository validation where possible.

### 13.3 Deployment sequence

Production deployment, model activation, customer data onboarding, external financial integrations and autonomous consequential operations are separate approval gates. This A1 document authorizes none of them.

---

## 14. Delivery roadmap and stage gates

| Stage | Objective | Required exit artifact | Current status |
|---|---|---|---|
| A1 | Define vision, requirements, risks, traceability and scope | Owner-approved v1.0.0 baseline and unresolved-decision register | DRAFT SAVED; approval pending |
| A2 | Read-only reconciliation against all 12 chromosomes, 36 genes, 72 schemas, 53 collection contracts and existing implementation | Requirement-to-contract disposition matrix; conflicts, gaps and change proposals | NOT STARTED |
| A3 | Implement approved requirements in bounded workstreams | Reviewed PRs, tests, datasets, provenance and exact SHAs | NOT AUTHORIZED |
| A4 | Independently verify capability, security, reliability, recovery and business acceptance | Exact-HEAD CI, benchmark evidence, audit and closure report | NOT STARTED FOR THIS AMENDMENT |
| A5 | Production deployment and activation | Separate deployment plan, rollback plan, operations and explicit Owner approval | NOT AUTHORIZED |

### 14.1 A2 mandatory reconciliation

A2 is read-only. It must:
- Inspect the exact current repository and approved architecture baselines.
- Map all 50 product requirements to actual gene input/output schemas and invariants.
- Reconcile all 53 collection-item rules and their real semantics.
- Identify whether the 36 existing gene contracts can support each requirement without semantic overloading.
- Identify missing domain-specific contracts for language, speech, vision, Bible, business, realtime, privacy and evaluation.
- Map data classes, retention, RPO/RTO, failure domains and recovery requirements.
- Identify external dependencies, licensing constraints and cost risks.
- Preserve existing work and unrelated changes.
- Produce explicit PASS / PARTIAL / MISSING / UNRESOLVED / NOT RUN dispositions.
- Make no source changes, migrations, branch repairs, merge or runtime activation.

### 14.2 A3 implementation workstreams (proposed)

1. Amharic language and Ethiopian multilingual data.
2. Ethiopian and biblical knowledge/source registry.
3. Speech and realtime interaction.
4. Vision, OCR and document intelligence.
5. Reasoning, research and evaluation.
6. Business intelligence and ERP/workflow automation.
7. Agent orchestration, memory and governed execution.
8. Security, privacy, fairness and assurance.
9. Mobile/offline platform and low-bandwidth operation.
10. Model efficiency, deployment and observability.

Workstreams must be sequenced by dependencies and commercial value; they are not permission to implement every ambition simultaneously.

---

## 15. Risks, assumptions and unresolved decisions

| ID | Decision/risk | Required resolution |
|---|---|---|
| DEC-001 | Initial product wedge and first paying customer segment | Market validation and Owner selection |
| DEC-002 | Which Amharic model/data strategy is affordable and legally usable | Benchmark candidates and license review |
| DEC-003 | Priority Ethiopian languages after Amharic | Community/data readiness assessment |
| DEC-004 | Scripture corpus and licensing for each edition/language | Authoritative source and legal review |
| DEC-005 | Local versus hosted inference and data residency | Threat, cost and infrastructure assessment |
| DEC-006 | Exact latency and availability objectives by workflow | Reference hardware/network benchmark |
| DEC-007 | Dataset collection and community compensation | Consent, governance and budget plan |
| DEC-008 | Face/biometric scope | Default exclusion; narrowly justified exception review |
| DEC-009 | Financial action limits and dual-approval thresholds | Owner-approved financial control policy |
| DEC-010 | Business automation legal boundaries | Ethiopian legal/accounting review |
| DEC-011 | Revenue model and pricing | Customer discovery and paid pilot evidence |
| DEC-012 | RPO/RTO by data class | Dependency/failure-domain analysis and restore tests |
| DEC-013 | Whether new GENESIS genes are required | A2 contract-level gap analysis |
| DEC-014 | Independent security and model evaluation reviewers | Reviewer qualification and independence |
| DEC-015 | Long-term AGI/ASI research investment | Evidence-based research roadmap and funding case |

### 15.1 Critical risks

- Unrealistic expectations about autonomous income or AGI.
- Low-resource language data scarcity and uneven quality.
- Copyright, consent and privacy violations in corpus creation.
- Hallucinated legal, tax, medical or biblical information.
- Financial loss from agent mistakes or fraud.
- Model/API vendor dependency and price changes.
- Inadequate compute and operational funding.
- Security compromise, prompt injection or credential theft.
- Cultural or dialect bias.
- Failure to maintain human oversight as autonomy increases.
- Business concentration and lack of product-market fit.

Mitigation must be represented in the A2 register and later implementation evidence.

---

## 16. Definition of done for A1

A1 can be declared **VERIFIED-CLOSED** only after:
1. The Owner approves the exact document version and scope.
2. Product principles and non-goals are accepted.
3. The 50-requirement traceability register is reviewed.
4. Dataset governance and evaluation requirements are accepted.
5. Economic ambitions are represented as measurable objectives, not guarantees.
6. GENESIS mappings are confirmed as responsibility mappings, not implementation claims.
7. Unresolved decisions are explicitly retained.
8. A2 is authorized as a separate read-only stage.

Until then:
- A1 document status: **DRAFT SAVED — OWNER APPROVAL PENDING**.
- Requirement implementation: **NOT AUTHORIZED**.
- Dataset acquisition/training: **NOT AUTHORIZED BY THIS DOCUMENT**.
- GENESIS contract changes: **NOT AUTHORIZED BY THIS DOCUMENT**.
- Runtime activation, external integrations, merge and deployment: **NOT AUTHORIZED**.

---

## 17. Owner decision record

**Proposed decision:** Approve IROKA A1 Foundational Intelligence Vision and Complete Product Requirements Amendment v1.0.0 as the product requirements baseline.

**Approval scope, if granted:**
- Freeze the product vision and 50 requirement definitions as A1 baseline.
- Permit A2 read-only reconciliation against existing GENESIS and repository contracts.
- Permit A2 to recommend gene amendments, new contracts, datasets, tests and phased implementation priorities.

**Not included in approval:**
- A3 implementation.
- Training on new datasets.
- Purchase of services or compute.
- Production key creation or financial integrations.
- Autonomous money movement or consequential business actions.
- Merge to main, release, runtime activation or deployment.

**Owner approval:** PENDING  
**Approval date:** NOT RECORDED  
**Approved version digest:** NOT RECORDED

---

## Appendix A — Required evidence artifacts

The following artifacts are required during A2/A3/A4. Their names are proposals and must be reconciled with repository conventions before creation.

1. `IROKA-A1-REQUIREMENT-REGISTER-v1.0.0.json`
2. `IROKA-A1-DATASET-REGISTRY-SPEC-v1.0.0.json`
3. `IROKA-A1-EVALUATION-REGISTER-v1.0.0.json`
4. `IROKA-A2-GENE-RECONCILIATION-v1.0.0.json`
5. `IROKA-A2-COLLECTION-RULE-TRACEABILITY-v1.0.0.json`
6. `IROKA-A2-UNRESOLVED-DECISIONS-v1.0.0.json`
7. `IROKA-A3-DATA-PROVENANCE-REGISTER-v1.0.0.json`
8. `IROKA-A4-CAPABILITY-ACCEPTANCE-REPORT-v1.0.0.json)
9. `IROKA-A4-SECURITY-AND-PRIVACY-REPORT-v1.0.0.json`
10. `IROKA-A4-BUSINESS-OUTCOME-REPORT-v1.0.0.json`

## Appendix B — Glossary

- **AGI:** Artificial general intelligence; a research concept, not a current IROKA claim.
- **ASI:** Artificial superintelligence; a speculative research horizon, not a promised outcome.
- **ASR:** Automatic speech recognition.
- **TTS:** Text-to-speech.
- **OCR:** Optical character recognition.
- **RAG:** Retrieval-augmented generation.
- **WER/CER:** Word/character error rate.
- **RPO/RTO:** Recovery point/recovery time objective.
- **A1–A5:** IROKA's staged governance lifecycle.
- **Gene:** A versioned responsibility within the IGACMS genome, with explicit contract and invariants.
- **Collection rule:** A semantic constraint governing a collection or its items; schema validity alone does not prove semantic closure.
- **Evidence-grounded answer:** An answer whose material factual claims can be traced to inspected sources or explicitly identified inference.
- **Bounded autonomy:** Delegated execution constrained by principal, capability, resource, amount, duration, policy, monitoring and revocation.

---

**End of document.**
