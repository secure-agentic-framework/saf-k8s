# EU AI Act (Regulation 2024/1689) — SAF-K8S Coverage Notes

Coverage of in-scope high-risk-obligation families (Annexes IV, VI–IX, XI; Articles 9–15, 72, 73).
Citations follow the official Formex numbering (CELEX 32024R1689).

- Official obligation-leaves mapped: 87
- Deliberate non-coverage (documented below): 99

## Coverage added by the completeness sweep

| Obligation | Control | Relation | Why |
|---|---|---|---|
| `Annex-IV.1.c` | SAF-K8S-0606-029 | partial/strong | The control requires GitOps deployment processes to preserve release metadata and version  |
| `Annex-IV.1.c` | SAF-K8S-0202-003 | partial/moderate | The control tracks container runtime versions against a supported version matrix and manda |
| `Annex-IV.1.c` | SAF-K8S-0701-008 | partial/moderate | The control versions training datasets, model checkpoints, and model artifacts so each run |
| `Annex-IV.1.c` | SAF-K8S-0104-020 | partial/weak | The control keeps clusters within the active support window, providing version-currency/up |
| `Annex-IV.2.f` | SAF-K8S-0905-015 | partial/moderate | Its statement directly addresses pre-determined changes and continuous compliance: continu |
| `Annex-IV.2.f` | SAF-K8S-1001-016 | partial/weak | Audit policies that capture training/pipeline workflow changes, model serving object chang |

## Deliberate non-coverage (out of platform scope)

These EU AI Act obligations have no SAF-K8S mapping by design — they are organizational, legal, procedural, registration/identity, or deployer-documentation duties with no Kubernetes/AI-platform technical control.

| Obligation | Text | Reason not covered |
|---|---|---|
| `Annex-IV.1.d` | the description of all the forms in which the AI system is placed on t | organizational/procedural |
| `Annex-IV.1.e` | the description of the hardware on which the AI system is intended to  | This Annex IV obligation requires the provider to author a descriptive document  |
| `Annex-IV.1.f` | where the AI system is a component of products, photographs or illustr | deployer-facing documentation artifact |
| `Annex-IV.1.g` | a basic description of the user-interface provided to the deployer; | organizational/procedural |
| `Annex-IV.1.h` | instructions for use for the deployer, and a basic description of the  | deployer-facing documentation artifact |
| `Annex-IV.4` | A description of the appropriateness of the performance metrics for th | This Annex IV obligation requires a written, analytical description in the techn |
| `Annex-IV.7` | A list of the harmonised standards applied in full or in part the refe | legal/conformity instrument |
| `Annex-IV.8` | A copy of the EU declaration of conformity referred to in Article 47; | legal/conformity instrument |
| `Annex-VI.1` | The conformity assessment procedure based on internal control is the c | This obligation is a definitional clause for the conformity assessment procedure |
| `Annex-VII.1` | Introduction | conformity-assessment application/procedure |
| `Annex-VII.2` | Overview | conformity-assessment application/procedure |
| `Annex-VII.3.1.a` | the name and address of the provider and, if the application is lodged | registration/identity field |
| `Annex-VII.3.1.b` | the list of AI systems covered under the same quality management syste | This obligation is a documentation field within the Annex VII conformity-assessm |
| `Annex-VII.3.1.e` | a description of the procedures in place to ensure that the quality ma | The obligation requires a description of procedures ensuring the quality managem |
| `Annex-VII.3.1.f` | a written declaration that the same application has not been lodged wi | authority/notified-body procedure |
| `Annex-VII.3.3` | The quality management system as approved shall continue to be impleme | This obligation requires the provider to continuously implement and maintain an  |
| `Annex-VII.3.4` | Any intended change to the approved quality management system or the l | authority/notified-body procedure |
| `Annex-VII.4.1` | In addition to the application referred to in point 3, an application  | authority/notified-body procedure |
| `Annex-VII.4.2.a` | the name and address of the provider; | This obligation is a pure registration/identity data field ("the name and addres |
| `Annex-VII.4.2.b` | a written declaration that the same application has not been lodged wi | authority/notified-body procedure |
| `Annex-VII.4.2.c` | the technical documentation referred to in Annex IV. | This obligation is a conformity-assessment procedural item: it lists "the techni |
| `Annex-VII.4.4` | In examining the technical documentation, the notified body may requir | authority/notified-body procedure |
| `Annex-VII.4.5` | Where necessary to assess the conformity of the high-risk AI system wi | authority/notified-body procedure |
| `Annex-VII.4.6` | The decision of the notified body shall be notified to the provider or | authority/notified-body procedure |
| `Annex-VII.4.7` | Any change to the AI system that could affect the compliance of the AI | authority/notified-body procedure |
| `Annex-VII.5.1` | The purpose of the surveillance carried out by the notified body refer | authority/notified-body procedure |
| `Annex-VII.5.2` | For assessment purposes, the provider shall allow the notified body to | authority/notified-body procedure |
| `Annex-VIII.A.1` | The name, address and contact details of the provider; | registration/identity field |
| `Annex-VIII.A.10` | Any Member States in which the AI system has been placed on the market | registration/identity field |
| `Annex-VIII.A.11` | A copy of the EU declaration of conformity referred to in Article 47; | legal/conformity instrument |
| `Annex-VIII.A.12` | Electronic instructions for use; this information shall not be provide | deployer-facing documentation artifact |
| `Annex-VIII.A.13` | A URL for additional information (optional). | registration/identity field |
| `Annex-VIII.A.2` | Where submission of information is carried out by another person on be | registration/identity field |
| `Annex-VIII.A.3` | The name, address and contact details of the authorised representative | registration/identity field |
| `Annex-VIII.A.5` | A description of the intended purpose of the AI system and of the comp | This is an EU AI Act registration database field requiring a textual description |
| `Annex-VIII.A.6` | A basic and concise description of the information used by the system  | This is an Annex VIII registration field: the provider must supply a basic, conc |
| `Annex-VIII.A.7` | The status of the AI system (on the market, or in service; no longer p | organizational/procedural |
| `Annex-VIII.A.8` | The type, number and expiry date of the certificate issued by the noti | authority/notified-body procedure |
| `Annex-VIII.A.9` | A scanned copy of the certificate referred to in point 8, where applic | organizational/procedural |
| `Annex-VIII.B.1` | The name, address and contact details of the provider; | registration/identity field |
| `Annex-VIII.B.2` | Where submission of information is carried out by another person on be | registration/identity field |
| `Annex-VIII.B.3` | The name, address and contact details of the authorised representative | registration/identity field |
| `Annex-VIII.B.4` | The AI system trade name and any additional unambiguous reference allo | registration/identity field |
| `Annex-VIII.B.5` | A description of the intended purpose of the AI system; | This obligation is a registration-database content field (Annex VIII, Section B) |
| `Annex-VIII.B.6` | The condition or conditions under Article 6(3)based on which the AI sy | This obligation is a registration database field (Annex VIII, Section B) requiri |
| `Annex-VIII.B.7` | A short summary of the grounds on which the AI system is considered to | This obligation is a registration/documentation field: providing a short written |
| `Annex-VIII.B.8` | The status of the AI system (on the market, or in service; no longer p | organizational/procedural |
| `Annex-VIII.B.9` | Any Member States in which the AI system has been placed on the market | registration/identity field |
| `Annex-VIII.C.1` | The name, address and contact details of the deployer; | registration/identity field |
| `Annex-VIII.C.2` | The name, address and contact details of the person submitting informa | registration/identity field |
| `Annex-VIII.C.3` | The URL of the entry of the AI system in the EU database by its provid | This obligation is a registration/identity field — the URL of the AI system's en |
| `Annex-VIII.C.4` | A summary of the findings of the fundamental rights impact assessment  | deployer organizational assessment |
| `Annex-VIII.C.5` | A summary of the data protection impact assessment carried out in acco | deployer organizational assessment |
| `Annex-IX.1` | A Union-wide unique single identification number of the testing in rea | registration/identity field |
| `Annex-IX.2` | The name and contact details of the provider or prospective provider a | registration/identity field |
| `Annex-IX.3` | A brief description of the AI system, its intended purpose, and other  | This is an Annex IX EU-database registration field: a brief textual description  |
| `Annex-IX.4` | A summary of the main characteristics of the plan for testing in real  | Annex IX.4 is a registration-database field: it requires the provider to author  |
| `Annex-IX.5` | Information on the suspension or termination of the testing in real wo | This is an Annex IX registration/documentation field: information submitted to t |
| `Annex-XI.1.2.a` | the technical means (e.g. instructions of use, infrastructure, tools)  | This obligation requires a general-purpose AI model provider to document, as par |
| `Annex-XI.1.2.e` | known or estimated energy consumption of the model. | This is a GPAI technical-documentation/transparency field requiring the provider |
| `Annex-XI.2.3` | Where applicable, a detailed description of the system architecture ex | This obligation requires a provider-authored documentation deliverable: a detail |
| `Article-9.10` | For providers of high-risk AI systems that are subject to requirements | Article 9.10 is a purely legal/procedural provision permitting providers already |
| `Article-9.3` | The risks referred to in this Article shall concern only those which m | Article 9.3 is a scoping/definitional clause that limits the risks addressed by  |
| `Article-9.4` | The risk management measures referred to in paragraph 2, point (d), sh | Article 9.4 is a methodological/organizational requirement on the provider's ris |
| `Article-9.5.c` | provision of information required pursuant to Article 13 and, where ap | This obligation requires the provider to supply Article 13 information (instruct |
| `Article-9.7` | Testing procedures may include testing in real-world conditions in acc | Article 9.7 permits testing procedures to include testing in real-world conditio |
| `Article-9.9` | When implementing the risk management system as provided for in paragr | This obligation requires providers to consider, as part of risk management, whet |
| `Article-10.3` | Training, validation and testing data sets shall be relevant, sufficie | Article 10.3 mandates data-quality properties of training, validation and testin |
| `Article-10.4` | Data sets shall take into account, to the extent required by the inten | This obligation requires that datasets reflect the geographical, contextual, beh |
| `Article-10.6` | For the development of high-risk AI systems not using techniques invol | This is a purely legal applicability/scoping clause. It states that for high-ris |
| `Article-11.2` | Where a high-risk AI system related to a product covered by the Union  | Article 11.2 requires that, for a high-risk AI system that is a product under Un |
| `Article-11.3` | The Commission is empowered to adopt delegated acts in accordance with | authority/notified-body procedure |
| `Article-13.2` | High-risk AI systems shall be accompanied by instructions for use in a | deployer-facing documentation artifact |
| `Article-13.3.a` | the identity and the contact details of the provider and, where applic | registration/identity field |
| `Article-13.3.b.i` | its intended purpose; | This obligation is a required content element of the high-risk AI system's instr |
| `Article-13.3.b.iii` | any known or foreseeable circumstance, related to the use of the high- | This obligation governs the content of the high-risk AI system's instructions fo |
| `Article-13.3.b.iv` | where applicable, the technical capabilities and characteristics of th | This is a deployer-facing documentation obligation: the instructions for use mus |
| `Article-13.3.b.v` | when appropriate, its performance regarding specific persons or groups | This obligation requires the instructions for use accompanying a high-risk AI sy |
| `Article-13.3.b.vii` | where applicable, information to enable deployers to interpret the out | This obligation requires the provider to include, in the instructions for use, i |
| `Article-13.3.c` | the changes to the high-risk AI system and its performance which have  | Article 13.3.c specifies required content of the provider's "instructions for us |
| `Article-13.3.d` | the human oversight measures referred to in Article 14, including the  | This obligation governs the content of the provider's instructions for use — it  |
| `Article-13.3.f` | where relevant, a description of the mechanisms included within the hi | This obligation requires the provider to include in the instructions for use a d |
| `Article-14.2` | Human oversight shall aim to prevent or minimise the risks to health,  | Article 14.2 defines the purpose/aim of human oversight for high-risk AI systems |
| `Article-14.3.b` | measures identified by the provider before placing the high-risk AI sy | This obligation (Article 14.3.b) concerns human oversight measures that the prov |
| `Article-14.4.b` | to remain aware of the possible tendency of automatically relying or o | This obligation requires that natural persons assigned to human oversight remain |
| `Article-14.4.c` | to correctly interpret the high-risk AI system’s output, taking into a | Article 14.4.c is a human-oversight design obligation: the high-risk AI system m |
| `Article-14.5` | For high-risk AI systems referred to in point 1(a) of Annex III, the m | Article 14.5 mandates a "four-eyes" human-oversight procedure: for biometric ide |
| `Article-15.2` | To address the technical aspects of how to measure the appropriate lev | authority/notified-body procedure |
| `Article-72.4` | For high-risk AI systems covered by the Union harmonisation legislatio | Article 72.4 is a purely procedural/legal provision allowing providers to integr |
| `Article-73.10` | For high-risk AI systems which are safety components of devices, or ar | authority/notified-body procedure |
| `Article-73.11` | National competent authorities shall immediately notify the Commission | authority/notified-body procedure |
| `Article-73.2` | The report referred to in paragraph 1 shall be made immediately after  | organizational/procedural |
| `Article-73.3` | Notwithstanding paragraph 2 of this Article, in the event of a widespr | organizational/procedural |
| `Article-73.4` | Notwithstanding paragraph 2, in the event of the death of a person, th | organizational/procedural |
| `Article-73.5` | Where necessary to ensure timely reporting, the provider or, where app | This obligation is a purely procedural reporting mechanism: it permits a provide |
| `Article-73.6` | Following the reporting of a serious incident pursuant to paragraph 1, | authority/notified-body procedure |
| `Article-73.7` | Upon receiving a notification related to a serious incident referred t | authority/notified-body procedure |
| `Article-73.8` | The market surveillance authority shall take appropriate measures, as  | authority/notified-body procedure |
| `Article-73.9` | For high-risk AI systems referred to in Annex III that are placed on t | Article 73.9 is a purely legal/procedural rule that narrows the serious-incident |
