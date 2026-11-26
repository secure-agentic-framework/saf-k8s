# NIST SP 800-53 Revision 5 5.2.0 - SR-3

- Framework Code: NIST-800-53R5
- Requirement Title: Supply Chain Controls and Processes

## Mapping Notes

Supply chain controls for AI model, tool, and plugin acquisition ensure component integrity

6.6 - CNCF lifecycle security (supply chain controls across Develop/Distribute/Deploy); 9.5 - ML dependency vulnerability management

## SAF-K8S Controls

### [SAF-K8S-0606-007 - CI/CD build activity monitoring](../../controls/SAF-K8S-0606-007.md)

- Domain: D06 - Supply Chain, Images, and Admission Control
- Knowledge Area: 6.6
- Relation Type: direct
- Strength: strong
- Applicability: required
- Strength Reason Code: n/a

### [SAF-K8S-0905-009 - Model provenance verification at deployment](../../controls/SAF-K8S-0905-009.md)

- Domain: D09 - AI Workload Security: Training, Serving, and Pipelines
- Knowledge Area: 9.5
- Relation Type: supports
- Strength: moderate
- Applicability: conditional
- Strength Reason Code: partial-control-coverage
