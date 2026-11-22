# Synthetic evidence E-AI-01

Evidence class: synthetic fixture. Describes a review prompt, not an observed deployment.

Trust boundary: model-serving clients, ingress, serving controller, inference workload, model artifact store, and GPU runtime are separate candidate trust zones. Data flow: request and supplied content -> endpoint/controller -> inference process -> model/artifact and telemetry services. Reviewers must establish actual tenancy, data classes, model lifecycle, GPU sharing, egress, and retention.
