# Diagram Insertion Guide

This folder contains diagrams required by IGNOU report sections.

## Use these files in Chapter 6 and Chapter 7

- `source/architecture_overview.mmd`
- `source/deployment_diagram.mmd`
- `source/dfd_level0.mmd`
- `source/dfd_level1.mmd`
- `source/use_case_diagram.mmd`
- `source/activity_workflow.mmd`
- `source/sequence_user_verification.mmd`
- `source/sequence_admin_review.mmd`
- `source/state_verification_session.mmd`
- `source/er_database.mmd`
- `source/class_backend_domain.mmd`
- `source/decision_control_flow.mmd`

## Approved synopsis image assets copied

- `approved_synopsis/gantt_chart.png`
- `approved_synopsis/pert_chart.png`
- `approved_synopsis/dfd_l1.png`
- `approved_synopsis/er_diagram.png`
- `approved_synopsis/main.png`

## Optional rendering

You can render Mermaid sources to PNG/SVG with Mermaid CLI if needed:

```bash
npx @mermaid-js/mermaid-cli -i source/er_database.mmd -o er_database.png
```
