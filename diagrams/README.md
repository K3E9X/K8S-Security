# Architecture Diagrams

This directory contains architecture diagrams for visualizing Kubernetes concepts and security patterns.

## File Types

- **.mermaid** - Mermaid diagram source code (renders in GitHub and MkDocs)
- **.drawio** - Draw.io source files (editable with https://app.diagrams.net/)
- **.png** - Exported images for documentation

## Diagrams

- `control-plane-architecture` - Kubernetes control plane components
- `networking-layers` - CNI, services, and network policies
- `security-layers` - Defense-in-depth security architecture
- `authn-authz-flow` - Authentication and authorization flow
- `zero-trust-architecture` - Zero-trust networking model
- `ci-cd-security` - Secure software supply chain

## Editing Diagrams

1. Open .drawio files with draw.io (desktop or web app)
2. Make changes
3. Export as PNG (2x scale, transparent background)
4. Commit both .drawio and .png files

## Using in Documentation

```markdown
![Diagram Title](../diagrams/diagram-name.png)

*[Edit diagram](../diagrams/diagram-name.drawio)*
```
