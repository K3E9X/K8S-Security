# Pull Request

## Description

<!-- Provide a brief description of your changes -->

## Type of Change

<!-- Mark the relevant option with an x -->

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] New module
- [ ] New lab
- [ ] Documentation update
- [ ] Diagram addition/update
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] This change requires a documentation update

## Modules Affected

<!-- List the modules affected by this PR -->

- Module XX: Module Name
- Labs: lab-name
- Examples: example-name

## Changes Made

<!-- Provide a detailed list of changes -->

- Change 1
- Change 2
- Change 3

## Testing Performed

<!-- Describe the testing you've done -->

### Local Testing
- [ ] Markdown linting (`make lint`)
- [ ] YAML validation (`make validate`)
- [ ] Documentation build (`make docs-build`)
- [ ] Tested labs locally

### Lab Testing
- [ ] Tested on kind
- [ ] Tested on k3d
- [ ] Tested on minikube
- [ ] Tested on cloud provider (specify): __________

### Manual Testing Steps

1. Step 1
2. Step 2
3. Expected outcome

## Screenshots or Output

<!-- If applicable, add screenshots or command output -->

```bash
# Paste relevant output
```

## References

<!-- Link to related issues, documentation, or external resources -->

- Closes #(issue number)
- Related to #(issue number)
- Based on [documentation](url)

## Checklist

<!-- Mark completed items with an x -->

### General
- [ ] My code follows the style guidelines of this project (see CONTRIBUTING.md)
- [ ] I have performed a self-review of my own changes
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have checked for and fixed any typos

### Content Quality
- [ ] All technical information is accurate and tested
- [ ] Sources are cited in REFERENCES.md
- [ ] Examples use current Kubernetes best practices
- [ ] Security best practices are followed
- [ ] No sensitive information (keys, passwords, etc.) is included

### Documentation
- [ ] README.md updated (if needed)
- [ ] SUMMARY.md updated (if adding/removing modules)
- [ ] CHANGELOG.md updated
- [ ] Module documentation follows template structure
- [ ] All links are valid and working

### Labs
- [ ] Lab has clear learning objectives
- [ ] Step-by-step instructions are provided
- [ ] Expected output is documented
- [ ] Cleanup/teardown instructions included
- [ ] Solution is provided in labs/solutions/
- [ ] Troubleshooting guide included

### Diagrams
- [ ] Mermaid diagrams render correctly in GitHub
- [ ] Draw.io source files (.drawio) included
- [ ] PNG exports included
- [ ] Diagrams are clearly labeled
- [ ] Alt text provided for accessibility

### Tests
- [ ] Markdown lint passes
- [ ] YAML validation passes
- [ ] All labs tested successfully
- [ ] Documentation builds without errors

## Breaking Changes

<!-- If this PR includes breaking changes, describe them and migration path -->

None / Describe breaking changes and migration

## Additional Notes

<!-- Any additional information for reviewers -->

## For Reviewers

<!-- Specific things you'd like reviewers to focus on -->

Please pay special attention to:
- Item 1
- Item 2

## Post-Merge Actions

<!-- Actions required after merge (if any) -->

- [ ] Update external documentation
- [ ] Notify community
- [ ] Create release notes
- [ ] Other: __________
