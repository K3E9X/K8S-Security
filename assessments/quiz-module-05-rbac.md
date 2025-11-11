# Module 05: Authentication and Authorization - Quiz

## Questions

**1. Which authentication strategy is recommended for human users in production Kubernetes clusters?**
- a) Client certificates
- b) Static token file
- c) OIDC integration with an identity provider
- d) Service account tokens

**2. What is the principle of least privilege in RBAC?**
- a) Give all users cluster-admin access
- b) Grant only the minimum permissions necessary for a task
- c) Use only ClusterRoles, never Roles
- d) Disable authentication to simplify operations

**3. Which RBAC resource applies cluster-wide permissions?**
- a) Role
- b) RoleBinding
- c) ClusterRole
- d) ServiceAccount

**4. What is the difference between a Role and a ClusterRole?**
- a) Roles are more powerful
- b) ClusterRoles can only be used for cluster-scoped resources
- c) Roles are namespace-scoped, ClusterRoles can be cluster-wide
- d) There is no difference

**5. How can you test RBAC permissions without making actual API calls?**
- a) kubectl can-i command
- b) kubectl auth can-i command
- c) kubectl test command
- d) RBAC cannot be tested

**6. Which is a valid RBAC verb?**
- a) get
- b) download
- c) execute
- d) connect

**7. What happens if a user has no RoleBinding or ClusterRoleBinding?**
- a) They get read-only access
- b) They are denied all access (default deny)
- c) They inherit cluster-admin permissions
- d) They can access their own namespace

**8. Service accounts are used for:**
- a) Human user authentication
- b) Pod and application authentication
- c) External system access only
- d) Backup purposes

**9. How can you limit a service account's access to the API server?**
- a) Delete the service account
- b) Use RBAC to grant minimal permissions
- c) Disable the API server
- d) Service accounts cannot be limited

**10. What is the effect of automountServiceAccountToken: false?**
- a) Deletes the service account
- b) Prevents automatic mounting of SA token in pods
- c) Disables RBAC
- d) Enables privileged mode

## Answers

1. **c** - OIDC integration (NSA/CISA recommendation)
2. **b** - Minimum necessary permissions
3. **c** - ClusterRole
4. **c** - Namespace vs cluster-wide scope
5. **b** - kubectl auth can-i
6. **a** - get (valid verbs: get, list, create, update, patch, delete, watch)
7. **b** - Default deny
8. **b** - Pod/application authentication
9. **b** - RBAC with least privilege
10. **b** - Prevents automatic token mounting

## Scoring

- 9-10 correct: Excellent understanding
- 7-8 correct: Good understanding, review mistakes
- 5-6 correct: Basic understanding, review module
- 0-4 correct: Revisit module content
