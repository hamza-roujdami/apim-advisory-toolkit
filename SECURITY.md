# Security

- This toolkit is read-only unless you run `apimtk remediate --apply`.
- It never retrieves secret values (`listValue` / `listSecrets` are not called) and never writes them to disk.
- Run it from a trusted workstation with your own credentials. Treat `out/` as sensitive: it lists your instance
  names, named value names, subscription ids and findings.
- Found a problem in the toolkit? Please open a private security advisory on this repository rather than a public issue.
