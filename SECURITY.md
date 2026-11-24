# Security

- This toolkit is read-only unless you run `apimtk remediate --apply`.
- It never retrieves secret values (`listValue` / `listSecrets` are not called) and never writes them to disk.
  Plain named values, backend credentials and policy XML are inspected in memory to spot keys written in clear text;
  only names, locations and verdicts are saved.
- `remediate --action update-client-secret` reads the new secret from a hidden prompt and logs it as `***`.
- Run it from a trusted workstation with your own credentials. Treat `out/` as sensitive: it lists your instance
  names, named value names, subscription ids and findings.
- Found a problem in the toolkit? Please open a private security advisory on this repository rather than a public issue.
