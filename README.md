# Shai Hulud Detector (NPM Worm)

Scans an org's repositories via GitHub's SBOM API (Dependency Graph)
and reports which repos contain any package@version listed in an input file.

## Usage

1. Rename `env.example` to `.env`.
2. Insert your GitHub PAT token.

> [!NOTE] The token needs access to your organisation's repos (scope: repo). Make sure the owner of the PAT is set to the target org.

```bash
node sbom-scan.mjs --org <ORG>
```

```

```
