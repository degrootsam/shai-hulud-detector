# Shai Hulud Detector (NPM Worm)

Scans an org's repositories via GitHub's SBOM API (Dependency Graph)
and reports which repos contain any package@version listed in an input file.

## Installation

1. Clone this repo:

   ```bash
   git clone https://github.com/degrootsam/shai-hulud-detector.git
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

## Usage

1. Rename `env.example` to `.env`.
2. Insert your GitHub PAT token.
3. Edit the `affected.txt` to contain your targeted packages.
4. Start the scanner:

```bash
node sbom-scan.mjs --org=<ORG>
```

> [!NOTE]
> The token needs access to your organisation's repos (scope: repo). Make sure the owner of the PAT is set to the target org.

## Affected NPM Packages

We are currently manually monitoring the packages from: [socket.dev](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)

Current affected packages: **526**

[Link to Highlight](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages#:~:text=confirmed%20as%20affected%3A-,Total%20packages%3A%20526,-%40ahmedhfarag/ngx%2Dperfect)
