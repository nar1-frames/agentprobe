# Paid attack packs: distribution model

This describes how commercial attack packs are meant to reach customers. It
is a design note, not a price list. The open-source tool, the built-in pack,
and the pack format stay free under MIT. What is paid is curated content: new
attacks, domain packs (support desks, retrieval-backed assistants, coding
agents), and regular refreshes as models change.

## How it works

1. **We sign every pack we publish** with an Ed25519 key, using `agentprobe
   packs sign`. The signature covers the pack's content digest, so it covers
   the manifest and every attack.
2. **Customers receive the pack** as a plain folder: a zip download, a private
   Git repository, or an artifact in their CI. Any channel works, because the
   signature travels with the content.
3. **Customers trust our public key once**, in their config:

   ```yaml
   packs_trust:
     mode: require          # refuse anything unsigned or signed by someone else
     keys:
       - "<our published public key, raw base64>"
   ```

4. **Every scan proves which content was used.** `run.attack_packs` records
   the pack's id, version, digest, `signed: true`, our `signer_key_id`, and
   `verified: true`. The customer report's methodology says "signed by
   <key id>, verified". A buyer forwarding the report can see the attacks
   came from the vendor, unmodified.

## What we deliberately do not do

- **No license server and no phone-home.** Scans never contact us. A pack
  works offline, in air-gapped CI, and years later.
- **No DRM or encryption of attack content.** Packs are readable YAML. A
  customer who copies a pack can run it; the signature only proves where it
  came from and that it is unchanged. The commercial protection is the
  subscription (fresh packs as models change) and the terms of the license
  in each manifest, not technical lock-in.
- **No telemetry.** Provenance lives in the customer's own reports and nowhere
  else.

## Operational notes

- Keep the signing private key off developer laptops: on an offline machine,
  or in a CI secret that only the release job can read. Publish the public
  key in the README, on the website, and in the release notes, so customers
  can cross-check it.
- If the key is ever exposed, generate a new key pair, re-sign all current
  packs, publish the new public key, and tell customers to replace the old
  key in `packs_trust.keys`. Old reports keep recording the old key id, so
  past evidence stays attributable.
- Bump a pack's `version` with every content change (see PACKS.md). The
  digest catches every change either way, but the version is what customers
  read.

See [PACKS.md](PACKS.md) for the pack format and the signing commands.
