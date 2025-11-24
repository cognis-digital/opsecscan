# Demo 01 - Basic OPSEC leak scan

This demo shows OPSECSCAN catching common operational-security leaks in a
public-affairs release draft before it ships.

## Input

`release_draft.txt` is a mock press-release / after-action note that an analyst
is about to publish. It accidentally contains material that violates OPSEC
hygiene:

- A classification banner that should have been removed for a public release
- A unit identifier and callsign
- Precise lat/lon coordinates
- A `.mil` email address and an SSN (PII)

## Run it

```sh
# Human-readable table
python -m opsecscan scan demos/01-basic/release_draft.txt

# Machine-readable for a CI release gate
python -m opsecscan scan demos/01-basic/release_draft.txt --format json
```

## Expected outcome

The scan reports CRITICAL/HIGH findings and exits non-zero (default
`--fail-on medium`), so it can be wired into a publishing pipeline as a gate:

```sh
python -m opsecscan scan ./outbound --recursive --fail-on high \
  || echo "BLOCKED: OPSEC review required before release"
```

Clean files exit 0. Use `--min-severity low` to surface advisory metadata
findings (author/producer/timestamp) you may also want to scrub.
