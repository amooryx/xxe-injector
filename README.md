<div align="center">
  <img src="./banner.svg" alt="xxe-injector" width="800">
</div>

# xxe-injector

> Safe XML endpoint baseline checker. It does not perform XXE exploitation or detection.

```bash
python xxe_injector.py --help
```

## What it does

The command sends exactly one fixed, well-formed XML document that contains no DTD or
entity declarations. It records the HTTP status, response content type, and at most
16 KiB of response text. The socket inactivity timeout is capped at 30 seconds,
custom headers are bounded, and redirects are not followed. This timeout is not a
total wall-clock deadline; a server that continually trickles data may take longer.

For example, against a local fixture you control:

```bash
python xxe_injector.py http://127.0.0.1:8080/xml \
  --authorized-target http://127.0.0.1:8080/xml \
  --i-have-authorization \
  --timeout 5 \
  --out baseline.json
```

`--authorized-target` must exactly match the URL argument, and the explicit
`--i-have-authorization` confirmation is required before any request is made. Use
only an endpoint for which you have authorization and keep testing within its
approved scope. Do not include credentials in the URL; use a carefully scoped
request header if needed.

## Limitations and safeguards

- No file-read, external-entity, DTD, or callback payloads are sent.
- A response is only evidence of the HTTP behavior observed for this benign
  baseline. It does not show that an XML parser was reached and cannot prove
  that XXE is present or absent.
- The tool does not probe multiple paths, follow redirects, or infer vulnerability
  status from response content.
- Only HTTP(S) URLs are accepted, and the target URL is limited to 2 KiB. The
  response body, socket inactivity timeout, and custom headers have explicit
  limits; transport failures are reported separately from HTTP responses. The
  timeout is not a total wall-clock deadline.
- Offline regressions use a loopback-only HTTP fixture:

  ```bash
  python -m unittest discover -s tests -v
  ```

To assess parser security, inspect the application’s parser configuration and run
its own tests against controlled local fixtures designed for that parser. This tool
does not supply such payloads.

## Author

**Omar Khalid**
