# Deliberately vulnerable fixtures

Every file here contains real, exploitable-looking patterns. They exist so the
scanner has something to find in tests and demos.

**Do not deploy any of it, and do not copy from it.** The credentials are
invented and inert; the code is wrong on purpose.

Scan it with:

    lory-scan scan examples/vulnerable-app
