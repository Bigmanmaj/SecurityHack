# Security Baseline

Every company laptop runs full-disk encryption and an endpoint agent. Devices that fall out of compliance for more than seven days lose access to internal services automatically until they are brought back into compliance. The check runs nightly and the owner is warned before the cutoff.

Passwords are managed through the company password manager. Shared credentials in documents, tickets, or chat are treated as an incident even when the credential is low value, because the habit is what causes breaches rather than any single secret.

Phishing reports are welcome and never penalised. Forward the message as an attachment to the security mailbox and delete it. If you clicked a link before reporting it, say so in the report; the response is materially different and nobody is disciplined for admitting it.

Data leaving the company boundary requires a named owner and a documented purpose. That applies to exports to partner systems, to analytics vendors, and to any automated integration. An integration that posts internal content to an external endpoint is a data export, whatever it is called in the tooling.

Security reviews are required for new external integrations and for changes to authentication flows. Everything else ships without review. The review is scheduled within two working days of request, and the reviewer's decision is recorded in the ticket.
