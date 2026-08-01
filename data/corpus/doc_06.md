# Nimbus: payment methods and failed payments

Nimbus accepts major credit cards and, on Business plans, bank transfer against
a 30-day invoice. When a card is declined the system retries on days 3, 5, and 7
and emails the billing contact after each attempt. If all retries fail, the
workspace moves to a read-only grace period for 14 days, during which files can
be downloaded but not uploaded. Updating the card in Settings, Billing restores
full access immediately and triggers a fresh charge attempt.
