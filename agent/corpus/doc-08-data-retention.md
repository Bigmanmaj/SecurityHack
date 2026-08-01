# Data Retention

Retention periods are set by data class, not by system. Customer records are kept for seven years after the end of the commercial relationship. Operational telemetry is kept for thirteen months. Chat messages are kept for one year unless a legal hold applies to the channel.

Deletion is automatic where the platform supports it and quarterly where it does not. Teams owning a system without automatic deletion are asked to record the manual process in the system record, including who runs it and how the run is evidenced.

Legal holds override every retention rule. When a hold is placed, automated deletion for the affected scope is suspended until the hold is lifted, and the suspension is logged. Deleting data under hold is a serious matter even when it happens by accident.

Backups follow the same retention clock as the primary system, with a thirty-day grace period to allow restores. A restore that reintroduces data past its retention date must be followed by a targeted deletion, and the restore ticket stays open until that is done.

Requests from individuals to delete their data are handled by the privacy team within thirty days. Engineering involvement is usually limited to confirming that a deletion ran and producing evidence of it, which the privacy team then supplies to the requester.
