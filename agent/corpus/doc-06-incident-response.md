# Incident Response

Anyone can declare an incident. There is no seniority threshold and no penalty for declaring one that turns out to be minor. The cost of a late declaration is consistently higher than the cost of an unnecessary one, and the process is designed around that asymmetry.

Declaring an incident opens a channel, pages the on-call responder, and starts a timeline. The timeline is the artefact that matters afterwards; responders are asked to post what they did and when they did it, even when it turns out to be wrong, so the reconstruction is accurate.

The incident commander coordinates and does not fix. This separation exists because the person deepest in the debugger is the worst-placed person to decide about customer communication, escalation, or rollback. Commanders hand off explicitly when they tire.

Customer-affecting incidents require a status page update within thirty minutes of declaration, even if the update says only that the issue is being investigated. Silence is worse than an incomplete update, and the communications team drafts the wording if asked.

Every incident above severity three gets a written review within five working days. The review names contributing factors and never names a person as a root cause. Action items have owners and dates, and they are tracked to completion in the same system as ordinary work.
