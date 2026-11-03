"""Built-in detection rules and their Linux_2k defaults.

Thresholds were chosen by counting the bundled file, not by seeding alerts.
Each rule states its window. Severity is an analyst priority, not a confirmed
incident outcome. Findings on this file are unlabeled 2005 syslog.

Tumbling windows are non-overlapping buckets aligned to the Unix epoch:
``start = floor(unix_seconds / window_seconds) * window_seconds``, UTC, half-open
``[start, start + window)``.

Sliding windows walk one group in timestamp order. A window opens on an event
and keeps later events of that group while they stay within ``window_seconds``
of the opening event. One alert is emitted for that span, then the walk resumes
after the last included event (non-overlapping emission). The span is inclusive.

Events with a null ``event_timestamp`` are not eligible for either window.
"""

from dataclasses import dataclass

DISCLAIMER = "This is a rule finding on unlabeled logs, not a confirmed compromise."

# root is the only uid-0 login principal in Linux_2k (user=root, ROOT LOGIN ON tty2,
# session opened for user root by LOGIN(uid=0)). guest and test are not privileged.
# cyrus and news appear only as su(pam_unix) targets of (uid=0); the privileged
# actor in those lines is root, and they have no authentication-failure lines.
PRIVILEGED_USERNAMES: tuple[str, ...] = ("root",)


@dataclass(frozen=True)
class BuiltinRule:
    name: str
    description: str
    severity: str
    threshold: int
    window_seconds: int
    window_type: str
    group_by: str
    title_template: str
    explanation_template: str
    required_attributes: tuple[str, ...]
    source_address_from_group: bool
    event_ids: tuple[str, ...] | None = None
    components: tuple[str, ...] | None = None
    content_contains: str | None = None
    usernames: tuple[str, ...] | None = None

    def logic(self) -> dict[str, object]:
        return {
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "window_type": self.window_type,
            "group_by": self.group_by,
            "title_template": self.title_template,
            "explanation_template": self.explanation_template,
            "required_attributes": list(self.required_attributes),
            "source_address_from_group": self.source_address_from_group,
            "event_ids": list(self.event_ids) if self.event_ids is not None else None,
            "components": list(self.components) if self.components is not None else None,
            "content_contains": self.content_contains,
            "usernames": list(self.usernames) if self.usernames is not None else None,
        }


def _explain(body: str) -> str:
    return body.rstrip() + " " + DISCLAIMER


BUILTIN_RULES: tuple[BuiltinRule, ...] = (
    BuiltinRule(
        name="ssh-auth-failures-by-source",
        description=(
            "Repeated sshd(pam_unix) authentication failures from the same rhost "
            "(templates E16, E17, E18, E19). Tumbling UTC day (86400 seconds, "
            "epoch-aligned). Threshold 5. rhost may be an IPv4 address or a hostname. "
            "Events without rhost are ignored. Analyst priority only."
        ),
        severity="medium",
        threshold=5,
        window_seconds=86400,
        window_type="tumbling",
        group_by="rhost",
        title_template="Repeated SSH authentication failures from {group}",
        explanation_template=_explain(
            "Repeated SSH authentication failures from {group}: {count} events "
            "between {first} and {last}. Threshold {threshold} in a "
            "{window_seconds}-second {window_type} window (analyst severity {severity})."
        ),
        required_attributes=(
            "event_timestamp",
            "component",
            "event_id",
            "rhost",
            "content authentication failure",
        ),
        source_address_from_group=True,
        event_ids=("E16", "E17", "E18", "E19"),
        components=("sshd(pam_unix)",),
        content_contains="authentication failure",
    ),
    BuiltinRule(
        name="ssh-bruteforce-burst",
        description=(
            "Potential SSH brute-force burst. Same sshd authentication-failure "
            "events as ssh-auth-failures-by-source, grouped by rhost. Sliding 60 "
            "seconds, threshold 10. One alert per non-overlapping burst. A rate "
            "finding, not a verified intrusion."
        ),
        severity="high",
        threshold=10,
        window_seconds=60,
        window_type="sliding",
        group_by="rhost",
        title_template="Potential SSH brute-force burst from {group}",
        explanation_template=_explain(
            "Potential SSH brute-force burst from {group}: {count} authentication "
            "failures between {first} and {last}. Threshold {threshold} in a "
            "{window_seconds}-second {window_type} window (analyst severity {severity})."
        ),
        required_attributes=(
            "event_timestamp",
            "component",
            "event_id",
            "rhost",
            "content authentication failure",
        ),
        source_address_from_group=True,
        event_ids=("E16", "E17", "E18", "E19"),
        components=("sshd(pam_unix)",),
        content_contains="authentication failure",
    ),
    BuiltinRule(
        name="privileged-user-auth-failures",
        description=(
            "Repeated SSH authentication failures whose target user is privileged. "
            "The privileged set is root only. root is the uid-0 login principal "
            "(user=root on E18, ROOT LOGIN ON tty2, and session opened for user root "
            "by LOGIN(uid=0)). guest and test are not privileged. cyrus and news "
            "appear only as su(pam_unix) targets of (uid=0); the privileged actor "
            "there is root, and those accounts have no authentication-failure lines. "
            "Grouped by rhost. Tumbling UTC day, threshold 5."
        ),
        severity="high",
        threshold=5,
        window_seconds=86400,
        window_type="tumbling",
        group_by="rhost",
        title_template="Privileged-user SSH failures from {group}",
        explanation_template=_explain(
            "SSH authentication failures targeting privileged user(s) {users} from "
            "{group}: {count} events between {first} and {last}. Threshold {threshold} "
            "in a {window_seconds}-second {window_type} window "
            "(analyst severity {severity})."
        ),
        required_attributes=(
            "event_timestamp",
            "component",
            "username",
            "rhost",
            "content authentication failure",
        ),
        source_address_from_group=True,
        event_ids=("E16", "E17", "E18", "E19"),
        components=("sshd(pam_unix)",),
        content_contains="authentication failure",
        usernames=PRIVILEGED_USERNAMES,
    ),
    BuiltinRule(
        name="unknown-username-attempts",
        description=(
            "Unknown-username activity: sshd or gdm 'check pass; user unknown' (E27) "
            "and ftpd 'User unknown timed out' (E112). Grouped by component in a "
            "tumbling 1-hour window. Threshold 1, so each component-hour with at "
            "least one such line is one alert. These lines do not store a username "
            "(the token unknown is rejected) and usually have no source address."
        ),
        severity="low",
        threshold=1,
        window_seconds=3600,
        window_type="tumbling",
        group_by="component",
        title_template="Unknown username attempts in {group}",
        explanation_template=_explain(
            "Unknown username attempts in {group}: {count} events between {first} "
            "and {last}. Threshold {threshold} in a {window_seconds}-second "
            "{window_type} window (analyst severity {severity})."
        ),
        required_attributes=("event_timestamp", "component", "event_id"),
        source_address_from_group=False,
        event_ids=("E27", "E112"),
    ),
    BuiltinRule(
        name="ftp-connection-burst",
        description=(
            "High-volume FTP connection bursts. ftpd template E29 (connection from), "
            "grouped by the first IPv4, sliding 60 seconds, threshold 20. On Linux_2k "
            "the dense bursts are about 23 connections in the same second; 20 is the "
            "high-volume cutoff. Smaller connection groups stay below the line. "
            "Non-overlapping sliding emission."
        ),
        severity="medium",
        threshold=20,
        window_seconds=60,
        window_type="sliding",
        group_by="source_ip",
        title_template="High-volume FTP connections from {group}",
        explanation_template=_explain(
            "High-volume FTP connection burst from {group}: {count} connections "
            "between {first} and {last}. Threshold {threshold} in a "
            "{window_seconds}-second {window_type} window (analyst severity {severity})."
        ),
        required_attributes=("event_timestamp", "component", "event_id", "source_ip"),
        source_address_from_group=True,
        event_ids=("E29",),
        components=("ftpd",),
    ),
    BuiltinRule(
        name="anonymous-ftp-auth",
        description=(
            "Unexpected anonymous FTP authentication (template E9). Anonymous FTP "
            "is treated as unexpected by policy on this host. The dataset has no "
            "malicious/benign labels. Grouped by source IPv4, sliding 60 seconds, "
            "threshold 1. The two Linux_2k lines share a timestamp and one source, "
            "so they form one alert."
        ),
        severity="medium",
        threshold=1,
        window_seconds=60,
        window_type="sliding",
        group_by="source_ip",
        title_template="Anonymous FTP authentication from {group}",
        explanation_template=_explain(
            "Anonymous FTP authentication from {group}: {count} events between "
            "{first} and {last}. Threshold {threshold} in a {window_seconds}-second "
            "{window_type} window (analyst severity {severity}). "
            "Anonymous FTP is unexpected by rule policy."
        ),
        required_attributes=("event_timestamp", "component", "event_id", "source_ip", "username"),
        source_address_from_group=True,
        event_ids=("E9",),
        components=("ftpd",),
        usernames=("anonymous",),
    ),
    BuiltinRule(
        name="repeated-service-failure",
        description=(
            "Repeated logrotate failures. Template E8 (ALERT exited abnormally "
            "with [1]), grouped by component, tumbling 7-day window (604800 seconds, "
            "epoch-aligned), threshold 7. On Linux_2k this is one abnormal exit per "
            "day; a full week of daily failures meets the threshold. The partial "
            "week that contains only 15 Jun 2005 does not."
        ),
        severity="low",
        threshold=7,
        window_seconds=604800,
        window_type="tumbling",
        group_by="component",
        title_template="Repeated service failures in {group}",
        explanation_template=_explain(
            "Repeated service failures in {group}: {count} abnormal exits between "
            "{first} and {last}. Threshold {threshold} in a {window_seconds}-second "
            "{window_type} window (analyst severity {severity})."
        ),
        required_attributes=("event_timestamp", "component", "event_id"),
        source_address_from_group=False,
        event_ids=("E8",),
        components=("logrotate",),
        content_contains="ALERT exited abnormally",
    ),
    BuiltinRule(
        name="unusual-session-sequence",
        description=(
            "Unusual user-session sequences. Session opened/closed templates E101, "
            "E102, and E103, grouped by username, sliding 60 seconds, threshold 6. "
            "A single session on this file is one open and one close (2 events). "
            "Six or more session records for the same user inside 60 seconds is the "
            "unusual sequence. Daily su to cyrus and news is two events and does "
            "not alert. The bursts that meet the threshold are sshd sessions for "
            "user test."
        ),
        severity="medium",
        threshold=6,
        window_seconds=60,
        window_type="sliding",
        group_by="username",
        title_template="Unusual session sequence for user {group}",
        explanation_template=_explain(
            "Unusual session sequence for user {group}: {count} session open/close "
            "events between {first} and {last}. Threshold {threshold} in a "
            "{window_seconds}-second {window_type} window (analyst severity {severity})."
        ),
        required_attributes=("event_timestamp", "username", "event_id"),
        source_address_from_group=False,
        event_ids=("E101", "E102", "E103"),
    ),
    BuiltinRule(
        name="event-frequency-spike",
        description=(
            "Unusual per-component event frequency. Every timestamped event, grouped "
            "by syslog component, tumbling 60 seconds, threshold 30. The busiest "
            "routine FTP minute on Linux_2k is 25 connections, so 30 sits above that "
            "background. It flags three minutes: kernel startup on 27 Jul (72 lines), "
            "a klogind cluster on 30 Jun (46), and an sshd cluster on 10 Jul (46). "
            "Operational noise can trip this rule."
        ),
        severity="medium",
        threshold=30,
        window_seconds=60,
        window_type="tumbling",
        group_by="component",
        title_template="Event frequency spike in {group}",
        explanation_template=_explain(
            "Event frequency spike in {group}: {count} events between {first} and "
            "{last}. Threshold {threshold} in a {window_seconds}-second {window_type} "
            "window (analyst severity {severity})."
        ),
        required_attributes=("event_timestamp", "component"),
        source_address_from_group=False,
    ),
)


BUILTIN_BY_NAME: dict[str, BuiltinRule] = {rule.name: rule for rule in BUILTIN_RULES}
