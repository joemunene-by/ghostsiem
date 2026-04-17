"""Built-in detection rules for GhostSIEM.

These rules are provided as YAML strings in SIGMA format and loaded
by the detection engine when no external rules directory is configured.
"""

from __future__ import annotations

from ghostsiem.detection.rule import Rule
from ghostsiem.detection.sigma_loader import load_sigma_rule

FAILED_SSH_LOGIN = """
title: Failed SSH Login
id: gs-001
status: stable
description: Detects failed SSH login attempts indicating potential unauthorized access.
author: GhostSIEM
logsource:
    product: linux
    service: auth
level: high
detection:
    selection:
        message|contains: "Failed password"
    condition: selection
tags:
    - attack.initial_access
    - attack.t1078
"""

SSH_BRUTE_FORCE = """
title: SSH Brute Force Attempt
id: gs-002
status: stable
description: >-
  Detects 5+ failed SSH logins from same IP in 60s, indicating brute force.
author: GhostSIEM
logsource:
    product: linux
    service: auth
level: critical
detection:
    selection:
        message|contains: "Failed password"
    threshold:
        field: src_ip
        value: 5
    timeframe: "60s"
    condition: selection
tags:
    - attack.credential_access
    - attack.t1110.001
"""

SSH_LOGIN_UNUSUAL_SOURCE = """
title: SSH Login From Unusual Source
id: gs-003
status: experimental
description: Detects successful SSH logins which may originate from unusual or external sources.
author: GhostSIEM
logsource:
    product: linux
    service: auth
level: medium
detection:
    selection:
        message|contains: "Accepted"
    condition: selection
tags:
    - attack.initial_access
    - attack.t1078
"""

SUDO_COMMAND = """
title: Sudo Command Executed
id: gs-004
status: stable
description: Detects execution of commands via sudo, which may indicate privilege escalation.
author: GhostSIEM
logsource:
    product: linux
    service: auth
level: medium
detection:
    selection:
        message|contains: "COMMAND="
    filter:
        message|contains: "pam_unix"
    condition: selection and not filter
tags:
    - attack.privilege_escalation
    - attack.t1548.003
"""

NEW_USER_CREATED = """
title: New User Account Created
id: gs-005
status: stable
description: Detects creation of new user accounts via useradd or adduser.
author: GhostSIEM
logsource:
    product: linux
    service: auth
level: high
detection:
    selection_useradd:
        message|contains: "useradd"
    selection_adduser:
        message|contains: "adduser"
    selection_newuser:
        message|contains: "new user"
    condition: 1 of selection*
tags:
    - attack.persistence
    - attack.t1136.001
"""

SERVICE_STATE_CHANGE = """
title: Service Started or Stopped
id: gs-006
status: stable
description: Detects system service state changes which may indicate tampering or maintenance.
author: GhostSIEM
logsource:
    product: linux
    service: syslog
level: low
detection:
    selection_started:
        message|contains: "Started"
    selection_stopped:
        message|contains: "Stopped"
    selection_systemctl:
        message|contains: "systemctl"
    condition: 1 of selection*
tags:
    - attack.defense_evasion
    - attack.t1562.001
"""

FIREWALL_RULE_CHANGE = """
title: Firewall Rule Change Detected
id: gs-007
status: stable
description: Detects modifications to firewall rules via iptables or ufw.
author: GhostSIEM
logsource:
    product: linux
    service: syslog
level: high
detection:
    selection_iptables:
        message|contains: "iptables"
    selection_ufw:
        message|contains: "ufw"
    filter_status:
        message|contains: "STATUS"
    condition: 1 of selection* and not filter_status
tags:
    - attack.defense_evasion
    - attack.t1562.004
"""

LARGE_OUTBOUND_TRANSFER = """
title: Large Outbound Data Transfer Indicator
id: gs-008
status: experimental
description: >-
  Detects log entries indicating large outbound transfers, potential exfil.
author: GhostSIEM
logsource:
    product: linux
    service: syslog
level: high
detection:
    selection_scp:
        message|contains: "scp"
    selection_rsync:
        message|contains: "rsync"
    selection_curl_upload:
        message|contains: "curl"
    selection_wget:
        message|contains: "wget"
    condition: 1 of selection*
tags:
    - attack.exfiltration
    - attack.t1048
"""

ALL_BUILTIN_RULES_YAML: list[str] = [
    FAILED_SSH_LOGIN,
    SSH_BRUTE_FORCE,
    SSH_LOGIN_UNUSUAL_SOURCE,
    SUDO_COMMAND,
    NEW_USER_CREATED,
    SERVICE_STATE_CHANGE,
    FIREWALL_RULE_CHANGE,
    LARGE_OUTBOUND_TRANSFER,
]


def load_builtin_rules() -> list[Rule]:
    """Load all built-in detection rules.

    Returns:
        List of Rule objects for all built-in rules.
    """
    rules: list[Rule] = []
    for yaml_str in ALL_BUILTIN_RULES_YAML:
        rule = load_sigma_rule(yaml_str)
        rules.append(rule)
    return rules
