"""
Vitorius Firewall - Polymorphic OS Personality Morphing
Randomizes and scrambles service banners and protocol responses across ports
to present contradictory fingerprints to automated reconnaissance engines (Nmap, Shodan, Nessus),
rendering automated exploit frameworks unable to determine the true host OS.
"""

import random
import logging

logger = logging.getLogger('vitorius.honeypot.morph')


class OSMorpher:
    """Manages polymorphic deception personas and banner scramblers."""

    PERSONAS = {
        'fedora': {
            'ssh': 'SSH-2.0-OpenSSH_9.6p1 Fedora-2024',
            'http': 'Apache/2.4.58 (Fedora Linux) OpenSSL/3.2.0',
            'telnet': 'Fedora Linux 41 (Server Edition) - Kernel 6.11.4-200.fc41.x86_64',
            'ftp': 'vsftpd 3.0.5 (Fedora Linux)',
            'smtp': 'mail.fedora-infra.local ESMTP Postfix',
        },
        'windows_server': {
            'ssh': 'SSH-2.0-OpenSSH_for_Windows_8.9p1',
            'http': 'Microsoft-IIS/10.0',
            'telnet': 'Microsoft Telnet Service - Windows Server 2022 Datacenter',
            'ftp': 'Microsoft FTP Service',
            'smtp': 'Microsoft ESMTP MAIL Service ready',
        },
        'freebsd': {
            'ssh': 'SSH-2.0-OpenSSH_9.5p1 FreeBSD-20231004',
            'http': 'nginx/1.24.0 (FreeBSD)',
            'telnet': 'FreeBSD 14.0-RELEASE (GENERIC)',
            'ftp': 'ProFTPD 1.3.8b Server (FreeBSD)',
            'smtp': 'mail.freebsd-relay.net ESMTP Sendmail 8.17.1/8.17.1',
        },
        'cisco': {
            'ssh': 'SSH-2.0-Cisco-1.25',
            'http': 'cisco-IOS',
            'telnet': 'User Access Verification - Cisco IOS-XE Software, Version 17.06.03',
            'ftp': 'Cisco IOS FTP server ready',
            'smtp': 'Cisco IronPort ESMTP',
        }
    }

    def __init__(self, mode: str = 'polymorphic'):
        self.mode = mode

    def get_banner(self, service: str) -> str:
        """
        Returns a service banner. In 'polymorphic' mode, deliberate contradictions are injected
        across ports (e.g. SSH claims Fedora, HTTP claims Windows IIS, FTP claims FreeBSD)
        so automated scanners cannot converge on a single exploit target.
        """
        if self.mode == 'polymorphic':
            # Assign conflicting personalities per service
            service_mapping = {
                'ssh': 'fedora',
                'http': 'windows_server',
                'telnet': 'cisco',
                'ftp': 'freebsd',
                'smtp': 'fedora',
                'vnc': 'freebsd',
            }
            persona_key = service_mapping.get(service, random.choice(list(self.PERSONAS.keys())))
        else:
            persona_key = self.mode if self.mode in self.PERSONAS else 'fedora'

        persona = self.PERSONAS.get(persona_key, self.PERSONAS['fedora'])
        return persona.get(service, persona.get('ssh', ''))
