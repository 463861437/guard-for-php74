# -*- coding: utf-8 -*-
"""Supported routes, derived from the same policies used during repair."""


def platform_support():
    repositories = []
    for rule in POLICY.get('entries', []):
        if rule['branch'] != '7.4':
            continue
        repositories.append(dict(os_id=rule['os_id'], os_version=rule['os_version'],
            source=rule['source_package'], channel=rule['channel'], minimum=rule['min_version'],
            architecture='matching installed architecture available in authenticated repository'))
    remi = globals().get('RP_REMI_POLICY', {})
    return dict(version=VERSION, cves=CVES, repository_routes=repositories,
        remi_repository_route=dict(os_ids=remi.get('supported_os_ids', []),
            os_majors=remi.get('supported_os_majors', []), sources=remi.get('sources', []),
            architectures=remi.get('supported_architectures', []), minimum_revision=31,
            requirement='existing same-vendor Remi PHP 7.4 packages; pinned RPM signatures'),
        local_source_routes=[
            dict(os_id='amzn', os_version='2', architecture='x86_64', baseline='php 7.4.33-1.amzn2'),
            dict(os_ids=['centos', 'rhel'], os_major='7', architecture='x86_64', baseline='php 7.4.33-15.el7.remi'),
            dict(os_ids=['centos', 'rhel'], os_major='7', architecture='x86_64',
                 baseline='php / php82-php 8.2.20-1.el7.remi', target='8.2.35',
                 layouts=['system: /usr, /etc/php*', 'scl: /opt/remi/php82, /etc/opt/remi/php82'],
                 source='PHP official signed source + pinned Remi EL7 packaging'),
            dict(os_id='ubuntu', os_version='20.04', architecture='amd64', baseline='Ondrej PPA php7.4 1:7.4.33-*+ubuntu20.04.1+deb.sury.org+*')],
        detection_only=['apk', 'pacman', 'zypper', 'unmanaged source builds', 'panel PHP', 'container PHP'],
        conditions=['does not enable repositories or migrate package vendors',
                    'complete same-branch package set and service preflight required',
                    'local source builds require tests to pass before installation',
                    'support describes implemented routes, not completed business acceptance on every OS'])
