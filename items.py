import re
import os
nginx_cert_dir = os.getcwd() + "/data/nginx/etc/ssl"
nginx_extras_dir = os.getcwd() + "/data/nginx/etc/nginx/extras"

pkg_dnf = {
    'nginx': {},
}

svc_systemd = {
    'nginx': {
        'enabled': True,
        'needs': [
            'action:generate_dhparam',
            'pkg_dnf:nginx',
        ],
    },
}

directories = {
    "/var/www": {
        "mode": "0755",
        "owner": "nginx",
        "group": "nginx",
        'needs': [
            "pkg_dnf:nginx",
        ],
    },
    "/etc/nginx/global": {
        "mode": "0644",
        "owner": "root",
        "group": "root",
        'needs': [
            "pkg_dnf:nginx",
        ],
    },
    "/etc/nginx/generic": {
        "mode": "0644",
        "owner": "root",
        "group": "root",
        'needs': [
            "pkg_dnf:nginx",
        ],
    },
    "/etc/nginx/extras": {
        "mode": "0644",
        "owner": "root",
        "group": "root",
        'needs': [
            "pkg_dnf:nginx",
        ],
    },
}

actions = {
    'generate_dhparam': {
        'command': "openssl dhparam -out /etc/ssl/dhparams.pem 4096",
        'unless': "test -f /etc/ssl/dhparams.pem",
        'cascade_skip': False,
        'needs': [
            "pkg_dnf:openssl",
        ],
    },
}

files = {
    '/etc/nginx/nginx.conf': {
        'source': "nginx.conf",
        'owner': "root",
        'group': "root",
        'mode': "0644",
        'content_type': "mako",
        'needs': [
            "pkg_dnf:nginx",
        ],
        'triggers': [
            "svc_systemd:nginx:restart",
        ],
    },
    '/etc/nginx/conf.d/ssl.conf': {
        'source': "ssl.conf",
        'owner': "root",
        'group': "root",
        'mode': "0644",
        'needs': [
            "pkg_dnf:nginx",
        ],
        'triggers': [
            "svc_systemd:nginx:restart",
        ],
    },
    '/etc/nginx/conf.d/status.conf': {
        'source': "status",
        'mode': "0644",
        'owner': "root",
        'group': "root",
        'triggers': [
            "svc_systemd:nginx:restart",
        ],
        'needs': [
            "pkg_dnf:nginx",
        ],
    },
    '/etc/nginx/global/fpm.conf': {
        'source': "fpm.conf",
        'owner': "root",
        'group': "root",
        'mode': "0644",
        'needs': [
            "pkg_dnf:nginx",
        ],
        'triggers': [
            "svc_systemd:nginx:restart",
        ],
    },
    '/etc/nginx/global/restrictions.conf': {
        'source': "restrictions.conf",
        'owner': "root",
        'group': "root",
        'mode': "0644",
        'needs': [
            "pkg_dnf:nginx",
        ],
        'triggers': [
            "svc_systemd:nginx:restart",
        ],
    },
    '/etc/logrotate.d/nginx': {
        'source': 'logrotate',
        'owner': 'root',
        'group': 'root',
        'mode': '0644',
        'content_type': 'mako',
    },
}

for vhost_name, vhost in sorted(node.metadata['nginx']['vhosts'].items()):
    wwwdir_user = vhost.get("wwwdir_user", "root")
    wwwdir_group = vhost.get("wwwdir_group", "root")
    wwwdir_mode = vhost.get("wwwdir_mode", "0755")
    domain = vhost.get("domain", vhost_name)

    directories['/var/www/{}'.format(vhost_name)] = {
        'owner': wwwdir_user,
        'group': wwwdir_group,
        'mode': wwwdir_mode,
    }
    directories['/var/www/{}/htdocs'.format(vhost_name)] = {
        'owner': wwwdir_user,
        'group': wwwdir_group,
        'mode': wwwdir_mode,
    }
    directories['/var/www/{}/logs'.format(vhost_name)] = {
        'owner': wwwdir_user,
        'group': wwwdir_group,
        'mode': wwwdir_mode,
    }

    files['/etc/nginx/conf.d/vhost_{}.conf'.format(vhost_name)] = {
        'content_type': 'mako',
        'source': "vhost_template",
        'owner': "root",
        'group': "root",
        'mode': "0644",
        'context': {
            'vhost': vhost,
            'vhost_name': vhost_name,
        },
        'needs': [
            "pkg_dnf:nginx",
        ],
        'triggers': [
            "svc_systemd:nginx:reload",
        ],
    }

    if 'letsencrypt' in vhost:
        directories['/var/www/{}/.well_known'.format(vhost_name)] = {
            'owner': wwwdir_user,
            'group': wwwdir_group,
            'mode': wwwdir_mode,
        }

        files['/opt/dehydrated/config_{}'.format(vhost_name)] = {
            'content_type': 'mako',
            'source': "dehydrated_config_template",
            'owner': "root",
            'group': "root",
            'mode': "0644",
            'context': {
                'vhost': vhost,
                'vhost_name': vhost_name,
            },
            'needs': [
                "git_deploy:/opt/dehydrated",
            ],
        }

        files['/etc/cron.d/dehydrated_{}'.format(vhost_name)] = {
            'content_type': 'mako',
            'source': "dehydrated_cron_template",
            'owner': "root",
            'group': "root",
            'mode': "0644",
            'context': {
                'vhost': vhost,
                'vhost_name': vhost_name,
                'domain': domain,
            },
            'needs': [
                "git_deploy:/opt/dehydrated",
            ],
        }

        files['/opt/dehydrated/hook.sh'] = {
            'source': "dehydrated_hook",
            'owner': "root",
            'group': "root",
            'mode': "0744",
            'needs': [
                "git_deploy:/opt/dehydrated",
            ],
        }

        if vhost.get('letsencrypt', {}).get('bootstrap', False):

            actions['nginx_letsencrypt_initial_request_{}'.format(domain)] = {
                'command': "/opt/dehydrated/dehydrated -c -d {} -f /opt/dehydrated/config_{}".format(domain, vhost_name),
                'cascade_skip': False,
                'needs': [
                    "pkg_dnf:nginx",
                    "git_deploy:/opt/dehydrated",
                ],
            }

    if not 'letsencrypt' in vhost:

        files['/etc/ssl/{}.crt'.format(vhost_name)] = {
            'content_type': 'mako',
            'source': "{}/{}.{}.crt".format(nginx_cert_dir, node.name, vhost_name),
            'owner': "root",
            'group': "root",
            'mode': "0644",
            'triggers': [
                "svc_systemd:nginx:reload",
            ],
        }

        files['/etc/ssl/private/{}.key'.format(vhost_name)] = {
            'content_type': 'mako',
            'source': "{}/{}.{}.key".format(nginx_cert_dir, node.name, vhost_name),
            'owner': "root",
            'group': "root",
            'mode': "0600",
            'triggers': [
                "svc_systemd:nginx:reload",
            ],
        }

    if 'generic' in vhost:
        files['/etc/nginx/generic/{}'.format(vhost['generic'])] = {
            'content_type': 'text',
            'source': "generic/{}".format(vhost['generic']),
            'owner': "root",
            'group': "root",
            'mode': "0644",
            'needs': [
                "pkg_dnf:nginx",
            ],
            'triggers': [
                "svc_systemd:nginx:reload",
            ],
        }

    if 'extras' in vhost:
        files['/etc/nginx/extras/{}'.format(vhost_name)] = {
            'content_type': 'text',
            'source': "{}/{}.{}".format(nginx_extras_dir, node.name, vhost_name),
            'owner': "root",
            'group': "root",
            'mode': "0644",
            'needs': [
                "pkg_dnf:nginx",
            ],
            'triggers': [
                "svc_systemd:nginx:reload",
            ],
        }

    for (_, basic_auth) in vhost.get('basic_auth', {}).items():
        htpasswd_suffix = re.sub('[^a-zA-Z0-9_-]', '', basic_auth['name'])

        files['/var/www/{}/.htpasswd-{}'.format(vhost_name, htpasswd_suffix)] = {
            'source': "htpasswd",
            'content_type': 'mako',
            'owner': "root",
            'group': node.metadata['nginx'].get('user', 'nginx'),
            'mode': "0640",
            'context': {
                'basic_auth': basic_auth,
            },
        }

    if node.has_bundle("monit"):
        files['/etc/monit.d/nginx'] = {
            'source': "monit",
            'mode': "0640",
            'owner': "root",
            'group': "root",
            'content_type': "mako",
            'context': {
                'vhost': vhost,
                'vhost_name': vhost_name,
                'domain': domain,
            },
            'triggers': [
                "svc_systemd:monit:restart",
            ],
        }

    if node.has_bundle("collectd") and 'fpm_proxy' in vhost:
        files['/etc/collectd.d/php-fpm_{}.conf'.format(vhost_name)] = {
            'source': "collectd_php-fpm_template.conf",
            'mode': "0640",
            'owner': "root",
            'group': "root",
            'content_type': "mako",
            'context': {
                'vhost': vhost,
                'vhost_name': vhost_name,
                'domain': domain,
            },
            'triggers': [
                "svc_systemd:collectd:restart",
            ],
        }

if node.has_bundle("firewalld"):
    if node.metadata.get('nginx', {}).get('firewalld_permitted_zones'):
        for zone in node.metadata.get('nginx', {}).get('firewalld_permitted_zones'):
            actions['firewalld_add_https_zone_{}'.format(zone)] = {
                'command': "firewall-cmd --permanent --zone={} --add-service=http --add-service=https".format(zone),
                'unless': "firewall-cmd --zone={} --list-services | grep https".format(zone),
                'cascade_skip': False,
                'needs': [
                    "pkg_dnf:firewalld",
                ],
                'triggers': [
                    "action:firewalld_reload",
                ],
            }
    elif node.metadata.get('firewalld', {}).get('default_zone'):
        default_zone = node.metadata.get('firewalld', {}).get('default_zone')
        actions['firewalld_add_https_zone_{}'.format(default_zone)] = {
            'command': "firewall-cmd --permanent --zone={} --add-service=http --add-service=https".format(default_zone),
            'unless': "firewall-cmd --zone={} --list-services | grep https".format(default_zone),
            'cascade_skip': False,
            'needs': [
                "pkg_dnf:firewalld",
            ],
            'triggers': [
                "action:firewalld_reload",
            ],
        }
    elif node.metadata.get('firewalld', {}).get('custom_zones', False):
        for interface in node.metadata['interfaces']:
            custom_zone = node.metadata.get('interfaces', {}).get(interface).get('firewalld_zone')
            actions['firewalld_add_https_zone_{}'.format(custom_zone)] = {
                'command': "firewall-cmd --permanent --zone={} --add-service=http --add-service=https".format(custom_zone),
                'unless': "firewall-cmd --zone={} --list-services | grep https".format(custom_zone),
                'cascade_skip': False,
                'needs': [
                    "pkg_dnf:firewalld",
                ],
                'triggers': [
                    "action:firewalld_reload",
                ],
            }
    else:
        actions['firewalld_add_https'] = {
            'command': "firewall-cmd --permanent --add-service=http --add-service=https",
            'unless': "firewall-cmd --list-services | grep https",
            'cascade_skip': False,
            'needs': [
                "pkg_dnf:firewalld",
            ],
            'triggers': [
                "action:firewalld_reload",
            ],
        }

if node.has_bundle("collectd"):

    pkg_dnf['collectd-nginx'] = {}

    files['/etc/collectd.d/nginx.conf'] = {
        'source': "collectd_nginx.conf",
        'mode': "0640",
        'owner': "root",
        'group': "root",
        'needs': [
            "pkg_dnf:collectd-nginx",
        ],
        'triggers': [
            "svc_systemd:collectd:restart",
        ],
    }

    files['/etc/collectd.d/php-fpm.conf'] = {
        'source': "collectd_php-fpm.conf",
        'mode': "0640",
        'owner': "root",
        'group': "root",
        'needs': [
            "pkg_dnf:collectd-nginx",
        ],
        'triggers': [
            "svc_systemd:collectd:restart",
        ],
    }

    files['/etc/collectd.d/types/php-fpm.db'] = {
        'source': "collectd_php-fpm.types",
        'mode': "0640",
        'owner': "root",
        'group': "root",
        'triggers': [
            "svc_systemd:collectd:restart",
        ],
    }
