"""Offloaded authentication.

An account with ``auth_mode = external`` has no password here; a
provider answers for it. Three are implemented -- LDAP, an HTTP
webhook, and OAuth2/OIDC token validation. RADIUS appears in the
schema's comment and is deliberately not built: it is vanishingly rare
for mail, and a half-built one is worse than an absent one.

Everything goes through ``lightr.auth.Authenticator``, which is the
single path SMTP submission, the REST API, and Dovecot's passdb all
share -- so a provider configured once works for IMAP without any
further wiring.
"""

from lightr.authproviders.base import (
    DEFAULT_TIMEOUT,
    Identity,
    Provider,
    ProviderConfigError,
    ProviderError,
    redact,
)
from lightr.authproviders.ldap import LDAPProvider
from lightr.authproviders.oidc import OIDCProvider
from lightr.authproviders.registry import (
    KINDS,
    AuthProviderRepo,
    Outcome,
    ProviderRecord,
    authenticate,
    providers_for,
)
from lightr.authproviders.webhook import WebhookProvider

__all__ = [
    "DEFAULT_TIMEOUT",
    "KINDS",
    "AuthProviderRepo",
    "Identity",
    "LDAPProvider",
    "OIDCProvider",
    "Outcome",
    "Provider",
    "ProviderConfigError",
    "ProviderError",
    "ProviderRecord",
    "WebhookProvider",
    "authenticate",
    "providers_for",
    "redact",
]
