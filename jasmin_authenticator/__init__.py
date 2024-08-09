"""JupyterHub authenticator implementation for the JASMIN notebook service."""

from functools import reduce

import ldap3
import traitlets
from jasmin_ldap import AuthenticationError, Connection, F, Query, ServerPool
from jupyterhub.auth import Authenticator
from ldap3.utils.conv import escape_filter_chars
from oauthenticator.generic import GenericOAuthenticator


class NotAPosixUserError(RuntimeError):
    pass


class JASMINAuthenticator(GenericOAuthenticator):
    """
    JupyterHub authenticator that performs an OAuth2 authentication with the JASMIN
    Accounts Portal before reading POSIX information for the user from LDAP.
    """

    addresses = traitlets.List(
        traitlets.Unicode(),
        config=True,
        minlen=1,
        help="List of LDAP server addresses.",
    )

    bind_dn = traitlets.Unicode(
        config=True,
        allow_none=True,
        default=None,
        help="""
        DN to use for administrative operations, i.e. everything except user authentication.

        Leave blank for anonymous bind.
        """,
    )

    bind_password = traitlets.Unicode(
        config=True,
        allow_none=True,
        default=None,
        help="""
        Password used to bind for administrative operations.

        Leave blank for anonymous bind.
        """,
    )

    user_dn_template = traitlets.Unicode(
        config=True,
        help="""
        Template for the DN to use when authenticating a user with LDAP.
        `{username}` is replaced with the given username.

        If possible, this is quicker than using searching for the DN.
        """,
    )

    allowed_user_filters = traitlets.List(
        config=True,
        allow_none=True,
        default=None,
        help="""
        List of filters to apply when searching for users, where each item is a dict
        with keys and values in the format understood by the keyword arguments of
        `jasmin_ldap.Query.filter`.

        The reason this is a list of dicts rather than a single dict is because you
        may need to reuse keys.

        E.g.:

        ```py
        allowed_user_filters = [
            { 'objectClass': 'posixAccount', 'description': 'cluster:jasmin-login' },
            { 'description': 'cluster:jasmin-notebooks', 'uid__startswith': 'mp' },
        ]
        ```

        If no filters are given, any user that can authenticate will be permitted.
        Multiple filters are combined using "and".
        """,
    )

    allowed_groups = traitlets.List(
        config=True,
        allow_none=True,
        default=None,
        help="""
        List of LDAP group DNs for which members should be granted access.

        If not given, then all users that can authenticate will be permitted.
        """,
    )

    admin_groups = traitlets.List(
        config=True,
        allow_none=True,
        default=None,
        help="""
        List of LDAP group DNs for which members should be granted admin status.
        Members of these groups are also granted regular access (see `allowed_groups`).

        Set to an empty list or None to use the admin whitelist only.
        """,
    )

    posix_group_search_base = traitlets.Unicode(
        config=True,
        allow_none=True,
        default=None,
        help="Search base for POSIX group memberships.",
    )

    def _connect(self, bind_dn=None, bind_password=None):
        """
        Attempt create a connection with the given settings.

        The DN and password for bind can be overridden by the given arguments.
        """
        addresses = [ldap3.Server(host=x) for x in self.addresses]
        return Connection.create(
            # We only need a read-only connection, so create a pool with replicas only
            ServerPool(replicas=addresses),
            user=bind_dn or self.bind_dn,
            password=bind_password if bind_dn else self.bind_password,
        )

    def _user_in_group(self, conn, group_dn, user_dn, username):
        return bool(
            Query(conn, group_dn, scope=Query.SCOPE_ENTITY)
            .filter(F(member=user_dn) | F(uniqueMember=user_dn) | F(memberUid=username))
            .one()
        )

    async def authenticate(self, handler, data):
        # First, do the OAuth login and get the username
        user_data = await super().authenticate(handler, data)
        username = user_data["name"]
        self.log.debug("[%s] User authenticated via OAuth", username)

        # Construct the user's LDAP DN
        user_dn = self.user_dn_template.format(username=escape_filter_chars(username))
        self.log.debug("[%s] Using LDAP DN '%s'", username, user_dn)

        with self._connect() as conn:
            # Check that the user matches the given filters, if given
            if self.allowed_user_filters:
                self.log.debug("[%s] Checking user matches required filters", username)
                # Create a query with the allowed filters
                query = reduce(
                    lambda query, filters: query.filter(**filters),
                    self.allowed_user_filters,
                    Query(conn, user_dn, scope=Query.SCOPE_ENTITY),
                )
                if not query.one():
                    self.log.warning(
                        "[%s] User does not match required filters", username
                    )
                    return None

            # Check that the user matches a group, if given
            if self.allowed_groups:
                self.log.debug("[%s] Checking if user is in an allowed group", username)
                # Admin groups are also permitted
                allowed_groups = list(self.allowed_groups or [])
                allowed_groups.extend(self.admin_groups or [])
                for group_dn in allowed_groups:
                    self.log.debug(
                        "[%s] Checking if user is in group %s", username, group_dn
                    )
                    if self._user_in_group(conn, group_dn, user_dn, username):
                        self.log.debug("[%s] User is in group %s", username, group_dn)
                        break
                else:
                    self.log.warning(
                        "[%s] User does not belong to any allowed groups", username
                    )
                    return None

        # If we get to this point, the user is authenticated
        return username

    def is_admin(self, handler, authentication):
        # If the user is already an admin by the whitelist, there is nothing to do
        if super().is_admin(handler, authentication):
            return True

        # If there are no admin groups, we are done
        if not self.admin_groups:
            self.log.info("No admin groups defined")
            return False

        # Form the user's DN from the username
        username = authentication["name"]
        user_dn = self.user_dn_template.format(username=escape_filter_chars(username))
        # Check if the user is in any admin groups
        with self._connect() as conn:
            self.log.debug("[%s] Checking if user is in an admin group", username)
            for group_dn in self.admin_groups:
                self.log.debug(
                    "[%s] Checking if user is in group %s", username, group_dn
                )
                if self._user_in_group(conn, group_dn, user_dn, username):
                    self.log.debug("[%s] User is in group %s", username, group_dn)
                    return True
        self.log.info("[%s] User does not belong to any admin groups", username)
        return False

    def pre_spawn_start(self, user, spawner):
        # Form the user's DN from the username
        username = user.name
        user_dn = self.user_dn_template.format(username=escape_filter_chars(username))
        with self._connect() as conn:
            # Fetch the user's UID, GID and homeDirectory from LDAP
            self.log.debug("[%s] Fetching POSIX user information", username)
            user = (
                Query(conn, user_dn, scope=Query.SCOPE_ENTITY)
                .filter(objectClass="posixAccount")
                .one()
            )
            if not user:
                self.log.error("[%s] User has no POSIX information", username)
                raise NotAPosixUserError("User is not a POSIX user")
            uid = user["uidNumber"][0]
            gid = user["gidNumber"][0]
            home_directory = user["homeDirectory"][0]
            self.log.debug("[%s] Found UID %d, GID %d", username, uid, gid)
            self.log.debug("[%s] Using home directory %s", username, home_directory)
            # Set values on the spawner
            spawner.uid = uid
            spawner.gid = gid
            spawner.fs_gid = None
            # Use the user's home directory as the working directory
            spawner.working_dir = home_directory
            # Also set the $HOME environment variable correctly
            spawner.environment["HOME"] = home_directory
            # Find the user's additional groups
            self.log.debug("[%s] Fetching additional POSIX groups", username)
            groups = (
                Query(conn, self.posix_group_search_base)
                .filter(objectClass="posixGroup")
                .filter(
                    F(member=user_dn) | F(uniqueMember=user_dn) | F(memberUid=username)
                )
                .exclude(gidNumber=gid)
            )
            self.log.debug("[%s} Found %d POSIX groups", username, len(groups))
            # It is important to include group 100 in the groups, as this has
            # special meaning in the notebook image
            spawner.supplemental_gids = [100] + [
                group["gidNumber"][0] for group in groups
            ]
