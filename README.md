## JASMIN Jupyterhub Authenticator
This is an authenticator for jupyterhub which first uses oauth2 to authenticate a user, then get's the users POSIX groups from LDAP so their container may spawn with the correct permissions.

Used as part of the deployment of the [JASMIN Notebook Service](https://help.jasmin.ac.uk/docs/interactive-computing/jasmin-notebooks-service/)
