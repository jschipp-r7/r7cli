"""Platform solution commands — validate, search, users, orgs, roles, api-keys, credentials."""
from __future__ import annotations

import click
from r7cli.cli_group import GlobalFlagHintGroup

from r7cli.client import R7Client
from r7cli.helpers import (
    auto_poll_options,
    data_body_options,
    emit,
    get_config,
    handle_errors,
    poll_loop,
    resolve_body,
)
from r7cli.models import (
    INSIGHT_BASE,
    IDR_V1_BASE,
    ACCOUNT_BASE,
    CREDMGMT_BASE,
    VALID_SEARCH_TYPES,
    R7Error,
    UserInputError,
)


_ACCT_DOC = "https://help.rapid7.com/insightAccount/en-us/api/v1/docs.html"
_CRED_DOC = "https://help.rapid7.com/credentialmanagement/en-us/api/v1/docs.html"


@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def platform(ctx):
    """Platform-level commands (validate, search, users, orgs, credentials, assets, extensions)."""
    pass


# Register cross-cutting subcommands under platform
def _register_platform_subgroups():
    from r7cli.agents import agents as assets_group
    from r7cli.extensions import extensions as extensions_group
    from r7cli.compliance import compliance as compliance_cmd
    from r7cli.matrix import matrix as matrix_group
    from r7cli.status import status as status_cmd
    platform.add_command(assets_group, "assets")
    platform.add_command(extensions_group, "extensions")
    platform.add_command(compliance_cmd, "compliance")
    platform.add_command(matrix_group, "matrix")
    platform.add_command(status_cmd, "status")

_register_platform_subgroups()


@platform.command()
@click.pass_context
def validate(ctx):
    """Validate API key (and DRP token if provided) against the Insight Platform."""
    from r7cli.models import DRP_BASE, APIError
    import sys

    config = get_config(ctx)
    client = R7Client(config)

    # --- Validate API key ---
    if config.api_key:
        url = INSIGHT_BASE.format(region=config.region) + "/validate"
        try:
            result = client.get(url, solution="platform", subcommand="validate")
            emit(result, config)
        except R7Error as exc:
            click.echo(str(exc), err=True)
            sys.exit(exc.exit_code)
    else:
        click.echo("No API key provided — skipping platform validation.", err=True)

    # --- Validate DRP token if provided ---
    if config.drp_token:
        token = config.drp_token
        if ":" in token:
            parts = token.split(":", 1)
            auth = (parts[0], parts[1])
        else:
            auth = (token, "")
        drp_url = f"{DRP_BASE}/public/v1/test-credentials"
        try:
            client.head(drp_url, auth=auth, solution="drp", subcommand="validate")
            click.echo("DRP credentials valid")
        except APIError as exc:
            if exc.status_code == 401:
                click.echo("DRP credentials invalid", err=True)
                sys.exit(1)
            click.echo(str(exc), err=True)
            sys.exit(exc.exit_code)


@platform.command()
@click.option("-t", "--type", "search_type", required=True,
              help="Search type: VULNERABILITY, ASSET, SCAN, SCHEDULE, APP.")
@click.option("-q", "--query", "query", required=True, help="Search query string.")
@click.option("--sort-field", default=None, help="Field to sort results by.")
@click.option("--sort-order", default=None, help="Sort order: asc or desc.")
@click.option("--from", "from_", type=int, default=0, help="Result offset (default: 0).")
@click.option("--size", type=int, default=100, help="Number of results (default: 100).")
@click.pass_context
@handle_errors
def search(ctx, search_type, query, sort_field, sort_order, from_, size):
    """Search the Insight Platform (IDR v1 search endpoint)."""
    config = get_config(ctx)

    if search_type not in VALID_SEARCH_TYPES:
        valid = ", ".join(sorted(VALID_SEARCH_TYPES))
        raise click.ClickException(
            f"Invalid search type '{search_type}'. Valid types: {valid}"
        )

    client = R7Client(config)
    url = IDR_V1_BASE.format(region=config.region) + "/search"

    payload: dict = {
        "type": search_type,
        "query": query,
        "from": from_,
        "size": size,
    }
    if sort_field:
        payload["sort_field"] = sort_field
    if sort_order:
        payload["sort_order"] = sort_order

    result = client.post(url, json=payload, solution="platform", subcommand="search")
    emit(result, config)


# ---------------------------------------------------------------------------
# platform users
# ---------------------------------------------------------------------------

@platform.group(cls=GlobalFlagHintGroup)
@click.pass_context
def users(ctx):
    """Insight Account user management commands."""
    pass


@users.command("list")
@auto_poll_options
@click.pass_context
@handle_errors
def users_list(ctx, auto_poll, interval):
    """List all users in the Insight Account."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/users"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getUsers", err=True)

    if not auto_poll:
        result = client.get(url, solution="platform", subcommand="users-list")
        emit(result, config)
    else:
        poll_loop(
            fetch=lambda: client.get(url, solution="platform", subcommand="users-list"),
            config=config,
            interval=interval,
        )


@users.command("get")
@click.argument("user_id")
@click.pass_context
@handle_errors
def users_get(ctx, user_id):
    """Get a user by ID."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/users/{user_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getUser", err=True)

    result = client.get(url, solution="platform", subcommand="users-get")
    emit(result, config)


@users.command("create")
@data_body_options
@click.pass_context
@handle_errors
def users_create(ctx, data_str, data_file):
    """Create a new user."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/users"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/createUser", err=True)

    body = resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with user definition.")

    result = client.post(url, json=body, solution="platform", subcommand="users-create")
    emit(result, config)


@users.command("delete")
@click.argument("user_id")
@click.pass_context
@handle_errors
def users_delete(ctx, user_id):
    """Delete a user by ID."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/users/{user_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/deleteUser", err=True)

    result = client.request("DELETE", url, solution="platform", subcommand="users-delete")
    emit(result, config)


# ---------------------------------------------------------------------------
# platform orgs
# ---------------------------------------------------------------------------

@platform.group(cls=GlobalFlagHintGroup)
@click.pass_context
def orgs(ctx):
    """Insight Account organization commands."""
    pass


@orgs.command("list")
@auto_poll_options
@click.pass_context
@handle_errors
def orgs_list(ctx, auto_poll, interval):
    """List organizations in the Insight Account."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/organizations"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getOrganizations", err=True)

    if not auto_poll:
        result = client.get(url, solution="platform", subcommand="orgs-list")
        emit(result, config)
    else:
        poll_loop(
            fetch=lambda: client.get(url, solution="platform", subcommand="orgs-list"),
            config=config,
            interval=interval,
        )


@orgs.command("managed")
@click.pass_context
@handle_errors
def orgs_managed(ctx):
    """List managed organizations."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/managed-organizations"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getManagedOrganizations", err=True)

    result = client.get(url, solution="platform", subcommand="orgs-managed")
    emit(result, config)


# ---------------------------------------------------------------------------
# platform products
# ---------------------------------------------------------------------------

@platform.group(cls=GlobalFlagHintGroup)
@click.pass_context
def products(ctx):
    """Insight Account product commands."""
    pass


@products.command("list")
@auto_poll_options
@click.pass_context
@handle_errors
def products_list(ctx, auto_poll, interval):
    """List products in the Insight Account."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/products"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/CustomerProducts", err=True)

    if not auto_poll:
        result = client.get(url, solution="platform", subcommand="products-list")
        emit(result, config)
    else:
        poll_loop(
            fetch=lambda: client.get(url, solution="platform", subcommand="products-list"),
            config=config,
            interval=interval,
        )


@products.command("get")
@click.argument("product_token")
@click.pass_context
@handle_errors
def products_get(ctx, product_token):
    """Get a product by token."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/products/{product_token}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/GetProduct", err=True)

    result = client.get(url, solution="platform", subcommand="products-get")
    emit(result, config)


# ---------------------------------------------------------------------------
# platform roles
# ---------------------------------------------------------------------------

@platform.group(cls=GlobalFlagHintGroup)
@click.pass_context
def roles(ctx):
    """Insight Account role commands."""
    pass


@roles.command("list")
@auto_poll_options
@click.pass_context
@handle_errors
def roles_list(ctx, auto_poll, interval):
    """List roles in the Insight Account."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/roles"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getCustomerRoles", err=True)

    if not auto_poll:
        result = client.get(url, solution="platform", subcommand="roles-list")
        emit(result, config)
    else:
        poll_loop(
            fetch=lambda: client.get(url, solution="platform", subcommand="roles-list"),
            config=config,
            interval=interval,
        )


@roles.command("get")
@click.argument("role_id")
@click.pass_context
@handle_errors
def roles_get(ctx, role_id):
    """Get a role by ID."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/roles/{role_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getRole", err=True)

    result = client.get(url, solution="platform", subcommand="roles-get")
    emit(result, config)


@roles.command("create")
@data_body_options
@click.pass_context
@handle_errors
def roles_create(ctx, data_str, data_file):
    """Create a custom role."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/roles"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/createCustomerRole", err=True)

    body = resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with role definition.")

    result = client.post(url, json=body, solution="platform", subcommand="roles-create")
    emit(result, config)


@roles.command("delete")
@click.argument("role_id")
@click.pass_context
@handle_errors
def roles_delete(ctx, role_id):
    """Delete a custom role by ID."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/roles/{role_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/deleteCustomerRole", err=True)

    result = client.request("DELETE", url, solution="platform", subcommand="roles-delete")
    emit(result, config)


# ---------------------------------------------------------------------------
# platform api-keys
# ---------------------------------------------------------------------------

@platform.group("api-keys", cls=GlobalFlagHintGroup)
@click.pass_context
def api_keys(ctx):
    """Insight Account API key management commands."""
    pass


@api_keys.command("list")
@auto_poll_options
@click.pass_context
@handle_errors
def api_keys_list(ctx, auto_poll, interval):
    """List API keys."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/api-keys"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getApiKeys", err=True)

    if not auto_poll:
        result = client.get(url, solution="platform", subcommand="api-keys-list")
        emit(result, config)
    else:
        poll_loop(
            fetch=lambda: client.get(url, solution="platform", subcommand="api-keys-list"),
            config=config,
            interval=interval,
        )


@api_keys.command("create")
@data_body_options
@click.pass_context
@handle_errors
def api_keys_create(ctx, data_str, data_file):
    """Generate a new API key."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/api-keys"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/generateApiKey", err=True)

    body = resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with API key definition.")

    result = client.post(url, json=body, solution="platform", subcommand="api-keys-create")
    emit(result, config)


@api_keys.command("delete")
@click.argument("apikey_id")
@click.pass_context
@handle_errors
def api_keys_delete(ctx, apikey_id):
    """Delete an API key by ID."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/api-keys/{apikey_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/deleteApiKey", err=True)

    result = client.request("DELETE", url, solution="platform", subcommand="api-keys-delete")
    emit(result, config)


# ---------------------------------------------------------------------------
# platform features
# ---------------------------------------------------------------------------

@platform.group(cls=GlobalFlagHintGroup)
@click.pass_context
def features(ctx):
    """Insight Account feature commands."""
    pass


@features.command("list")
@auto_poll_options
@click.pass_context
@handle_errors
def features_list(ctx, auto_poll, interval):
    """List available features."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/features"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getFeatures", err=True)

    if not auto_poll:
        result = client.get(url, solution="platform", subcommand="features-list")
        emit(result, config)
    else:
        poll_loop(
            fetch=lambda: client.get(url, solution="platform", subcommand="features-list"),
            config=config,
            interval=interval,
        )


# ---------------------------------------------------------------------------
# platform user-groups
# ---------------------------------------------------------------------------

@platform.group("user-groups", cls=GlobalFlagHintGroup)
@click.pass_context
def user_groups(ctx):
    """Insight Account user group commands."""
    pass


@user_groups.command("list")
@auto_poll_options
@click.pass_context
@handle_errors
def user_groups_list(ctx, auto_poll, interval):
    """List user groups."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/user-groups"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getUserGroups", err=True)

    if not auto_poll:
        result = client.get(url, solution="platform", subcommand="user-groups-list")
        emit(result, config)
    else:
        poll_loop(
            fetch=lambda: client.get(url, solution="platform", subcommand="user-groups-list"),
            config=config,
            interval=interval,
        )


@user_groups.command("get")
@click.argument("group_id")
@click.pass_context
@handle_errors
def user_groups_get(ctx, group_id):
    """Get a user group by ID."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/user-groups/{group_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getUserGroup", err=True)

    result = client.get(url, solution="platform", subcommand="user-groups-get")
    emit(result, config)


@user_groups.command("create")
@data_body_options
@click.pass_context
@handle_errors
def user_groups_create(ctx, data_str, data_file):
    """Create a user group."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/user-groups"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/createUserGroup", err=True)

    body = resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with user group definition.")

    result = client.post(url, json=body, solution="platform", subcommand="user-groups-create")
    emit(result, config)


@user_groups.command("delete")
@click.argument("group_id")
@click.pass_context
@handle_errors
def user_groups_delete(ctx, group_id):
    """Delete a user group by ID."""
    config = get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/user-groups/{group_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/deleteUserGroup", err=True)

    result = client.request("DELETE", url, solution="platform", subcommand="user-groups-delete")
    emit(result, config)


# ---------------------------------------------------------------------------
# platform credentials (from credential-management-api-v1)
# ---------------------------------------------------------------------------

@platform.group("credentials", cls=GlobalFlagHintGroup)
@click.pass_context
def credentials(ctx):
    """Platform credential management commands."""
    pass


@credentials.command("list")
@click.argument("org_id")
@click.option("--page", type=int, default=0, help="Page index (0-based).")
@click.option("--size", type=int, default=20, help="Page size (default: 20).")
@auto_poll_options
@click.pass_context
@handle_errors
def credentials_list(ctx, org_id, page, size, auto_poll, interval):
    """List credentials for an organization."""
    config = get_config(ctx)
    client = R7Client(config)
    url = CREDMGMT_BASE.format(region=config.region) + f"/credentials/organization/{org_id}"

    if config.verbose:
        click.echo(f"Docs: {_CRED_DOC}#operation/findByOrganizationId", err=True)

    params = {"page": page, "size": size}

    if not auto_poll:
        result = client.get(url, params=params, solution="platform", subcommand="credentials-list")
        emit(result, config)
    else:
        poll_loop(
            fetch=lambda: client.get(url, params=params, solution="platform", subcommand="credentials-list"),
            config=config,
            interval=interval,
        )


@credentials.command("get")
@click.argument("rrn")
@click.pass_context
@handle_errors
def credentials_get(ctx, rrn):
    """Get a credential by RRN."""
    config = get_config(ctx)
    client = R7Client(config)
    url = CREDMGMT_BASE.format(region=config.region) + f"/credentials/{rrn}"

    if config.verbose:
        click.echo(f"Docs: {_CRED_DOC}#operation/findByCredentialRRN", err=True)

    result = client.get(url, solution="platform", subcommand="credentials-get")
    emit(result, config)


@credentials.command("create")
@data_body_options
@click.pass_context
@handle_errors
def credentials_create(ctx, data_str, data_file):
    """Create a new credential."""
    config = get_config(ctx)
    client = R7Client(config)
    url = CREDMGMT_BASE.format(region=config.region) + "/credentials"

    if config.verbose:
        click.echo(f"Docs: {_CRED_DOC}#operation/createCredential", err=True)

    body = resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with credential definition.")

    result = client.post(url, json=body, solution="platform", subcommand="credentials-create")
    emit(result, config)


@credentials.command("delete")
@click.argument("rrn")
@click.pass_context
@handle_errors
def credentials_delete(ctx, rrn):
    """Delete a credential by RRN."""
    config = get_config(ctx)
    client = R7Client(config)
    url = CREDMGMT_BASE.format(region=config.region) + f"/credentials/{rrn}"

    if config.verbose:
        click.echo(f"Docs: {_CRED_DOC}#operation/deleteCredential", err=True)

    result = client.request("DELETE", url, solution="platform", subcommand="credentials-delete")
    emit(result, config)
