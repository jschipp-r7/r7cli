"""Platform solution commands — validate, search, users, orgs, roles, api-keys, credentials."""
from __future__ import annotations

import sys

import click
from r7cli.cli_group import GlobalFlagHintGroup

from r7cli.client import R7Client
from r7cli.config import Config
from r7cli.models import (
    INSIGHT_BASE,
    IDR_V1_BASE,
    ACCOUNT_BASE,
    CREDMGMT_BASE,
    VALID_SEARCH_TYPES,
    R7Error,
    UserInputError,
)
from r7cli.output import format_output


def _get_config(ctx: click.Context) -> Config:
    return ctx.obj["config"]


def _resolve_body(data_str: str | None, data_file: str | None) -> dict | None:
    """Parse a JSON body from --data or --data-file."""
    import json as _json
    if data_str and data_file:
        raise UserInputError("Provide either --data or --data-file, not both.")
    if data_str:
        return _json.loads(data_str)
    if data_file:
        with open(data_file) as fh:
            return _json.load(fh)
    return None


_ACCT_DOC = "https://help.rapid7.com/insightAccount/en-us/api/v1/docs.html"
_CRED_DOC = "https://help.rapid7.com/credentialmanagement/en-us/api/v1/docs.html"


@click.group(cls=GlobalFlagHintGroup)
@click.pass_context
def platform(ctx):
    """Platform-level commands (validate, search, users, orgs, credentials)."""
    pass


@platform.command()
@click.pass_context
def validate(ctx):
    """Validate API key against the Insight Platform."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = INSIGHT_BASE.format(region=config.region) + "/validate"
    try:
        result = client.get(url, solution="platform", subcommand="validate")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
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
def search(ctx, search_type, query, sort_field, sort_order, from_, size):
    """Search the Insight Platform (IDR v1 search endpoint)."""
    config = _get_config(ctx)

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

    try:
        result = client.post(url, json=payload, solution="platform", subcommand="search")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)



# ---------------------------------------------------------------------------
# platform users
# ---------------------------------------------------------------------------

@platform.group(cls=GlobalFlagHintGroup)
@click.pass_context
def users(ctx):
    """Insight Account user management commands."""
    pass


@users.command("list")
@click.pass_context
def users_list(ctx):
    """List all users in the Insight Account."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/users"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getUsers", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="users-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@users.command("get")
@click.argument("user_id")
@click.pass_context
def users_get(ctx, user_id):
    """Get a user by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/users/{user_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getUser", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="users-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@users.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for user creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def users_create(ctx, data_str, data_file):
    """Create a new user."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/users"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/createUser", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with user definition.")

    try:
        result = client.post(url, json=body, solution="platform", subcommand="users-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@users.command("delete")
@click.argument("user_id")
@click.pass_context
def users_delete(ctx, user_id):
    """Delete a user by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/users/{user_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/deleteUser", err=True)

    try:
        result = client.request("DELETE", url, solution="platform", subcommand="users-delete")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# platform orgs
# ---------------------------------------------------------------------------

@platform.group(cls=GlobalFlagHintGroup)
@click.pass_context
def orgs(ctx):
    """Insight Account organization commands."""
    pass


@orgs.command("list")
@click.pass_context
def orgs_list(ctx):
    """List organizations in the Insight Account."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/organizations"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getOrganizations", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="orgs-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@orgs.command("managed")
@click.pass_context
def orgs_managed(ctx):
    """List managed organizations."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/managed-organizations"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getManagedOrganizations", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="orgs-managed")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# platform products
# ---------------------------------------------------------------------------

@platform.group(cls=GlobalFlagHintGroup)
@click.pass_context
def products(ctx):
    """Insight Account product commands."""
    pass


@products.command("list")
@click.pass_context
def products_list(ctx):
    """List products in the Insight Account."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/products"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/CustomerProducts", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="products-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@products.command("get")
@click.argument("product_token")
@click.pass_context
def products_get(ctx, product_token):
    """Get a product by token."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/products/{product_token}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/GetProduct", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="products-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# platform roles
# ---------------------------------------------------------------------------

@platform.group(cls=GlobalFlagHintGroup)
@click.pass_context
def roles(ctx):
    """Insight Account role commands."""
    pass


@roles.command("list")
@click.pass_context
def roles_list(ctx):
    """List roles in the Insight Account."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/roles"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getCustomerRoles", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="roles-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@roles.command("get")
@click.argument("role_id")
@click.pass_context
def roles_get(ctx, role_id):
    """Get a role by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/roles/{role_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getRole", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="roles-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@roles.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for role creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def roles_create(ctx, data_str, data_file):
    """Create a custom role."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/roles"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/createCustomerRole", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with role definition.")

    try:
        result = client.post(url, json=body, solution="platform", subcommand="roles-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@roles.command("delete")
@click.argument("role_id")
@click.pass_context
def roles_delete(ctx, role_id):
    """Delete a custom role by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/roles/{role_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/deleteCustomerRole", err=True)

    try:
        result = client.request("DELETE", url, solution="platform", subcommand="roles-delete")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# platform api-keys
# ---------------------------------------------------------------------------

@platform.group("api-keys", cls=GlobalFlagHintGroup)
@click.pass_context
def api_keys(ctx):
    """Insight Account API key management commands."""
    pass


@api_keys.command("list")
@click.pass_context
def api_keys_list(ctx):
    """List API keys."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/api-keys"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getApiKeys", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="api-keys-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@api_keys.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for API key generation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def api_keys_create(ctx, data_str, data_file):
    """Generate a new API key."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/api-keys"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/generateApiKey", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with API key definition.")

    try:
        result = client.post(url, json=body, solution="platform", subcommand="api-keys-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@api_keys.command("delete")
@click.argument("apikey_id")
@click.pass_context
def api_keys_delete(ctx, apikey_id):
    """Delete an API key by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/api-keys/{apikey_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/deleteApiKey", err=True)

    try:
        result = client.request("DELETE", url, solution="platform", subcommand="api-keys-delete")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# platform features
# ---------------------------------------------------------------------------

@platform.group(cls=GlobalFlagHintGroup)
@click.pass_context
def features(ctx):
    """Insight Account feature commands."""
    pass


@features.command("list")
@click.pass_context
def features_list(ctx):
    """List available features."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/features"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getFeatures", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="features-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


# ---------------------------------------------------------------------------
# platform user-groups
# ---------------------------------------------------------------------------

@platform.group("user-groups", cls=GlobalFlagHintGroup)
@click.pass_context
def user_groups(ctx):
    """Insight Account user group commands."""
    pass


@user_groups.command("list")
@click.pass_context
def user_groups_list(ctx):
    """List user groups."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/user-groups"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getUserGroups", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="user-groups-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@user_groups.command("get")
@click.argument("group_id")
@click.pass_context
def user_groups_get(ctx, group_id):
    """Get a user group by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/user-groups/{group_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/getUserGroup", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="user-groups-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@user_groups.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for user group creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def user_groups_create(ctx, data_str, data_file):
    """Create a user group."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + "/user-groups"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/createUserGroup", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with user group definition.")

    try:
        result = client.post(url, json=body, solution="platform", subcommand="user-groups-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@user_groups.command("delete")
@click.argument("group_id")
@click.pass_context
def user_groups_delete(ctx, group_id):
    """Delete a user group by ID."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = ACCOUNT_BASE.format(region=config.region) + f"/user-groups/{group_id}"

    if config.verbose:
        click.echo(f"Docs: {_ACCT_DOC}#operation/deleteUserGroup", err=True)

    try:
        result = client.request("DELETE", url, solution="platform", subcommand="user-groups-delete")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


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
@click.pass_context
def credentials_list(ctx, org_id, page, size):
    """List credentials for an organization."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = CREDMGMT_BASE.format(region=config.region) + f"/credentials/organization/{org_id}"

    if config.verbose:
        click.echo(f"Docs: {_CRED_DOC}#operation/findByOrganizationId", err=True)

    params = {"page": page, "size": size}

    try:
        result = client.get(url, params=params, solution="platform", subcommand="credentials-list")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@credentials.command("get")
@click.argument("rrn")
@click.pass_context
def credentials_get(ctx, rrn):
    """Get a credential by RRN."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = CREDMGMT_BASE.format(region=config.region) + f"/credentials/{rrn}"

    if config.verbose:
        click.echo(f"Docs: {_CRED_DOC}#operation/findByCredentialRRN", err=True)

    try:
        result = client.get(url, solution="platform", subcommand="credentials-get")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@credentials.command("create")
@click.option("--data", "data_str", default=None, help="JSON body for credential creation.")
@click.option("--data-file", type=click.Path(exists=True), default=None, help="Path to JSON file.")
@click.pass_context
def credentials_create(ctx, data_str, data_file):
    """Create a new credential."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = CREDMGMT_BASE.format(region=config.region) + "/credentials"

    if config.verbose:
        click.echo(f"Docs: {_CRED_DOC}#operation/createCredential", err=True)

    body = _resolve_body(data_str, data_file)
    if not body:
        raise UserInputError("Provide --data or --data-file with credential definition.")

    try:
        result = client.post(url, json=body, solution="platform", subcommand="credentials-create")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)


@credentials.command("delete")
@click.argument("rrn")
@click.pass_context
def credentials_delete(ctx, rrn):
    """Delete a credential by RRN."""
    config = _get_config(ctx)
    client = R7Client(config)
    url = CREDMGMT_BASE.format(region=config.region) + f"/credentials/{rrn}"

    if config.verbose:
        click.echo(f"Docs: {_CRED_DOC}#operation/deleteCredential", err=True)

    try:
        result = client.request("DELETE", url, solution="platform", subcommand="credentials-delete")
        click.echo(format_output(result, config.output_format, config.limit))
    except R7Error as exc:
        click.echo(str(exc), err=True)
        sys.exit(exc.exit_code)
