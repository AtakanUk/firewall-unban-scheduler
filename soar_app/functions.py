"""SOAR app functions for an app generated with ``resilient-sdk codegen``.

``unban_scheduler``  inputs: incident_id, unban_minutes, unban_source, ip_address,
                     bluecoat_domain, prisma_domain (targets optional)
``ip_block_list``    inputs: ip_address (comma-separated), firewall_action ("Add" / "Remove")

Settings come from the environment of the resilient-circuits service (see .env.example).
"""

from resilient_circuits import AppFunctionComponent, FunctionResult, app_function
from resilient_lib import IntegrationError, validate_fields

from unban_scheduler.backends import IpBlockList
from unban_scheduler.config import Settings
from unban_scheduler.store import UnbanStore

PACKAGE_NAME = "fn_unban_scheduler"


def _optional(fn_inputs, name):
    value = getattr(fn_inputs, name, None)
    if not value:
        return None
    return str(value).strip() or None


class UnbanSchedulerComponent(AppFunctionComponent):
    def __init__(self, opts):
        super().__init__(opts, PACKAGE_NAME)
        self.settings = Settings()
        self.store = UnbanStore(self.settings.db_path)

    @app_function("unban_scheduler")
    def _schedule(self, fn_inputs):
        validate_fields(["incident_id", "unban_minutes", "unban_source"], fn_inputs)
        expires_at = self.store.schedule(
            int(fn_inputs.incident_id),
            str(fn_inputs.unban_source),
            int(fn_inputs.unban_minutes),
            ip_address=_optional(fn_inputs, "ip_address"),
            bluecoat_domain=_optional(fn_inputs, "bluecoat_domain"),
            prisma_domain=_optional(fn_inputs, "prisma_domain"),
        )
        yield self.status_message(f"Unban scheduled for incident {fn_inputs.incident_id}")
        yield FunctionResult({"status": "scheduled", "expires_at": expires_at})


class IpBlockListComponent(AppFunctionComponent):
    def __init__(self, opts):
        super().__init__(opts, PACKAGE_NAME)
        self.ip_list = IpBlockList(Settings().ip_list_path)

    @app_function("ip_block_list")
    def _update(self, fn_inputs):
        validate_fields(["ip_address", "firewall_action"], fn_inputs)
        action = getattr(fn_inputs.firewall_action, "name", fn_inputs.firewall_action)
        if action not in ("Add", "Remove"):
            raise IntegrationError(f"firewall_action must be Add or Remove, got {action!r}")
        result = (
            self.ip_list.add(fn_inputs.ip_address)
            if action == "Add"
            else self.ip_list.remove(fn_inputs.ip_address)
        )
        yield FunctionResult(result)
