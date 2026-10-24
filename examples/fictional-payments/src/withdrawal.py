"""Fictional pseudocode for a report example; not production code or a sandbox."""


def submit(request, policy_service, settlement_service):
    # The API submits a payout request. The independent settlement service
    # still checks the customer's signature against the exact amount/recipient.
    policy_service.check_destination(request.recipient)
    settlement_service.execute(request)


def configure_destinations(policy_service, new_allowlist, runtime_credentials):
    # This credential is available to the assumed compromised API runtime.
    # External enforcement alone therefore does not protect this allowlist.
    policy_service.replace_allowlist(runtime_credentials.policy_admin, new_allowlist)


class SettlementService:
    # Hosted independently. This example's source defines the intended boundary;
    # it does not establish any actual deployed configuration.
    def execute(self, request):
        verify_customer_signature(request.amount, request.recipient, request.nonce)
        consume_nonce(request.nonce)
        transfer(request.amount, request.recipient)

    def replace_customer_key(self, old_key_signature, new_key):
        # The runtime has no replacement-key authority in this fictional design.
        verify_current_customer_key(old_key_signature, new_key)
        save_customer_key(new_key)


def refund(provider, order_id):
    # Destination and administration rules live at a third-party provider.
    # No provider configuration or recovery policy was supplied to this review.
    return provider.refund(order_id)
