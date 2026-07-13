import hashlib
import hmac

from flask import abort, jsonify, redirect

from CTFd.models import Challenges, Flags
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.flags import FLAG_CLASSES, BaseFlag
from CTFd.utils.decorators import authed_only
from CTFd.utils.user import get_current_user, is_admin

DIGEST_LENGTH = 16
DEFAULT_PREFIX = "pbctf"
TICKET_CONTEXT = b"ticket:"


def make_digest(secret, account_id):
    return hmac.new(
        secret.encode(), str(account_id).encode(), hashlib.sha256
    ).hexdigest()[:DIGEST_LENGTH]


def make_ticket(secret, account_id):
    sig = hmac.new(
        secret.encode(), TICKET_CONTEXT + str(account_id).encode(), hashlib.sha256
    ).hexdigest()[:DIGEST_LENGTH]
    return "%s.%s" % (account_id, sig)


def parse_data(data):
    """The flag's data field holds up to two lines: the prefix on line 1 and
    an optional redirect URL on line 2. Legacy single-line values are treated
    as a bare prefix, so existing flags keep working."""
    lines = (data or "").splitlines()
    prefix = (lines[0].strip() if lines else "") or DEFAULT_PREFIX
    url = lines[1].strip() if len(lines) > 1 else ""
    return prefix, url


class HmacFlag(BaseFlag):
    name = "hmac"
    templates = {  # Nunjucks templates used for key editing & viewing
        "create": "/plugins/hmac_flag/assets/create.html",
        "update": "/plugins/hmac_flag/assets/edit.html",
    }

    @staticmethod
    def compare(chal_key_obj, provided):
        secret = chal_key_obj.content
        prefix, _ = parse_data(chal_key_obj.data)

        user = get_current_user()
        if user is None or user.account_id is None:
            return False

        expected = "%s{%s}" % (prefix, make_digest(secret, user.account_id))
        return hmac.compare_digest(expected, provided)


def load(app):
    register_plugin_assets_directory(app, base_path="/plugins/hmac_flag/assets/")
    FLAG_CLASSES["hmac"] = HmacFlag

    @app.route("/hmac/ticket/<int:challenge_id>", methods=["GET"])
    @authed_only
    def hmac_ticket(challenge_id):
        user = get_current_user()
        if user is None or user.account_id is None:
            return jsonify({"success": False, "error": "Join a team to get a ticket"}), 403

        challenge = Challenges.query.filter_by(id=challenge_id).first()
        if challenge is None or (challenge.state != "visible" and not is_admin()):
            abort(404)

        flag = Flags.query.filter_by(challenge_id=challenge_id, type="hmac").first()
        if flag is None:
            abort(404)

        ticket = make_ticket(flag.content, user.account_id)

        # Prefer the redirect target configured on the flag (admin-only, never
        # shown to players); fall back to Connection Info for older challenges.
        _, target = parse_data(flag.data)
        if not target:
            target = challenge.connection_info or ""
        if target.startswith(("http://", "https://")):
            sep = "&" if "?" in target else "?"
            return redirect(target + sep + "t=" + ticket)
        return jsonify({"success": True, "ticket": ticket})
