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


class HmacFlag(BaseFlag):
    name = "hmac"
    templates = {  # Nunjucks templates used for key editing & viewing
        "create": "/plugins/hmac_flag/assets/create.html",
        "update": "/plugins/hmac_flag/assets/edit.html",
    }

    @staticmethod
    def compare(chal_key_obj, provided):
        secret = chal_key_obj.content
        prefix = chal_key_obj.data or DEFAULT_PREFIX

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

        conn = challenge.connection_info or ""
        if conn.startswith(("http://", "https://")):
            sep = "&" if "?" in conn else "?"
            return redirect(conn + sep + "t=" + ticket)
        return jsonify({"success": True, "ticket": ticket})
