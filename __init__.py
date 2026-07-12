import hashlib
import hmac

from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.flags import FLAG_CLASSES, BaseFlag
from CTFd.utils.user import get_current_user

DIGEST_LENGTH = 16
DEFAULT_PREFIX = "pbctf"


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

        digest = hmac.new(
            secret.encode(), str(user.account_id).encode(), hashlib.sha256
        ).hexdigest()[:DIGEST_LENGTH]
        expected = "%s{%s}" % (prefix, digest)
        return hmac.compare_digest(expected, provided)


def load(app):
    register_plugin_assets_directory(app, base_path="/plugins/hmac_flag/assets/")
    FLAG_CLASSES["hmac"] = HmacFlag
