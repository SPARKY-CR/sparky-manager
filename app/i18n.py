"""UI strings — Persian (default) and English.

The panel UI is Persian-first RTL; English is the secondary toggle.
Templates call :func:`t` with a key and the current language.
Unknown keys fall back to English, then to the key itself, so a
missing translation never crashes a page.
"""

from __future__ import annotations

FA: dict[str, str] = {
    # Navigation / sections
    "dashboard": "داشبورد",
    "users": "کاربران",
    "inbounds": "اینباندها",
    "settings": "تنظیمات",
    "login": "ورود",
    "logout": "خروج",
    "subscriptions": "اشتراک‌ها",
    "audit_log": "گزارش رویدادها",
    # Common actions
    "save": "ذخیره",
    "delete": "حذف",
    "edit": "ویرایش",
    "add": "افزودن",
    "enable": "فعال",
    "disable": "غیرفعال",
    "cancel": "لغو",
    "back": "بازگشت",
    "search": "جستجو",
    "copy": "کپی",
    "refresh": "به‌روزرسانی",
    "confirm": "تأیید",
    "close": "بستن",
    "yes": "بله",
    "no": "خیر",
    # Users
    "user": "کاربر",
    "username": "نام کاربری",
    "password": "رمز عبور",
    "add_user": "افزودن کاربر",
    "edit_user": "ویرایش کاربر",
    "delete_user": "حذف کاربر",
    "user_name": "نام کاربر",
    "note": "یادداشت",
    "status": "وضعیت",
    "enabled": "فعال",
    "disabled": "غیرفعال",
    # Traffic / expiry
    "traffic": "ترافیک",
    "traffic_used": "ترافیک مصرف‌شده",
    "traffic_limit": "سقف ترافیک",
    "traffic_remaining": "ترافیک باقی‌مانده",
    "unlimited": "نامحدود",
    "upload": "آپلود",
    "download": "دانلود",
    "total": "مجموع",
    "expiry": "انقضا",
    "expires_at": "تاریخ انقضا",
    "never": "هرگز",
    "expired": "منقضی‌شده",
    "days_left": "روز باقی‌مانده",
    "online": "آنلاین",
    "offline": "آفلاین",
    "last_seen": "آخرین مشاهده",
    # Inbounds
    "inbound": "اینباند",
    "add_inbound": "افزودن اینباند",
    "protocol": "پروتکل",
    "port": "پورت",
    "core": "هسته",
    "tag": "برچسب",
    "remark": "توضیح",
    # Subscription
    "subscription": "اشتراک",
    "subscription_link": "لینک اشتراک",
    "subscription_token": "توکن اشتراک",
    "rotate_token": "تعویض توکن",
    "qr_code": "کد QR",
    "copy_link": "کپی لینک",
    # Login / admin
    "admin": "مدیر",
    "login_title": "ورود به پنل",
    "login_failed": "نام کاربری یا رمز عبور اشتباه است.",
    "login_locked": "به‌دلیل تلاش‌های ناموفق، ورود برای ۱۵ دقیقه قفل شده است.",
    "wrong_password": "رمز عبور اشتباه است.",
    "change_password": "تغییر رمز عبور",
    "current_password": "رمز عبور فعلی",
    "new_password": "رمز عبور جدید",
    # Misc
    "panel": "پنل",
    "version": "نسخه",
    "domain": "دامین",
    "subscription_host": "هاست اشتراک",
    "no_domain": "بدون دامین (با IP سرور)",
    "save_success": "با موفقیت ذخیره شد.",
    "delete_confirm": "آیا مطمئن هستید؟ این عمل قابل بازگشت نیست.",
    "not_found": "یافت نشد.",
    "ikev2": "IKEv2",
    "ikev2_status": "وضعیت IKEv2",
    "open_ikev2_manager": "باز کردن Ikev2-manager",
}

EN: dict[str, str] = {
    # Navigation / sections
    "dashboard": "Dashboard",
    "users": "Users",
    "inbounds": "Inbounds",
    "settings": "Settings",
    "login": "Login",
    "logout": "Logout",
    "subscriptions": "Subscriptions",
    "audit_log": "Audit log",
    # Common actions
    "save": "Save",
    "delete": "Delete",
    "edit": "Edit",
    "add": "Add",
    "enable": "Enable",
    "disable": "Disable",
    "cancel": "Cancel",
    "back": "Back",
    "search": "Search",
    "copy": "Copy",
    "refresh": "Refresh",
    "confirm": "Confirm",
    "close": "Close",
    "yes": "Yes",
    "no": "No",
    # Users
    "user": "User",
    "username": "Username",
    "password": "Password",
    "add_user": "Add user",
    "edit_user": "Edit user",
    "delete_user": "Delete user",
    "user_name": "User name",
    "note": "Note",
    "status": "Status",
    "enabled": "Enabled",
    "disabled": "Disabled",
    # Traffic / expiry
    "traffic": "Traffic",
    "traffic_used": "Traffic used",
    "traffic_limit": "Traffic limit",
    "traffic_remaining": "Traffic remaining",
    "unlimited": "Unlimited",
    "upload": "Upload",
    "download": "Download",
    "total": "Total",
    "expiry": "Expiry",
    "expires_at": "Expires at",
    "never": "Never",
    "expired": "Expired",
    "days_left": "Days left",
    "online": "Online",
    "offline": "Offline",
    "last_seen": "Last seen",
    # Inbounds
    "inbound": "Inbound",
    "add_inbound": "Add inbound",
    "protocol": "Protocol",
    "port": "Port",
    "core": "Core",
    "tag": "Tag",
    "remark": "Remark",
    # Subscription
    "subscription": "Subscription",
    "subscription_link": "Subscription link",
    "subscription_token": "Subscription token",
    "rotate_token": "Rotate token",
    "qr_code": "QR code",
    "copy_link": "Copy link",
    # Login / admin
    "admin": "Admin",
    "login_title": "Login to panel",
    "login_failed": "Wrong username or password.",
    "login_locked": "Login is locked for 15 minutes after too many failed attempts.",
    "wrong_password": "Wrong password.",
    "change_password": "Change password",
    "current_password": "Current password",
    "new_password": "New password",
    # Misc
    "panel": "Panel",
    "version": "Version",
    "domain": "Domain",
    "subscription_host": "Subscription host",
    "no_domain": "No domain (use server IP)",
    "save_success": "Saved successfully.",
    "delete_confirm": "Are you sure? This cannot be undone.",
    "not_found": "Not found.",
    "ikev2": "IKEv2",
    "ikev2_status": "IKEv2 status",
    "open_ikev2_manager": "Open Ikev2-manager",
}

_STRINGS: dict[str, dict[str, str]] = {"fa": FA, "en": EN}
DEFAULT_LANG = "fa"


def t(key: str, lang: str = DEFAULT_LANG) -> str:
    """Translate ``key`` for ``lang`` (``fa`` default, ``en`` fallback).

    Falls back to English, then to the key itself, so a missing
    translation never breaks a page.
    """
    table = _STRINGS.get(lang) or _STRINGS[DEFAULT_LANG]
    if key in table:
        return table[key]
    if key in EN:
        return EN[key]
    return key


__all__ = ["FA", "EN", "DEFAULT_LANG", "t"]
