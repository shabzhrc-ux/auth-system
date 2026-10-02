"""Non-auth pages."""
from flask import Blueprint, g, redirect, render_template, url_for

from auth import login_required

bp = Blueprint("views", __name__)


@bp.route("/")
def index():
    if g.user:
        return redirect(url_for("views.dashboard"))
    return redirect(url_for("auth.login"))


@bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")
