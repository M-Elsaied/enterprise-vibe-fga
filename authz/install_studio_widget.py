"""
Install (or remove) the floating persona widget inside the nsflow studio UI.

Injects a script into nsflow's served index.html so the persona switcher lives
INSIDE the studio: a pill bar in the bottom-right corner that switches the
identity-gateway persona in one click, plus a maximizable DETAILS panel that
previews, per persona, exactly what the studio persona console (:8400) shows -
roles, per-network verb chips, tools, special-agent access, create rights - so
people understand what they are choosing before they switch. Minimize returns
to the compact bar.

Idempotent: safe to run repeatedly; --remove to undo; re-run after an nsflow
reinstall. Persona set and endpoints are configured at INSTALL time:

    STUDIO_WIDGET_PERSONAS   "name|description|GROUP1+GROUP2;name|desc|GROUPS;..."
                             (groups may be empty; they feed the preview API)
    STUDIO_CONSOLE_URL       default http://127.0.0.1:8400  (needs CORS enabled)
    STUDIO_GATEWAY_URL       default http://127.0.0.1:8210

Usage:
    .venv\\Scripts\\python.exe authz\\install_studio_widget.py [--remove]
"""

import argparse
import json
import os
import sys
from pathlib import Path

MARKER = "<!-- vibe-fga-persona-widget -->"

DEFAULT_PERSONAS = [["sam", "platform super admin", ""],
                    ["ada", "tenant alpha admin", ""],
                    ["alice", "alpha member, builder", ""],
                    ["bob", "beta member", ""],
                    ["eve", "stranger, zero grants", ""]]


def personas() -> list:
    raw = os.environ.get("STUDIO_WIDGET_PERSONAS", "")
    if not raw.strip():
        return DEFAULT_PERSONAS
    result = []
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        name, _, rest = entry.partition("|")
        desc, _, groups = rest.partition("|")
        result.append([name.strip(), desc.strip() or name.strip(),
                       ",".join(g.strip() for g in groups.split("+") if g.strip())])
    return result or DEFAULT_PERSONAS


WIDGET = MARKER + """
<script>
(function () {
  var GW = "__GATEWAY__";
  var CONSOLE = "__CONSOLE__";
  var PERSONAS = __PERSONAS__;   // [name, description, "GROUP1,GROUP2"]
  var current = null, previewing = null, maximized = false;

  function el(tag, css, html) {
    var e = document.createElement(tag);
    if (css) e.style.cssText = css;
    if (html !== undefined) e.innerHTML = html;
    return e;
  }
  var chipOk = "display:inline-block;border-radius:6px;padding:1px 7px;font-size:11px;" +
               "font-weight:600;margin:1px;background:#1a7f37;color:#fff";
  var chipNo = chipOk.replace("#1a7f37", "#3d1418") + ";color:#f85149;border:1px solid #f85149";
  function chips(o, keys) {
    return keys.map(function (k) {
      return '<span style="' + (o[k] ? chipOk : chipNo) + '">' + k + "</span>";
    }).join("");
  }

  var box = el("div",
    "position:fixed;bottom:14px;right:14px;z-index:99999;background:#161b22;" +
    "border:1px solid #30363d;border-radius:12px;padding:8px 10px;max-width:560px;" +
    "font-family:'Segoe UI',system-ui,sans-serif;color:#e6edf3;font-size:12px;" +
    "box-shadow:0 4px 18px rgba(0,0,0,.55)");
  var head = el("div", "display:flex;justify-content:space-between;align-items:center;" +
    "margin-bottom:4px;color:#8b949e");
  head.appendChild(el("span", "", "FGA persona"));
  var toggle = el("button", "background:#0d1117;color:#7ee1f5;border:1px solid #30363d;" +
    "border-radius:6px;padding:1px 8px;cursor:pointer;font-size:11px", "details \\u25B4");
  head.appendChild(toggle);
  box.appendChild(head);
  var panel = el("div", "display:none;border-bottom:1px solid #30363d;margin-bottom:6px;" +
    "padding-bottom:6px;max-height:340px;overflow-y:auto;min-width:420px");
  box.appendChild(panel);
  var bar = el("div", "");
  box.appendChild(bar);
  document.body.appendChild(box);

  function renderBar() {
    bar.innerHTML = "";
    PERSONAS.forEach(function (p) {
      var b = el("button",
        "margin:2px;padding:3px 10px;border-radius:999px;border:1px solid #30363d;" +
        "color:#e6edf3;cursor:pointer;font-size:12px;background:" +
        (p[0] === current ? "#1f6feb" :
         (maximized && p[0] === previewing ? "#3b2b63" : "#0d1117")));
      b.textContent = p[0];
      b.title = p[1];
      b.onclick = function () {
        if (maximized) { previewing = p[0]; renderBar(); preview(p); }
        else { switchTo(p[0]); }
      };
      bar.appendChild(b);
    });
  }

  function switchTo(name) {
    fetch(GW + "/__persona/set?u=" + name).then(function () { location.reload(); });
  }

  function preview(p) {
    panel.innerHTML = '<div style="color:#8b949e">loading ' + p[0] + "\\u2026</div>";
    var headers = { "X-Dev-User": p[0] };
    if (p[2]) headers["X-Dev-Groups"] = p[2];
    fetch(CONSOLE + "/api/overview", { headers: headers })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        var html = '<div style="margin-bottom:4px"><b>' + p[0] + "</b> \\u00B7 " + p[1] +
          '<button id="vfga-switch" style="float:right;background:#1f6feb;color:#fff;' +
          'border:none;border-radius:6px;padding:2px 10px;cursor:pointer;font-size:11px">' +
          "switch \\u2192</button></div>" +
          '<div style="color:#7ee1f5;font-family:Consolas,monospace;font-size:11px;' +
          'margin-bottom:6px">roles: ' + ((d.roles || []).join("  ") || "(none)") + "</div>";
        (d.networks || []).forEach(function (n) {
          html += '<div style="margin:2px 0"><span style="font-family:Consolas,monospace">' +
            n.id + "</span> " + chips(n, ["read", "update", "delete", "execute"]) + "</div>";
        });
        (d.tools || []).forEach(function (t) {
          html += '<div style="margin:2px 0"><span style="font-family:Consolas,monospace">tool:' +
            t.id + "</span> " + chips(t, ["read", "update", "delete"]) + "</div>";
        });
        html += '<div style="margin:2px 0">special agents <span style="' +
          (d.special_access ? chipOk : chipNo) + '">agent_network_designer</span></div>';
        var create = d.create || {};
        html += '<div style="margin:2px 0">create: ' + (Object.keys(create).map(function (t) {
          return '<span style="' + (create[t] ? chipOk : chipNo) + '">' + t + "</span>";
        }).join("") || "-") + "</div>";
        if (!(d.networks || []).length && !(d.tools || []).length) {
          html += '<div style="color:#f85149">sees nothing - no mapped roles</div>';
        }
        panel.innerHTML = html;
        var sw = document.getElementById("vfga-switch");
        if (sw) sw.onclick = function () { switchTo(p[0]); };
      })
      .catch(function () {
        panel.innerHTML = '<span style="color:#f85149">preview console offline (' +
          CONSOLE + ")</span>";
      });
  }

  toggle.onclick = function () {
    maximized = !maximized;
    toggle.innerHTML = maximized ? "minimize \\u25BE" : "details \\u25B4";
    panel.style.display = maximized ? "block" : "none";
    if (maximized) {
      previewing = previewing || current || PERSONAS[0][0];
      var p = PERSONAS.filter(function (x) { return x[0] === previewing; })[0] || PERSONAS[0];
      renderBar(); preview(p);
    } else { renderBar(); }
  };

  fetch(GW + "/__persona/state").then(function (r) { return r.json(); })
    .then(function (j) { current = j.persona; renderBar(); })
    .catch(function () {
      head.innerHTML = '<span style="color:#f85149">FGA gateway offline</span>';
      renderBar();
    });
})();
</script>
"""


def find_index() -> Path:
    import nsflow
    index = Path(nsflow.__file__).parent / "prebuilt_frontend" / "dist" / "index.html"
    if not index.exists():
        sys.exit(f"nsflow index.html not found at {index}")
    return index


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--remove", action="store_true", help="remove the widget")
    args = parser.parse_args()

    index = find_index()
    html = index.read_text(encoding="utf-8")

    if args.remove or MARKER in html:
        if MARKER in html:
            start = html.index(MARKER)
            end = html.index("</script>", start) + len("</script>")
            html = html[:start] + html[end:]
            if args.remove:
                index.write_text(html, encoding="utf-8")
                print(f"Widget removed from {index}")
                return
        elif args.remove:
            print("Widget not installed; nothing to remove.")
            return

    if "</body>" not in html:
        sys.exit("No </body> tag found; nsflow layout changed - update this script.")
    widget = (WIDGET
              .replace("__PERSONAS__", json.dumps(personas()))
              .replace("__CONSOLE__", os.environ.get("STUDIO_CONSOLE_URL", "http://127.0.0.1:8400"))
              .replace("__GATEWAY__", os.environ.get("STUDIO_GATEWAY_URL", "http://127.0.0.1:8210")))
    index.write_text(html.replace("</body>", widget + "</body>"), encoding="utf-8")
    print(f"Widget installed into {index} with {len(personas())} personas")


if __name__ == "__main__":
    main()
