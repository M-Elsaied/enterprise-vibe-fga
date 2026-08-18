"""
Install (or remove) the floating persona widget inside the nsflow studio UI.

Injects a small script into nsflow's served index.html so the persona switcher
lives INSIDE the studio: a pill in the bottom-right corner that shows the
active persona and switches it with one click (the page reloads and every
studio panel re-authorizes as the new persona). The widget talks to the
identity gateway (studio_gateway.py) on port 8210.

Idempotent: safe to run repeatedly. Survives until nsflow is reinstalled or
upgraded - just run it again after that. Remove with --remove.

Usage:
    .venv\\Scripts\\python.exe authz\\install_studio_widget.py [--remove]
"""

import argparse
import sys
from pathlib import Path

MARKER = "<!-- vibe-fga-persona-widget -->"

WIDGET = MARKER + """
<script>
(function () {
  var GW = "http://127.0.0.1:8210";
  var PERSONAS = [["sam", "platform super admin"], ["ada", "tenant alpha admin"],
                  ["alice", "alpha member, builder"], ["bob", "beta member"],
                  ["eve", "stranger, zero grants"]];
  function mount() {
    var box = document.createElement("div");
    box.style.cssText = "position:fixed;bottom:14px;right:14px;z-index:99999;" +
      "background:#161b22;border:1px solid #30363d;border-radius:12px;" +
      "padding:8px 10px;font-family:'Segoe UI',system-ui,sans-serif;" +
      "color:#e6edf3;font-size:12px;box-shadow:0 4px 18px rgba(0,0,0,.55)";
    box.innerHTML = '<div style="margin-bottom:4px;color:#8b949e">' +
      'FGA persona &middot; refreshes on switch</div><div id="vfga-btns"></div>';
    document.body.appendChild(box);
    var current = null;
    function render() {
      var c = document.getElementById("vfga-btns");
      c.innerHTML = "";
      PERSONAS.forEach(function (pd) {
        var b = document.createElement("button");
        b.textContent = pd[0];
        b.title = pd[1];
        b.style.cssText = "margin:2px;padding:3px 10px;border-radius:999px;" +
          "border:1px solid #30363d;color:#e6edf3;cursor:pointer;font-size:12px;" +
          "background:" + (pd[0] === current ? "#1f6feb" : "#0d1117");
        b.onclick = function () {
          fetch(GW + "/__persona/set?u=" + pd[0]).then(function () { location.reload(); });
        };
        c.appendChild(b);
      });
    }
    fetch(GW + "/__persona/state").then(function (r) { return r.json(); })
      .then(function (j) { current = j.persona; render(); })
      .catch(function () {
        box.innerHTML = '<span style="color:#f85149">FGA gateway offline (:8210)</span>';
      });
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mount);
  } else { mount(); }
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

    if args.remove:
        if MARKER not in html:
            print("Widget not installed; nothing to remove.")
            return
        start = html.index(MARKER)
        end = html.index("</script>", start) + len("</script>")
        index.write_text(html[:start] + html[end:], encoding="utf-8")
        print(f"Widget removed from {index}")
        return

    if MARKER in html:
        print(f"Widget already installed in {index}")
        return
    if "</body>" not in html:
        sys.exit("No </body> tag found; nsflow layout changed - update this script.")
    index.write_text(html.replace("</body>", WIDGET + "</body>"), encoding="utf-8")
    print(f"Widget installed into {index}")


if __name__ == "__main__":
    main()
