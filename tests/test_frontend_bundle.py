from pathlib import Path


def test_frontend_bundle_does_not_require_global_react():
    dist_assets = Path(__file__).resolve().parents[1] / "frontend" / "dist" / "assets"
    bundles = list(dist_assets.glob("index-*.js"))

    assert bundles, "frontend production bundle is missing; run npm run build first"
    bundle_text = "\n".join(bundle.read_text(encoding="utf-8", errors="ignore") for bundle in bundles)

    assert "React.createElement" not in bundle_text
    assert "=React;" not in bundle_text.replace(" ", "")

def test_export_report_uses_attached_download_link():
    export_source = Path(__file__).resolve().parents[1] / "frontend" / "src" / "lib" / "format.js"
    source_text = export_source.read_text(encoding="utf-8")

    assert "document.body.appendChild(link)" in source_text
    assert "link.remove()" in source_text

def test_recharts_containers_define_minimum_dimensions():
    root = Path(__file__).resolve().parents[1]
    dashboard = (root / "frontend" / "src" / "components" / "Dashboard.jsx").read_text(encoding="utf-8")
    evidence = (root / "frontend" / "src" / "components" / "ModelEvidence.jsx").read_text(encoding="utf-8")
    result_panel = (root / "frontend" / "src" / "components" / "ResultPanel.jsx").read_text(encoding="utf-8")

    assert 'minWidth={1}' in dashboard
    assert 'minHeight={1}' in dashboard
    assert 'minWidth={1}' in evidence
    assert 'minHeight={1}' in evidence
    assert 'minWidth={1}' in result_panel
    assert 'minHeight={1}' in result_panel
