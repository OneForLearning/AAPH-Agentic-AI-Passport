from PyInstaller.utils.hooks import collect_submodules

a = Analysis(
    ["aaph_agent/main.py"],
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=collect_submodules("aaph_agent"),
    excludes=["pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name="aaph-agent", console=True)
