import logging


try:
    from qt_material import apply_stylesheet, list_themes
    QT_MATERIAL_AVAILABLE = True
except Exception as exc:
    QT_MATERIAL_AVAILABLE = False
    logging.warning("qt_material is unavailable; using the default Qt theme. Error: %s", exc)

    def apply_stylesheet(*args, **kwargs):
        return None

    def list_themes():
        return ["dark_blue.xml", "light_blue.xml"]
