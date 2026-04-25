import logging


try:
    import qt_material
    QT_MATERIAL_AVAILABLE = True

    def apply_stylesheet(*args, **kwargs):
        return qt_material.apply_stylesheet(*args, **kwargs)

    def list_themes():
        themes = qt_material.list_themes()
        if 'cyberpunk.xml' not in themes:
            themes.append('cyberpunk.xml')
        return themes

except Exception as exc:
    QT_MATERIAL_AVAILABLE = False
    logging.warning("qt_material is unavailable; using the default Qt theme. Error: %s", exc)

    def apply_stylesheet(*args, **kwargs):
        return None

    def list_themes():
        return ["dark_blue.xml", "light_blue.xml", "cyberpunk.xml"]
