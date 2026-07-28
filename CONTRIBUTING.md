# Contribuir

## Añadir un check nuevo

Cada check implementa el protocolo `Check` (`filewhy/plugin.py`):

```python
class MiCheck:
    name = "mi_check"

    def run(self, path: Path) -> list[Finding]:
        ...  # devuelve [] si el fichero no es relevante para este check
```

Se registra vía entry point en tu propio `pyproject.toml`:

```toml
[project.entry-points."filewhy.checks"]
mi_check = "mi_paquete.check:MiCheck"
```

## Antes de un PR

- `ruff check .` y `pytest` en verde.
- Ningún check debe ejecutar código del fichero analizado, ejecutar
  JavaScript embebido, ni extraer archivos a disco — solo inspección
  estática de metadatos/estructura.
- Ficheros de test malformados/corruptos no deben hacer que un check lance
  una excepción sin capturar (debe devolver `[]` o un hallazgo, nunca crashear
  el resto del escaneo).
