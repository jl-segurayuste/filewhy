# filewhy

`file` con esteroides, pero como agregador: en vez de una herramienta por
formato, un solo informe con las señales de riesgo que de verdad importan —
sin ejecutar ni abrir nada peligroso.

```
$ filewhy scan ./descargas

── descargas/foto_vacaciones.jpg ──────────────────
  [HIGH  ] Extensión '.jpg' pero el contenido real es PE/EXE (Windows)
           El fichero no es lo que su extensión afirma -- revisar antes de abrirlo o ejecutarlo.

── descargas/factura.pdf ───────────────────────────
  [HIGH  ] El PDF contiene JavaScript embebido
           Revisar el JS antes de abrir el PDF en un lector que lo ejecute.

Total: 2 hallazgo(s) en 2 de 15 fichero(s).
```

## Por qué existe

Ya existen buenas herramientas por formato (analizadores de PDF, de APK, de
ZIP...), pero ninguna que las agregue en un único informe de riesgo —
exactamente el mismo hueco que llevó a construir
[checkforge](https://github.com/jl-segurayuste/checkforge) para repos de
código. `filewhy` hace lo mismo para ficheros sueltos: identidad real vs.
extensión, riesgos estructurales de archivos ZIP-based (ZIP/JAR/APK/DOCX/
XLSX), y riesgos de PDF.

## Instalación

Todavía no está en PyPI:

```bash
pip install git+https://github.com/jl-segurayuste/filewhy.git
```

## Uso

```bash
filewhy scan fichero.pdf
filewhy scan ./carpeta                  # recursivo
filewhy scan ./carpeta --only file_identity
filewhy scan ./carpeta --json
filewhy scan ./carpeta --fail-on high   # código de salida 1 si hay algo "high"
filewhy list-checks
```

## Checks incluidos

| Check | Qué detecta |
|---|---|
| `file_identity` | La extensión promete un tipo, pero la firma de bytes real es otra (un `.jpg` que en realidad es un ejecutable) |
| `archive_risk` | En ZIP/JAR/APK/DOCX/XLSX: path traversal ("zip-slip"), miembros ejecutables, ratio de compresión sospechoso (posible zip bomb) |
| `pdf_risk` | JavaScript embebido, apertura automática (`/OpenAction`), ficheros embebidos, enlaces URI, si está cifrado |

Ningún check extrae archivos a disco, ejecuta JavaScript, ni abre ficheros
embebidos — solo lee metadatos/estructura (vía `zipfile`/`pypdf`, ambas
bibliotecas maduras que no ejecutan contenido).

## Desarrollo

```bash
pip install -e ".[dev]"
ruff check .
pytest
```
