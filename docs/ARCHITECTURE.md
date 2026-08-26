# Arquitectura

## Objetivos

La refactorización reduce el acoplamiento del antiguo `main.py` monolítico y
establece dependencias dirigidas hacia el dominio. La captura, SQLite y Flet
quedan en los bordes del sistema para que la agregación sea comprobable sin
Npcap, red ni interfaz gráfica.

## Capas

- `domain`: contiene `Packet`, `AppState`, `NetworkScan`, `ScanHost`,
  `ScanService` y contratos mínimos. No importa Flet, Scapy, psutil, Nmap ni
  SQLite.
- `infrastructure`: implementa captura, ejecucion y parseo XML de Nmap y
  persistencia. Puede depender del dominio, pero el dominio no depende de esta
  capa.
- `services`: ejecuta enriquecimiento DNS/geográfico fuera del hilo de UI.
- `presentation`: compone dependencias, maneja eventos y renderiza vistas.

## Decisiones

1. `Packet` se movió al dominio para evitar que la lógica de agregación importe
   Scapy o psutil indirectamente.
2. `AppState` recibe un enriquecedor por inyección. En pruebas usa una
   implementación nula; en producción recibe `IpInfoCache`.
3. La base se ubica en `data/netpulse.db`, calculada desde el proyecto, para no
   depender del directorio desde el que se inicia el proceso.
4. La persistencia acumula los cinco intervalos de 200 ms antes de escribir el
   resumen por segundo. Los contadores por IP usan deltas, evitando duplicar
   totales acumulados en cada upsert.
5. Existe un único punto de entrada, `python -m netpulse`; el punto de
   composición real vive en `netpulse.presentation.app`.
6. La captura pasiva y el escaneo activo son flujos independientes. Scapy
   alimenta indicadores en tiempo real; Nmap produce instantaneas auditables y
   comparables bajo demanda.
7. Nmap se ejecuta con una lista de argumentos y salida XML. No se usa una
   shell ni se interpreta texto orientado a humanos, reduciendo riesgos de
   inyeccion y fragilidad ante cambios de formato.
8. El riesgo se calcula en infraestructura a partir de puertos expuestos,
   servicios detectados y hallazgos NSE. La presentacion solo transforma ese
   resultado en indicadores visuales.
9. Los escaneos se normalizan en `network_scans`, `scan_hosts`,
   `scan_services` y `scan_alerts`. Esto permite consultar historial y cambios
   sin almacenar XML opaco como fuente unica.
10. Los diálogos se abren y cierran únicamente a través de
    `presentation/dialogs.py`. Flet 0.85 eliminó `Page.dialog`; asignarlo crea
    un atributo suelto y el diálogo nunca aparece. Un único punto de entrada
    evita que esa regresión vuelva y admite embebidos antiguos.
11. El esquema se versiona con `PRAGMA user_version`. Las migraciones de datos
    costosas se ejecutan una vez; las sentencias `CREATE ... IF NOT EXISTS` y
    los `ALTER TABLE` protegidos siguen siendo idempotentes en cada arranque.
12. La paleta activa vive en `presentation/theme.py`. Los controles montados se
    repintan con `recolor_tree`; los lienzos redibujan desde Python, por lo que
    `presentation/charts.py` mantiene su propia copia de la paleta y expone
    `recolor` para las series.
13. El registro se configura una sola vez en `logging_setup.py`. Flet Desktop se
    desprende de la consola, así que `stderr` no es un destino observable.
14. El repintado de tema recorre `app_layout` **y** los ocho envoltorios de
    vista. Flet solo alcanza el montado a través de `main_content`; los otros
    siete conservarían la paleta anterior. Un `seen` compartido evita repintar
    dos veces un control alcanzable desde ambas raíces.
15. `set_active_palette` reenlaza las constantes de color en los módulos
    consumidores. Las vistas construyen filas en cada refresco a partir de esos
    nombres, así que el contenido renderizado *después* de cambiar de tema solo
    sigue la paleta nueva si el nombre apunta al valor nuevo. `recolor_tree`
    cubre lo que ya existe; el reenlace cubre lo que aún no se ha creado.
16. El color se reparte según tres reglas. **Cromo**: el acento pinta marca,
    raíl, encabezados y foco; tiene valores propios y nunca reutiliza un color
    de estado. **Estado**: verde, ámbar y rojo significan logrado, atención y
    peligro; el caso benigno es neutro, no verde, para que noventa puertos sin
    incidencia no tapen los dos que importan. **Dato**: los tonos de protocolo
    y de serie codifican categoría. El marco de las tarjetas es estructural y
    uniforme; `card()` ya no acepta un color de realce.
17. El acento no se repinta por coincidencia de valor. Comparte color con un
    rol semántico (el cian de marca es también el de TCP), así que mapearlo
    arrastraba las insignias de datos, y lo dibujado después volvía al color
    original: dos colores para un mismo significado en la misma pantalla. Los
    controles de cromo se registran con `accented()` y `apply_accent()` los
    repinta directamente.
18. La paleta cumple un contrato colorimétrico verificable, no una elección
    estética libre. Está fijado en `tests/test_colorimetry.py`, que construye las
    ocho secciones de los seis temas, compone el fondo real de cada control y
    exige: 4.5:1 para texto pequeño, 3:1 para iconos y texto grande, 1.5 para
    que un borde separe su superficie, una escalera de elevación de 1.09 por
    paso y 1.19 de fondo a tarjeta, y que dos insignias de protocolo nunca
    coincidan a la vez en tono, luminancia y saturación.
19. El reflujo trabaja en píxeles enteros. Cada vista reparte su ancho con
    `snap()` y `split()` de `presentation/theme.py`: `snap()` redondea una
    medida y `split()` divide una fila en columnas enteras que suman exactamente
    el ancho disponible. Antes, cuentas como `(ancho - 36) / 5` daban 437,75 o
    587,66 y Flutter repartía el borde de 1 px entre dos píxeles físicos, así
    que dos tarjetas contiguas parecían tener marcos de grosor distinto y el
    borde derecho de la fila quedaba dentado. `tests/test_layout_geometry.py`
    recorre siete tamaños de escritorio y falla ante cualquier medida
    fraccionaria.
20. El ancho que una vista toma del viewport se redondea **hacia abajo** con
    `fit()`, no con `snap()`. Flet Desktop informa píxeles lógicos y el escalado
    DPI de Windows los deja fraccionarios: una pantalla de 2560x1600 al 150 %
    entrega 1601,666 px al panel central. `snap()` redondeaba eso hacia arriba y
    la fila quedaba un tercio de píxel más ancha que su contenedor; como todas
    las filas responsivas son `Row(wrap=True)` —un `Wrap` de Flutter— esa
    fracción bastaba para empujar la última tarjeta a un renglón propio. En
    pantalla completa el resumen perdía una columna de métricas, apilaba CPU y
    RAM y bajaba el donut de protocolos debajo de la gráfica, dejando un cuarto
    de la ventana vacío. `fit()` no puede desbordar al padre.
21. `translate_tree` traduce `value` solo en `Text`. En un `Dropdown` ese
    atributo es la clave de la opción seleccionada y en un `TextField` es lo que
    escribió el operador: traducirlos desligaba el control de sus propias
    opciones y el campo se dibujaba vacío (así se perdían el selector de interfaz
    de la cabecera y los filtros del explorador de paquetes). El recorrido sí
    entra en `columns`, `rows` y `cells`, que es donde `DataTable` guarda sus
    encabezados.

22. El mapa de red se repinta a sí mismo, así que su módulo figura en
    `PALETTE_CONSUMERS`. Seleccionar un nodo o cambiar el filtro de protocolo
    reconstruye toda la superficie —lienzo, nodos, panel de detalle y tabla— a
    partir de las constantes del módulo, y `recolor_tree` solo alcanza los
    controles que ya existen: sin ese registro, un mapa redibujado después de
    cambiar de tema volvía con la paleta oscura (tinta clara sobre tarjeta
    clara, placas oscuras sobre lienzo claro).
23. Los nodos del mapa nunca se solapan. Cada dispositivo ocupa una caja de
    124x126 px con su icono, su insignia y una placa de dos líneas; la
    disposición prueba dos familias de anillos —de fuera hacia dentro y de
    dentro hacia fuera— y se queda con la que necesita menos reducción para
    caber en un marco de proporción `FRAME_ASPECT`. El lienzo crece con el
    número de dispositivos y el visor ajusta el zoom hasta `MIN_FIT_ZOOM`; por
    debajo de eso se desplaza con el ratón. Antes, dos anillos fijos dentro de
    un lienzo fijo de 920x500 hacían que a partir de nueve dispositivos los
    nombres se pintaran encima de los iconos vecinos.

## Historial y recuperación de datos

- El esquema v2 añade `session_applications` y `session_events`. Conserva
  contadores, destinos, protocolos, picos, alertas y eventos importantes, pero
  nunca payloads de paquetes.
- Los respaldos usan la API `sqlite3_backup`, por lo que incluyen datos del WAL
  sin copiar una base en estado inconsistente.
- Una restauración valida `PRAGMA integrity_check` y las tablas mínimas, crea un
  respaldo previo y reemplaza la base mediante una operación atómica.
- La exportación completa genera un ZIP con manifiesto, copia SQLite, JSON y
  CSV por tabla; el historial individual usa JSON para mantener las estructuras
  de aplicaciones, destinos y eventos.

## Elementos eliminados

- El `main.py` monolítico de aproximadamente 2.000 líneas.
- El modelo `Packet` duplicado dentro del adaptador de captura.
- `DB.upsert_ip`, sin consumidores y redundante frente a `upsert_ips`.
- Imports globales mezclados de UI, red, persistencia y utilidades.
- `main.py` y los wrappers de arranque duplicados; `scripts/start.bat` y
  `python -m netpulse` abren una única aplicación nativa de escritorio.

## Reglas de evolución

- El dominio no debe importar módulos de `presentation` o `infrastructure`.
- Las consultas externas deben permanecer asíncronas y no bloquear Flet.
- Los escaneos activos deben ejecutarse fuera del hilo de UI, tener timeout y
  validar el objetivo antes de iniciar Nmap.
- Los cambios de esquema deben introducir migraciones explícitas y elevar
  `SCHEMA_VERSION` cuando incluyan un backfill de datos.
- Las vistas no deben tocar `page.dialog`, `page.show_dialog` ni
  `page.pop_dialog` directamente; `tests/test_dialogs.py` lo verifica.
- Todo color nuevo debe declararse como rol de paleta, no como literal, para que
  los temas claros y oscuros sigan siendo intercambiables.
- Un tema nuevo debe pasar `tests/test_colorimetry.py` sin relajar los umbrales.
- El rol `muted` hace de tinta terciaria y de insignia `OTHER`; debe mantenerse
  por debajo del 20 % de saturación para que se lea como «sin categoría» y no
  como un tercer azul junto a `cyan` y `blue`.
- Un acento nuevo no puede coincidir con `green`, `amber` ni `red`, y todo
  control de cromo debe registrarse con `accented()` en vez de confiar en que
  `recolor_tree` lo alcance por color.
- El verde se reserva para algo conseguido (un hallazgo resuelto, un puerto
  cerrado, una comprobación superada). La ausencia de problema es neutra.
- Toda medida calculada en un `set_viewport` debe pasar por `snap()`, `fit()` o
  `split()`; la que se deriva del viewport usa `fit()` y las internas `snap()`.
  `tests/test_layout_geometry.py` lo verifica en nueve tamaños, fraccionarios
  incluidos, y comprueba además que ninguna fila entregue a sus hijos más ancho
  del que ella misma tiene.
- Ningún panel debe dejar el fondo del escritorio a la vista: si una pestaña o
  una tarjeta ocupa menos que el alto disponible, el hueco va dentro del marco
  (por ejemplo el suelo de la pestaña «Escaneo»), y el resumen reparte su alto
  para que la fila inferior no quede bajo la barra de estado.
- Un par de campos solo se coloca en una fila si su ancho resultante deja sitio
  a la etiqueta traducida; por debajo de ese umbral se apilan en vez de
  recortarse.
- Todo módulo de presentación que reconstruya controles después del arranque
  debe estar en `PALETTE_CONSUMERS`; `recolor_tree` por sí solo no alcanza lo
  que se dibuja más tarde.
- Las cadenas de origen se escriben en inglés y se traducen con `tr()`; un
  literal en español en el código deja la otra mitad de la sección sin traducir.
  `tests/test_topology_map.py` lo verifica en el mapa.
- La lógica nueva de agregación debe cubrirse con pruebas sin captura real.
- Los nuevos perfiles Nmap deben declarar su alcance y costo para evitar
  escaneos sorpresivamente invasivos o lentos.
