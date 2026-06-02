# PSP PRX Decrypter - Rust Port

Port moderno y seguro en Rust de la herramienta de desencriptado de PRX/EBOOT.BIN del PlayStation Portable (PSP), basado en el motor KIRK.

## Features
- Detección automática de tipo de tag/encriptación
- Soporte para AES + KIRK engine decryption
- Validación de integridad con SHA1
- Parsing seguro de headers binarios
- Enfoque en memory safety (sin unsafe innecesario)

## Estructura del proyecto
- `src/headers.rs` → Parsing de headers
- `src/prx_decrypt.rs` → Lógica principal de desencriptado
- `src/kirk_lib/` → Implementación del engine KIRK
- `src/keys.rs` → Manejo de claves

## Cómo compilar y usar

```bash
cargo build --release
cargo run <ruta_al_archivo_prx_o_eboot>
```
## Ejecutar Test de Unidad
```bash
cargo test
```

## Roadmap
- [ ] Soporte completo para todos los tipos de tags
- [ ] Tests con archivos reales
- [ ] CLI más completa con argumentos
- [ ] ...