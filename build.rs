// Страница и CGI — внутрь бинарника, сжатыми (gzip -9 хоста): на роутере cgmon
// распаковывает их в /tmp/cgmon/www (src/webfiles.rs). Файла нет в дереве — пропуск.
use std::io::Write;

fn main() {
    let out = std::env::var("OUT_DIR").unwrap();
    // (файл в репозитории, путь под /www, права)
    let files = [
        ("www/status.html", "status.html", 0o644),
        ("www/cgi-bin/api_status", "cgi-bin/api_status", 0o755),
        ("www/cgi-bin/api_router", "cgi-bin/api_router", 0o755),
        ("www/cgi-bin/api_set", "cgi-bin/api_set", 0o755),
        ("www/cgi-bin/api_hist", "cgi-bin/api_hist", 0o755),
    ];
    println!("cargo:rerun-if-changed=Cargo.toml"); // версия страницы
    let mut code = String::from("pub static FILES: &[(&str, u32, &[u8])] = &[\n");
    for (i, (src, name, mode)) in files.iter().enumerate() {
        println!("cargo:rerun-if-changed={src}");
        if !std::path::Path::new(src).exists() {
            continue;
        }
        let gz = format!("{out}/f{i}.gz");
        // версия страницы = версия cgmon: устаревшая копия в браузере сама перезагрузится
        let text = std::fs::read(src).unwrap();
        let text = String::from_utf8_lossy(&text).replace("__CGMON_PAGE_VERSION__", &std::env::var("CARGO_PKG_VERSION").unwrap());
        let plain = format!("{out}/f{i}.src");
        std::fs::write(&plain, text).unwrap();
        let o = std::process::Command::new("gzip").args(["-9", "-n", "-c", &plain]).output().expect("build.rs: нужен gzip");
        assert!(o.status.success(), "build.rs: gzip {src}");
        std::fs::File::create(&gz).unwrap().write_all(&o.stdout).unwrap();
        code += &format!("    ({name:?}, {mode:#o}, include_bytes!({gz:?})),\n");
    }
    code += "];\n";
    std::fs::write(format!("{out}/webfiles.rs"), code).unwrap();
}
