//! Which NVD product an installed program is. Registry names are free text, so a built-in table
//! covers widely installed and often attacked programs; other programs get a CPE guessed from
//! publisher and name, which only finds data when both match NVD's spelling.

use super::inventory::Program;
use super::nvd::Cpe;
use super::version;

/// Where the program's real version is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionFrom {
    DisplayVersion,
    /// DisplayVersion is a build number (Python, JetBrains IDEs, NVIDIA drivers).
    Name,
}

#[derive(Debug)]
pub struct Known {
    /// Lowercase; the name equals one or starts with it followed by a non-alphanumeric character.
    pub names: &'static [&'static str],
    /// Lowercase words that must all be in the name.
    pub with: &'static [&'static str],
    /// Lowercase words that rule it out.
    pub without: &'static [&'static str],
    /// Registry key suffixes that identify it whatever the display language.
    pub keys: &'static [&'static str],
    pub cpes: &'static [Cpe],
    pub version: VersionFrom,
}

const fn cpe(vendor: &'static str, product: &'static str) -> Cpe {
    Cpe { vendor, product }
}

const fn k(names: &'static [&'static str], cpes: &'static [Cpe]) -> Known {
    Known {
        names,
        with: &[],
        without: &[],
        keys: &[],
        cpes,
        version: VersionFrom::DisplayVersion,
    }
}

impl Known {
    const fn with(mut self, words: &'static [&'static str]) -> Self {
        self.with = words;
        self
    }
    const fn without(mut self, words: &'static [&'static str]) -> Self {
        self.without = words;
        self
    }
    const fn keys(mut self, suffixes: &'static [&'static str]) -> Self {
        self.keys = suffixes;
        self
    }
    const fn version_from_name(mut self) -> Self {
        self.version = VersionFrom::Name;
        self
    }
}

/// Checked against NVD's product names. Order matters: the first match wins.
pub const KNOWN: &[Known] = &[
    // Browsers and mail.
    k(&["google chrome"], &[cpe("google", "chrome")]),
    k(&["microsoft edge"], &[cpe("microsoft", "edge_chromium")]).without(&["webview", "update"]),
    k(&["mozilla firefox"], &[cpe("mozilla", "firefox_esr")]).with(&["esr"]),
    k(&["mozilla firefox"], &[cpe("mozilla", "firefox")]),
    k(&["mozilla thunderbird"], &[cpe("mozilla", "thunderbird")]),
    k(&["brave"], &[cpe("brave", "brave")]),
    k(&["opera stable", "opera"], &[cpe("opera", "opera_browser")]).without(&["gx"]),
    k(&["tor browser"], &[cpe("torproject", "tor_browser")]),
    // Archives, documents, media.
    k(&["7-zip"], &[cpe("7-zip", "7-zip")]),
    k(&["winrar"], &[cpe("rarlab", "winrar")]),
    k(&["vlc media player"], &[cpe("videolan", "vlc_media_player")]),
    k(&["notepad++"], &[cpe("notepad-plus-plus", r"notepad\+\+")]),
    k(&["libreoffice"], &[cpe("libreoffice", "libreoffice")]).without(&["help pack"]),
    k(
        &["adobe acrobat"],
        &[cpe("adobe", "acrobat_reader_dc"), cpe("adobe", "acrobat_dc")],
    ),
    k(&["foxit pdf reader"], &[cpe("foxit", "pdf_reader")]),
    k(&["gimp"], &[cpe("gimp", "gimp")]),
    k(&["inkscape"], &[cpe("inkscape", "inkscape")]),
    k(&["blender"], &[cpe("blender", "blender")]),
    k(&["irfanview"], &[cpe("irfanview", "irfanview")]),
    k(&["imagemagick"], &[cpe("imagemagick", "imagemagick")]),
    k(&["gpl ghostscript"], &[cpe("artifex", "ghostscript")]),
    k(&["itunes"], &[cpe("apple", "itunes")]),
    k(&["audacity"], &[cpe("audacityteam", "audacity")]),
    // Remote access, VPN, transfer.
    k(&["putty"], &[cpe("putty", "putty")]),
    k(&["winscp"], &[cpe("winscp", "winscp")]),
    k(&["filezilla server"], &[cpe("filezilla-project", "filezilla_server")]),
    k(&["filezilla"], &[cpe("filezilla-project", "filezilla_client")]),
    k(&["teamviewer"], &[cpe("teamviewer", "teamviewer")]),
    k(&["anydesk"], &[cpe("anydesk", "anydesk")]),
    k(&["openvpn connect"], &[cpe("openvpn", "connect")]),
    k(&["openvpn"], &[cpe("openvpn", "openvpn")]),
    k(&["forticlient"], &[cpe("fortinet", "forticlient")]),
    k(&["cisco secure client"], &[cpe("cisco", "secure_client")]),
    k(
        &["cisco anyconnect secure mobility client"],
        &[cpe("cisco", "anyconnect_secure_mobility_client")],
    ),
    k(&["citrix workspace"], &[cpe("citrix", "workspace")]),
    k(&["tightvnc"], &[cpe("tightvnc", "tightvnc")]),
    k(&["ultravnc"], &[cpe("uvnc", "ultravnc")]),
    k(&["mremoteng"], &[cpe("mremoteng", "mremoteng")]),
    k(&["qbittorrent"], &[cpe("qbittorrent", "qbittorrent")]),
    k(&["nextcloud"], &[cpe("nextcloud", "desktop")]),
    // Passwords and encryption.
    k(&["keepass password safe"], &[cpe("keepass", "keepass")]),
    k(&["keepassxc"], &[cpe("keepassxc", "keepassxc")]),
    k(&["veracrypt"], &[cpe("idrix", "veracrypt")]),
    k(&["openssl"], &[cpe("openssl", "openssl")]),
    // Messaging and meetings.
    k(
        &["zoom workplace", "zoom"],
        &[cpe("zoom", "workplace_desktop"), cpe("zoom", "meetings")],
    ),
    k(&["telegram desktop"], &[cpe("telegram", "telegram_desktop")]),
    k(&["signal"], &[cpe("signal", "signal-desktop")]),
    k(&["pidgin"], &[cpe("pidgin", "pidgin")]),
    // Development.
    k(&["git"], &[cpe("git-scm", "git")]).without(&["lfs", "extensions", "credential", "desktop"]),
    k(&["python"], &[cpe("python", "python")])
        .without(&[
            "launcher",
            "documentation",
            "test suite",
            "core interpreter",
            "standard library",
            "executables",
            "development libraries",
            "tcl/tk",
            "pip bootstrap",
            "utility scripts",
            "add to path",
            "debug",
        ])
        .version_from_name(),
    k(&["node.js"], &[cpe("nodejs", "node.js")]),
    k(&["go programming language"], &[cpe("golang", "go")]),
    k(
        &["microsoft visual studio code"],
        &[cpe("microsoft", "visual_studio_code")],
    ),
    k(&["powershell 7"], &[cpe("microsoft", "powershell")]),
    k(&["docker desktop"], &[cpe("docker", "desktop")]),
    k(&["wireshark"], &[cpe("wireshark", "wireshark")]),
    k(&["vagrant"], &[cpe("hashicorp", "vagrant")]),
    k(&["intellij idea"], &[cpe("jetbrains", "intellij_idea")]).version_from_name(),
    k(&["pycharm"], &[cpe("jetbrains", "pycharm")]).version_from_name(),
    k(&["webstorm"], &[cpe("jetbrains", "webstorm")]).version_from_name(),
    k(&["clion"], &[cpe("jetbrains", "clion")]).version_from_name(),
    k(&["jetbrains rider"], &[cpe("jetbrains", "rider")]).version_from_name(),
    k(&["goland"], &[cpe("jetbrains", "goland")]).version_from_name(),
    k(&["phpstorm"], &[cpe("jetbrains", "phpstorm")]).version_from_name(),
    k(&["jetbrains toolbox"], &[cpe("jetbrains", "toolbox")]),
    k(&["postgresql"], &[cpe("postgresql", "postgresql")]),
    k(&["mysql server"], &[cpe("oracle", "mysql")]),
    k(&["mongodb"], &[cpe("mongodb", "mongodb")]).without(&["compass", "shell", "tools"]),
    // Virtualization and drivers.
    k(
        &["oracle vm virtualbox", "oracle virtualbox"],
        &[cpe("oracle", "vm_virtualbox")],
    ),
    k(&["vmware workstation"], &[cpe("vmware", "workstation")]),
    k(&["nvidia graphics driver"], &[cpe("nvidia", "gpu_display_driver")])
        .keys(&["_Display.Driver"])
        .version_from_name(),
    k(&["hp support assistant"], &[cpe("hp", "support_assistant")]),
];

fn name_matches(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix)
        .is_some_and(|rest| rest.chars().next().is_none_or(|c| !c.is_alphanumeric()))
}

pub fn lookup(program: &Program) -> Option<&'static Known> {
    let name = program.name.to_lowercase();
    KNOWN.iter().find(|k| {
        k.keys.iter().any(|s| program.key.ends_with(s))
            || (k.names.iter().any(|p| name_matches(&name, p))
                && k.with.iter().all(|w| name.contains(w))
                && !k.without.iter().any(|w| name.contains(w)))
    })
}

/// The version to compare with NVD, normalized to its first version-looking token.
pub fn program_version(program: &Program, from: VersionFrom) -> Option<String> {
    let from_display = || version::extract(&program.version);
    match from {
        VersionFrom::DisplayVersion => from_display().or_else(|| version::extract(&program.name)),
        VersionFrom::Name => version::extract(&program.name).or_else(from_display),
    }
}

const COMPANY_SUFFIXES: &[&str] = &[
    "incorporated",
    "inc",
    "llc",
    "ltd",
    "limited",
    "gmbh",
    "corporation",
    "corp",
    "co",
    "company",
    "s.a",
    "sa",
    "ag",
    "bv",
    "b.v",
    "oy",
    "ab",
    "srl",
    "pty",
    "plc",
    "software",
    "technologies",
    "foundation",
    "project",
    "team",
    "the",
];

fn tokens(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !(c.is_alphanumeric() || c == '+' || c == '-' || c == '.'))
        .map(|t| t.trim_matches(['.', '-']).to_string())
        .filter(|t| !t.is_empty())
        .collect()
}

fn is_noise(t: &str) -> bool {
    t.chars().next().is_some_and(|c| c.is_ascii_digit())
        || matches!(
            t,
            "x64" | "x86" | "64-bit" | "32-bit" | "bit" | "amd64" | "arm64" | "win64" | "win32" | "en-us" | "version"
        )
}

/// `cpe:2.3:a:<publisher>:<name>` in NVD's style ("Igor Pavlov" / "WinMerge 2.16.44 x64" gives
/// igor_pavlov:winmerge). Guesses only ever find data when NVD spells both the same.
pub fn guess(program: &Program) -> Option<(String, String)> {
    let mut vendor: Vec<String> = tokens(&program.publisher);
    while vendor.last().is_some_and(|t| COMPANY_SUFFIXES.contains(&t.as_str())) {
        vendor.pop();
    }
    vendor.retain(|t| t != "the");
    let product: Vec<String> = tokens(&program.name).into_iter().take_while(|t| !is_noise(t)).collect();
    let ascii = |s: &str| s.chars().all(|c| c.is_ascii_alphanumeric() || "_-.+".contains(c));
    let (vendor, product) = (vendor.join("_"), product.join("_"));
    if vendor.is_empty() || product.is_empty() || !ascii(&vendor) || !ascii(&product) {
        return None;
    }
    // CPE escapes these.
    let escape = |s: &str| s.replace('+', r"\+");
    Some((escape(&vendor), escape(&product)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str, version: &str) -> Program {
        Program {
            name: name.into(),
            version: version.into(),
            publisher: String::new(),
            key: String::new(),
        }
    }

    fn product(name: &str) -> Option<&'static str> {
        lookup(&p(name, "1")).map(|k| k.cpes[0].product)
    }

    #[test]
    fn maps_registry_names_to_nvd_products() {
        assert_eq!(product("7-Zip 24.06 (x64)"), Some("7-zip"));
        assert_eq!(product("7-Zip 24.06 (x64 edition)"), Some("7-zip"));
        assert_eq!(product("Mozilla Firefox (x64 en-US)"), Some("firefox"));
        assert_eq!(product("Mozilla Firefox 128.4.0 ESR (x64 en-US)"), Some("firefox_esr"));
        assert_eq!(product("Microsoft Edge"), Some("edge_chromium"));
        assert_eq!(product("Microsoft Edge WebView2 Runtime"), None);
        assert_eq!(product("Notepad++ (64-bit x64)"), Some(r"notepad\+\+"));
        assert_eq!(product("Git"), Some("git"));
        assert_eq!(product("Git LFS version 3.5.1"), None);
        assert_eq!(product("GitHub Desktop"), None, "word boundary");
        assert_eq!(product("Python 3.12.4 (64-bit)"), Some("python"));
        assert_eq!(product("Python Launcher"), None);
        assert_eq!(product("FileZilla 3.68.1"), Some("filezilla_client"));
        assert_eq!(product("FileZilla Server"), Some("filezilla_server"));
        assert_eq!(product("Opera GX Stable 114.0"), None);
        assert_eq!(product("Bravura"), None);
        assert_eq!(product("Zoom Workplace (64-bit)"), Some("workplace_desktop"));
    }

    #[test]
    fn takes_the_version_from_where_the_vendor_puts_it() {
        let python = p("Python 3.12.4 (64-bit)", "3.12.4150.0");
        assert_eq!(
            program_version(&python, lookup(&python).unwrap().version).as_deref(),
            Some("3.12.4")
        );
        let nvidia = p("NVIDIA Graphics Driver 566.14", "32.0.15.6614");
        assert_eq!(
            program_version(&nvidia, lookup(&nvidia).unwrap().version).as_deref(),
            Some("566.14")
        );
        let zoom = p("Zoom Workplace (64-bit)", "6.2.5 (50227)");
        assert_eq!(
            program_version(&zoom, lookup(&zoom).unwrap().version).as_deref(),
            Some("6.2.5")
        );
        let ru = Program {
            key: "{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}_Display.Driver".into(),
            ..p("NVIDIA Графический драйвер 581.57", "32.0.15.8157")
        };
        let known = lookup(&ru).expect("matched by registry key");
        assert_eq!(program_version(&ru, known.version).as_deref(), Some("581.57"));
        let steam = p("Steam", "");
        assert_eq!(program_version(&steam, VersionFrom::DisplayVersion), None);
    }

    #[test]
    fn guesses_cpes_from_publisher_and_name() {
        let g = |publisher: &str, name: &str| {
            guess(&Program {
                name: name.into(),
                version: String::new(),
                publisher: publisher.into(),
                key: String::new(),
            })
        };
        assert_eq!(
            g("Thingamajig Software, Inc.", "Gizmo Pro 2.4 (x64)"),
            Some(("thingamajig".into(), "gizmo_pro".into()))
        );
        assert_eq!(
            g("The WinMerge Project", "WinMerge 2.16.44 x64"),
            Some(("winmerge".into(), "winmerge".into()))
        );
        assert_eq!(
            g("Igor Pavlov", "Foo++"),
            Some(("igor_pavlov".into(), r"foo\+\+".into()))
        );
        assert_eq!(g("", "Gizmo"), None);
        assert_eq!(g("Яндекс", "Браузер"), None);
    }
}
