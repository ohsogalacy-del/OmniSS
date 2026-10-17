use std::process::Command;

#[derive(Debug, Clone)]
pub struct DnsHit {
    pub domain: String,
    pub cheat_association: String,
    pub raw_entry: String,
}

// Database of 30+ known cheat licensing & download domains
const CHEAT_DOMAINS: &[(&str, &str)] = &[
    ("vape.gg", "Vape V4 / Vape Lite (Manthe)"),
    ("drip.gg", "Drip Lite / Drip Client"),
    ("dripclient.com", "Drip Lite"),
    ("slinky.gg", "Slinky Ghost Client"),
    ("prestigeclient.vip", "Prestige Client (Crystal / Sword)"),
    ("breezemc.com", "Breeze Ghost Client"),
    ("breezestore.net", "Breeze Store"),
    ("karma.rip", "Karma Ghost Client"),
    ("entropy.club", "Entropy Ghost Client"),
    ("whiteout.gg", "Whiteout Client"),
    ("sloth.wtf", "Sloth Ghost Client"),
    ("antic.lol", "Antic Ghost Client"),
    ("dreamclient.net", "Dream Ghost Client"),
    ("futureclient.net", "Future Client (Anarchy)"),
    ("rusherhack.org", "RusherHack (Anarchy)"),
    ("boze.dev", "Boze Client"),
    ("meteorclient.com", "Meteor Client"),
    ("riseclient.com", "Rise Blatant Client"),
    ("novoline.lol", "Novoline Client"),
    ("novoline.wtf", "Novoline Client"),
    ("tenacity.dev", "Tenacity Client"),
    ("liquidbounce.net", "LiquidBounce"),
    ("thunderhack.net", "Thunderhack Recode"),
    ("augustus.lol", "Augustus Client"),
    ("astolfo.lgbt", "Astolfo Client"),
    ("moonclient.xyz", "Moon Client"),
    ("doomsdayclient", "Doomsday Client"),
];

pub fn audit_dns_cache() -> Vec<DnsHit> {
    let mut hits = Vec::new();

    // Query Windows DNS resolver cache via ipconfig
    let output = Command::new("ipconfig")
        .arg("/displaydns")
        .output();

    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let lower = stdout.to_lowercase();

        for &(domain, cheat) in CHEAT_DOMAINS {
            if lower.contains(domain) {
                // Find context lines
                let line_ctx = stdout
                    .lines()
                    .filter(|l| l.to_lowercase().contains(domain))
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" | ");

                hits.push(DnsHit {
                    domain: domain.to_string(),
                    cheat_association: cheat.to_string(),
                    raw_entry: line_ctx,
                });
            }
        }
    }

    hits
}
