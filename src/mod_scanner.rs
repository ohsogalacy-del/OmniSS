use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ModScanResult {
    pub jar_name: String,
    pub path: String,
    pub suspicion_score: u32, // 0% to 100%
    pub is_trojan: bool,
    pub matched_heuristics: Vec<HeuristicHit>,
}

#[derive(Debug, Clone)]
pub struct HeuristicHit {
    pub category: String,
    pub weight: u32,
    pub description: String,
}

// Known verified canonical mod IDs and legitimate package roots
const CANONICAL_MOD_WHITELIST: &[(&str, &str)] = &[
    ("sodium", "net.caffeinemc.mods.sodium"),
    ("iris", "net.irisshaders.iris"),
    ("cloth-config", "me.shedaniel.clothconfig2"),
    ("cloth-config2", "me.shedaniel.clothconfig2"),
    ("cloth-config-v2", "me.shedaniel.clothconfig2"),
    ("viafabricplus", "de.florianmichael.viafabricplus"),
    ("viaversion", "com.viaversion.viaversion"),
    ("viabackwards", "com.viaversion.viabackwards"),
    ("vialegacy", "net.raphimc.vialegacy"),
    ("viabedrock", "net.raphimc.viabedrock"),
    ("fabric-api", "net.fabricmc.fabric"),
    ("voicechat", "de.maxhenkel.voicechat"),
    ("simple-voice-chat", "de.maxhenkel.voicechat"),
    ("litematica", "fi.dy.masa.litematica"),
    ("c2me", "com.ishland.c2me"),
    ("mixinextras", "com.llamalad7.mixinextras"),
    ("moreculling", "ca.fxco.moreculling"),
    ("notenoughanimations", "dev.tr7zw.notenoughanimations"),
    ("animatium", "dev.tr7zw.animatium"),
    ("appleskin", "squeek.appleskin"),
    ("architectury", "dev.architectury"),
    ("bobby", "de.johni0702.minecraft.bobby"),
    ("dynamicfps", "dynamicfps"),
    ("dynamic_fps", "net.lostluma.dynamic_fps"),
    ("entityculling", "dev.tr7zw.entityculling"),
    ("essential", "gg.essential"),
    ("feather", "net.digitalingot.feather"),
    ("sodium-extra", "me.flashyreese.mods.sodiumextra"),
    ("tiertagger", "net.tiertagger"),
    ("tiers", "net.tiers"),
    ("lifestealutils", "net.lifestealutils"),
    ("shieldfixes", "net.shieldfixes"),
    ("combat-hitboxes", "me.sootysplash.box"),
    ("combat-hitbox", "me.sootysplash.box"),
    ("betterhitreg", "you.jass.betterhitreg"),
    ("bowboost", "net.paleclient.bowboost"),
    ("walksylib", "main.walksy.lib"),
    ("shieldstatus", "walksy.shieldstatus"),
    ("nochatrestrictions", "com.aizistral.nochatrestrictions"),
    ("tick-sync", "loggamja.sync"),
    ("serverpingfixer", "de.joker"),
    ("marlowcrystal", "com.deathmotion.marlowcrystal"),
    ("herosanchoroptimizer", "hero.bane.herosanchoroptimizer"),
    ("jcraft", "net.arna.jcraft"),
    ("badoptimizations", "me.nullfire"),
    ("bettercapes", "dev.tr7zw.bettercapes"),
    ("crosshairindicator", "com.bawn"),
    ("cursorcenteredfix", "net.pedroksl.cursorcenteredfix"),
    ("ias", "net.ias"),
    ("reeses-sodium-options", "me.flashyreese.mods.reesessodiumoptions"),
    ("scoreboardtweaks", "de.joker.scoreboardtweaks"),
    ("sodium-fullbright", "net.sodiumfullbright"),
    ("placeholder-api", "eu.pb4.placeholders"),
    ("ukus-armor-hud", "me.uku"),
    ("ukulib", "me.uku.ukulib"),
    ("variants-cit", "fr.estecka.variantscit"),
    ("yet_another_config_lib_v3", "dev.isxander.yacl"),
    ("yacl", "dev.isxander.yacl"),
];

// High-confidence cheat signatures targeting actual cheat mod packages & architectures
const CHEAT_SIGNATURE_RULES: &[(&str, &str, u32, &str)] = &[
    // --- Mace Attack Assistance (MAA) & Mace Cores ---
    (
        "Mace Core / Attack Assist",
        "maceattackassistance",
        90,
        "Confirmed Mace Attack Assistance (MAA) cheat package/classes",
    ),
    (
        "Mace Core / Attack Assist",
        "com.papack.maceattackassistance",
        100,
        "Papack MAA Mace Attack Assist Trojan payload",
    ),
    (
        "Mace Core / Attack Assist",
        "AutoMace",
        85,
        "Automated Mace smash attack triggerbot routine",
    ),
    (
        "Mace Core / Attack Assist",
        "SmashAssist",
        80,
        "Mace fall-damage smash assist automation",
    ),

    // --- Trident's Cart Core & Minecart PvP Exploits ---
    (
        "Cart Core / Minecart Exploit",
        "cartcore",
        95,
        "Confirmed Trident Cart Core / Cart PvP exploit suite",
    ),
    (
        "Cart Core / Minecart Exploit",
        "tridents-cartcore",
        100,
        "Trident's Premium Cart Core macro mod",
    ),
    (
        "Cart Core / Minecart Exploit",
        "cartcore.mixins.json",
        90,
        "Cart Core automated TNT rail injection mixins",
    ),

    // --- Cyemer Ghost Client (disguised as Dynamic FPS or standalone) ---
    (
        "Ghost Client Suite",
        "cyemer",
        100,
        "Cyemer Ghost Client suite (AutoCrit, AutoMace, InstaCart, SnapTap, TriggerBot, SelfDestruct)",
    ),
    (
        "Ghost Client Suite",
        "com.slither.cyemer",
        100,
        "Cyemer Ghost Client core package",
    ),
    (
        "Ghost Client Suite",
        "cyemer.client.mixins.json",
        100,
        "Cyemer Ghost Client mixin configuration",
    ),

    // --- imnotcheatinn Ghost Client ---
    (
        "Ghost Client Suite",
        "imnotcheatinn",
        100,
        "imnotcheatinn Mace/Combat Ghost Client suite (SmartAim, LegitClicks, LegitRotations)",
    ),
    (
        "Ghost Client Suite",
        "com.imnotcheatinn",
        100,
        "imnotcheatinn Ghost Client package",
    ),

    // --- Vengeance Client ---
    (
        "Ghost Client Suite",
        "vengeanceclient",
        100,
        "Vengeance Ghost Client (SnapTap, WTap, Velocity, JNA NativeMouse)",
    ),
    (
        "Ghost Client Suite",
        "com.vengeance.vengeanceclient",
        100,
        "Vengeance Ghost Client package",
    ),
    (
        "Ghost Client Suite",
        "vengeance-client",
        100,
        "Vengeance Ghost Client archive identifier",
    ),

    // --- Marlowww & Crystal / Anchor Macros ---
    (
        "Ghost Client Suite",
        "imnotcheatingyouare",
        100,
        "Marlowww Ghost Client Suite (AimAssist, AutoClicker, AutoTotem, AutoMace, AnchorMacro)",
    ),
    (
        "Ghost Client Suite",
        "com.eclipseware.imnotcheatingyouare",
        100,
        "Marlowww Ghost Client engine package",
    ),
    (
        "Anchor / Crystal Core",
        "marlowww",
        95,
        "Marlowww custom PvP exploit / macro client classes",
    ),
    (
        "Anchor / Crystal Core",
        "anchormacro",
        85,
        "Automated Respawn Anchor glowstone charging macro",
    ),
    (
        "Shield Exploit",
        "instantshield",
        85,
        "Instant Shield (Removes 5-tick vanilla shield raise delay)",
    ),
    (
        "Shield Exploit",
        "no shield delay",
        80,
        "Anchor's No Shield Delay combat exploit",
    ),
    (
        "Combat Macro",
        "pearl-catcher",
        85,
        "Pearl Catcher automated mid-air pearl retrieval macro",
    ),
    (
        "Combat Macro",
        "com.invisapple.pearlcatcher",
        90,
        "Pearl Catcher automation package",
    ),

    // --- Hitbox & Reach Modifications (Strictly Entity Reach Manipulation) ---
    (
        "Reach / Hitbox Expansion",
        "expandHitbox",
        90,
        "Entity bounding box reach expansion routine",
    ),
    (
        "Reach / Hitbox Expansion",
        "hitbox_expander",
        90,
        "Entity bounding box reach expansion routine",
    ),

    // --- Baritone Bot ---
    (
        "Baritone Bot",
        "baritone/api/BaritoneAPI",
        60,
        "Baritone automated pathfinding & botting engine",
    ),

    // --- True Synthetic Clicks (KeyBinding.setPressed outside Input loop) ---
    (
        "Synthetic Click / Spoofing",
        "options.attackKey.setPressed(true)",
        80,
        "Synthetically forces attackKey down via automation thread",
    ),
    // --- Remote Payload Droppers & In-Memory HWID Loaders ---
    (
        "Remote HWID Dropper / Loader",
        "net/fabricmc/loader/impl/launch/FabricLauncherBase",
        95,
        "Accesses raw Fabric classloader to inject dynamic in-memory bytecode",
    ),
    (
        "Remote HWID Dropper / Loader",
        "oshi/PlatformEnum",
        90,
        "Hardware ID / OS fingerprinting query routine in Fabric mod",
    ),
    (
        "Remote HWID Dropper / Loader",
        "oshi/util/tuples/Quartet",
        90,
        "Hardware ID tuple inspection routine",
    ),
];

pub fn scan_mods_directory() -> Vec<ModScanResult> {
    let mut results = Vec::new();
    let mut mods_paths = Vec::new();

    // Check default .minecraft/mods
    if let Ok(appdata) = std::env::var("APPDATA") {
        let default_mods = PathBuf::from(&appdata).join(".minecraft\\mods");
        if default_mods.exists() {
            mods_paths.push(default_mods);
        }

        // Feather Client mods
        let feather_mods = PathBuf::from(&appdata).join(".feather\\user-mods");
        if feather_mods.exists() {
            mods_paths.push(feather_mods);
        }

        // Modrinth App profiles
        let modrinth_mods = PathBuf::from(&appdata).join("ModrinthApp\\profiles");
        if modrinth_mods.exists() {
            mods_paths.push(modrinth_mods);
        }
    }

    // Check user profile for common multi-instance launchers (Prism, CurseForge, Modrinth)
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let prism_mods = PathBuf::from(&userprofile).join("AppData\\Roaming\\PrismLauncher\\instances");
        if prism_mods.exists() {
            mods_paths.push(prism_mods);
        }

        let curseforge_mods = PathBuf::from(&userprofile).join("curseforge\\minecraft\\Instances");
        if curseforge_mods.exists() {
            mods_paths.push(curseforge_mods);
        }
    }

    for dir in mods_paths {
        collect_and_scan_jars(&dir, &mut results);
    }

    results
}

fn collect_and_scan_jars(dir: &Path, results: &mut Vec<ModScanResult>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("jar") {
                if let Some(res) = audit_single_jar(&path) {
                    results.push(res);
                }
            } else if path.is_dir() {
                collect_and_scan_jars(&path, results);
            }
        }
    }
}

fn audit_single_jar(jar_path: &Path) -> Option<ModScanResult> {
    let file = File::open(jar_path).ok()?;
    let mut archive = match zip::ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => return None,
    };

    let mut mod_id = String::new();
    let mut all_filenames = Vec::new();

    // Extract fabric.mod.json or mcmod.info metadata
    for i in 0..archive.len() {
        if let Ok(mut zip_file) = archive.by_index(i) {
            let name = zip_file.name().to_string();
            all_filenames.push(name.clone());

            if name == "fabric.mod.json" || name == "quilt.mod.json" {
                let mut content = String::new();
                if zip_file.read_to_string(&mut content).is_ok() {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(id) = val.get("id").and_then(|v| v.as_str()) {
                            mod_id = id.to_lowercase();
                        }
                    }
                }
            }
        }
    }

    let has_plugin_yml = all_filenames.iter().any(|f| f == "plugin.yml");
    let has_mod_metadata = all_filenames.iter().any(|f| {
        f == "fabric.mod.json"
            || f == "quilt.mod.json"
            || f == "mcmod.info"
            || f == "META-INF/mods.toml"
    });

    // If it's a server plugin (Spigot/Bukkit/Paper) without client mod metadata, ignore for client screenshare
    if has_plugin_yml && !has_mod_metadata {
        return None;
    }

    let mut total_score: u32 = 0;
    let mut hits = Vec::new();
    let mut is_trojan = false;
    let mut seen_patterns = std::collections::HashSet::new();

    // 1. Check for Trojan Disguised Mods (e.g., Cloth Config containing Mace Attack Assistance, or Dynamic FPS containing Cyemer!)
    for &(canonical_id, _legitimate_pkg) in CANONICAL_MOD_WHITELIST {
        if mod_id == canonical_id {
            // Check if foreign cheat packages are inside this supposedly clean mod
            for fname in &all_filenames {
                let lower_fname = fname.to_lowercase();
                if lower_fname.contains("maceattackassistance")
                    || lower_fname.contains("cartcore")
                    || lower_fname.contains("imnotcheatingyouare")
                    || lower_fname.contains("papack")
                    || lower_fname.contains("cyemer")
                    || lower_fname.contains("imnotcheatinn")
                    || lower_fname.contains("vengeanceclient")
                {
                    is_trojan = true;
                    total_score = 100;
                    hits.push(HeuristicHit {
                        category: "FATAL: Trojan Disguised Mod".to_string(),
                        weight: 100,
                        description: format!(
                            "Mod claims to be '{}' but contains foreign cheat package: '{}'!",
                            canonical_id, fname
                        ),
                    });
                    break;
                }
            }
            break;
        }
    }

    // Check for Remote HWID Dropper / Loader (e.g. fabric-rendering-indigo-v2.jar / "fix")
    let has_oshi = all_filenames.iter().any(|f| {
        let l = f.to_lowercase();
        l.contains("oshi") || l.contains("platformenum") || l.contains("sysfs") || l.contains("iokit")
    });
    let has_single_letter_classes = all_filenames.iter().filter(|f| {
        f.ends_with(".class") && f.len() <= 7 && !f.contains('/')
    }).count() >= 3;
    let is_prelaunch = all_filenames.iter().any(|f| f == "Init.class") || mod_id == "fix";

    if (has_oshi || is_prelaunch) && has_single_letter_classes {
        is_trojan = true;
        total_score = 100;
        hits.push(HeuristicHit {
            category: "FATAL: HWID-Locked Remote Cheat Dropper".to_string(),
            weight: 100,
            description: format!(
                "Mod '{}' is an obfuscated PreLaunch HWID remote payload dropper (fingerprints hardware to download/decrypt memory cheat)",
                mod_id
            ),
        });
    }

    // If verified canonical mod with NO trojan payload, return clean 0% immediately
    let is_canonical = CANONICAL_MOD_WHITELIST.iter().any(|&(id, _)| id == mod_id) && !is_trojan;
    if is_canonical {
        let jar_name = jar_path.file_name()?.to_string_lossy().to_string();
        return Some(ModScanResult {
            jar_name,
            path: jar_path.to_string_lossy().to_string(),
            suspicion_score: 0,
            is_trojan: false,
            matched_heuristics: Vec::new(),
        });
    }

    // 2. High-precision behavioral inspection of JAR contents
    let file_tree_text = all_filenames.join(" ");

    let is_benign_render_only = |text: &str| -> bool {
        let l = text.to_lowercase();
        l.contains("hitboxrendermixin")
            || l.contains("accordionheaderhitbox")
            || l.contains("sidebarhitbox")
            || l.contains("attackhitboxeffectrenderer")
            || l.contains("mixinentityhitboxdebugrenderer")
            || l.contains("ientityhitboxdebugrendererinvoker")
            || l.contains("debugrenderer")
    };

    for &(category, pattern, weight, desc) in CHEAT_SIGNATURE_RULES {
        let pattern_lower = pattern.to_lowercase();
        if !seen_patterns.contains(pattern) && file_tree_text.to_lowercase().contains(&pattern_lower) {
            if category.contains("Hitbox") && is_benign_render_only(&file_tree_text) {
                continue;
            }
            seen_patterns.insert(pattern.to_string());
            total_score = total_score.saturating_add(weight);
            hits.push(HeuristicHit {
                category: category.to_string(),
                weight,
                description: desc.to_string(),
            });
        }
    }

    // Check raw class bytes for synthetic clicks or deep hooks
    for i in 0..archive.len().min(80) {
        if let Ok(mut zip_file) = archive.by_index(i) {
            let fname = zip_file.name().to_string();
            if fname.ends_with(".class") {
                let mut buffer = Vec::new();
                if zip_file.read_to_end(&mut buffer).is_ok() {
                    let class_text = String::from_utf8_lossy(&buffer);
                    for &(category, pattern, weight, desc) in CHEAT_SIGNATURE_RULES {
                        if !seen_patterns.contains(pattern) && class_text.contains(pattern) {
                            if category.contains("Hitbox") && is_benign_render_only(&fname) {
                                continue;
                            }
                            seen_patterns.insert(pattern.to_string());
                            total_score = total_score.saturating_add(weight);
                            hits.push(HeuristicHit {
                                category: category.to_string(),
                                weight,
                                description: desc.to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    let jar_name = jar_path.file_name()?.to_string_lossy().to_string();
    let suspicion_score = total_score.min(100);

    Some(ModScanResult {
        jar_name,
        path: jar_path.to_string_lossy().to_string(),
        suspicion_score,
        is_trojan,
        matched_heuristics: hits,
    })
}
