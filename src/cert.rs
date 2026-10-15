use rcgen::{
    CertificateParams, DistinguishedName, KeyUsagePurpose, ExtendedKeyUsagePurpose,
    IsCa, BasicConstraints, PKCS_ECDSA_P256_SHA256, KeyPair, SanType, Issuer
};
use rcgen::string::Ia5String;
use time::{OffsetDateTime, Duration};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use log::{info, error};
use anyhow::{anyhow, Result};
use std::process::Command;
use tokio::sync::mpsc::Sender;

pub const CA_CERT_PATH: &str = "certs/test.local.crt";
pub const CA_KEY_PATH: &str = "certs/test.local.key";
pub const CERT_DIR: &str = "certs";

#[derive(Clone)]
pub struct CaCert {
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_params: CertificateParams,  // Added to store for Issuer
}

impl CaCert {
    pub fn new(_force: bool, status_tx: Option<Sender<String>>) -> Result<Self> {  // prefixed unused force
        let send = |msg: &str| {
            if let Some(tx) = &status_tx {
                let _ = tx.send(msg.to_string());
            }
            info!("{}", msg);
        };

        if Path::new(CA_CERT_PATH).exists() {
            let cert_pem = fs::read_to_string(CA_CERT_PATH)?;
            let key_pem = fs::read_to_string(CA_KEY_PATH)?;
            if !cert_pem.contains("-----BEGIN CERTIFICATE-----") || !key_pem.contains("-----BEGIN PRIVATE KEY-----") {
                return Err(anyhow!("Invalid PEM format in certificate or key files"));
            }
            send(&format!("Using existing CA certificate at {}", CA_CERT_PATH));

            // For stored params, we need to recreate since it's not saved - for simplicity, recreate params for Issuer
            let mut ca_params = CertificateParams::new(vec![])?;
            ca_params.distinguished_name = DistinguishedName::new();
            ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Test MITM CA");
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.not_before = OffsetDateTime::now_utc();
            ca_params.not_after = ca_params.not_before + Duration::days(3650);
            ca_params.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            ca_params.serial_number = Some(1u64.into());

            return Ok(CaCert { cert_pem, key_pem, ca_params });
        }

        send("Generating new CA certificate...");

        let mut params = CertificateParams::new(vec![])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "Test MITM CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = params.not_before + Duration::days(3650);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.serial_number = Some(1u64.into());

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        fs::create_dir_all(CERT_DIR)?;
        File::create(CA_CERT_PATH)?.write_all(cert_pem.as_bytes())?;
        File::create(CA_KEY_PATH)?.write_all(key_pem.as_bytes())?;

        send(&format!("Generated CA certificate at {}", CA_CERT_PATH));

        import_ca_to_firefox(CA_CERT_PATH, status_tx.clone())?;

        send("CA generation and import completed successfully");

        Ok(CaCert { cert_pem, key_pem, ca_params: params })
    }

    pub fn regenerate_and_import(&self, status_tx: Option<Sender<String>>) -> Result<()> {
        let _new_ca = Self::new(true, status_tx.clone())?;
        import_ca_to_firefox(CA_CERT_PATH, status_tx)?;
        Ok(())
    }

    pub fn import_to_firefox(&self, status_tx: Option<Sender<String>>) -> Result<()> {
        import_ca_to_firefox(CA_CERT_PATH, status_tx)
    }

    pub fn remove_from_firefox(&self, status_tx: Option<Sender<String>>) -> Result<()> {
        remove_from_firefox(status_tx)
    }
}

fn reset_nss_db(profile_path: &str) -> Result<()> {
    let files = vec!["cert9.db", "cert8.db", "key4.db", "key3.db", "pkcs11.txt", "secmod.db"];
    for file in files {
        let path = format!("{}/{}", profile_path, file);
        if Path::new(&path).exists() {
            fs::remove_file(&path)?;
            info!("Deleted {}", path);
        }
    }

    let sql_dir = format!("sql:{}", profile_path);
    let output = Command::new("certutil")
    .args(&["-N", "--empty-password", "-d", &sql_dir])
    .output()?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Failed to create new NSS database: {}", err_msg));
    }
    info!("Created new NSS database for profile {}", profile_path);
    Ok(())
}

fn get_firefox_profiles() -> Result<Vec<String>> {
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME environment variable not set"))?;
    let firefox_dir = format!("{}/.mozilla/firefox", home);
    let profiles_ini_path = format!("{}/profiles.ini", firefox_dir);

    if !Path::new(&profiles_ini_path).exists() {
        return Err(anyhow!("Firefox profiles.ini not found"));
    }

    let contents = fs::read_to_string(&profiles_ini_path)?;
    let mut profile_paths = Vec::new();
    let lines: Vec<&str> = contents.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.trim().starts_with("[Profile") {
            for profile_line in &lines[i..] {
                if profile_line.starts_with("Path=") {
                    let path = profile_line.split('=').nth(1).ok_or(anyhow!("Invalid Path line"))?.trim();
                    let full_path = format!("{}/{}", firefox_dir, path);
                    if Path::new(&full_path).exists() {
                        profile_paths.push(full_path);
                    }
                    break;
                }
            }
        }
    }

    if profile_paths.is_empty() {
        return Err(anyhow!("No Firefox profiles found"));
    }
    Ok(profile_paths)
}

fn import_ca_to_firefox(ca_cert_path: &str, status_tx: Option<Sender<String>>) -> Result<()> {
    let send = |msg: &str| {
        if let Some(tx) = &status_tx {
            let _ = tx.send(msg.to_string());
        }
        info!("{}", msg);
    };

    let profiles = get_firefox_profiles()?;

    let mut success = false;
    for profile_path in profiles {
        send(&format!("Attempting import to Firefox profile: {}", profile_path));

        let sql_dir = format!("sql:{}", profile_path);

        let test_output = Command::new("certutil")
        .args(&["-L", "-d", &sql_dir])
        .output()?;

        if !test_output.status.success() && String::from_utf8_lossy(&test_output.stderr).contains("SEC_ERROR_BAD_DATABASE") {
            send(&format!("Bad database detected in profile {}, resetting...", profile_path));
            reset_nss_db(&profile_path)?;
        }

        let _ = Command::new("certutil")
        .args(&["-D", "-d", &sql_dir, "-n", "Test MITM CA"])
        .status();

        let output = Command::new("certutil")
        .args(&["-A", "-d", &sql_dir, "-n", "Test MITM CA", "-t", "CT,C,C", "-i", ca_cert_path])
        .output()?;

        if output.status.success() {
            send(&format!("Successfully imported CA to profile: {}", profile_path));
            success = true;
        } else {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            error!("Failed to import CA to {}: {}", profile_path, err_msg);
            send(&format!("Import failed for profile {}: {}", profile_path, err_msg));
        }
    }

    if success {
        Ok(())
    } else {
        Err(anyhow!("Failed to import CA to any Firefox profile"))
    }
}

fn remove_from_firefox(status_tx: Option<Sender<String>>) -> Result<()> {
    let send = |msg: &str| {
        if let Some(tx) = &status_tx {
            let _ = tx.send(msg.to_string());
        }
        info!("{}", msg);
    };

    let profiles = get_firefox_profiles()?;

    let mut success = false;
    for profile_path in profiles {
        send(&format!("Attempting to remove CA from profile: {}", profile_path));

        let sql_dir = format!("sql:{}", profile_path);

        let test_output = Command::new("certutil")
        .args(&["-L", "-d", &sql_dir])
        .output()?;

        if !test_output.status.success() && String::from_utf8_lossy(&test_output.stderr).contains("SEC_ERROR_BAD_DATABASE") {
            send(&format!("Bad database detected in profile {}, resetting...", profile_path));
            reset_nss_db(&profile_path)?;
        }

        let output = Command::new("certutil")
        .args(&["-D", "-d", &sql_dir, "-n", "Test MITM CA"])
        .output()?;

        if output.status.success() {
            send(&format!("Successfully removed CA from profile: {}", profile_path));
            success = true;
        } else {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            if err_msg.contains("SEC_ERROR_BAD_NICKNAME") || err_msg.contains("not found") {
                send(&format!("CA not found in profile {}, skipping", profile_path));
                success = true;
            } else {
                error!("Failed to remove CA from {}: {}", profile_path, err_msg);
                send(&format!("Remove failed for profile {}: {}", profile_path, err_msg));
            }
        }
    }

    if success {
        Ok(())
    } else {
        Err(anyhow!("Failed to remove CA from any Firefox profile"))
    }
}

pub fn generate_server_cert(hostname: &str, ca: &CaCert, force: bool) -> Result<(String, String, String)> {
    let cert_path = format!("{}/{}.crt", CERT_DIR, hostname);
    let key_path = format!("{}/{}.key", CERT_DIR, hostname);
    let chain_path = format!("{}/{}_chain.pem", CERT_DIR, hostname);

    if Path::new(&cert_path).exists() && Path::new(&key_path).exists() && !force {
        info!("Using existing server certificate for {}", hostname);
        return Ok((cert_path, key_path, chain_path));
    }

    let ca_key_pair = KeyPair::from_pem(&ca.key_pem)?;
    let mut ca_params = CertificateParams::new(vec![])?;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Test MITM CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    ca_params.not_after = ca_params.not_before + Duration::days(3650);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let _ca_cert = ca_params.self_signed(&ca_key_pair)?;

    let mut params = CertificateParams::new(vec![hostname.to_string()])?;
    params.distinguished_name.push(rcgen::DnType::CommonName, hostname);
    params.subject_alt_names = vec![SanType::DnsName(Ia5String::try_from(hostname).map_err(|_| anyhow!("Invalid hostname"))?)];
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = params.not_before + Duration::days(365);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let issuer = Issuer::new(ca.ca_params.clone(), &ca_key_pair);
    let cert = params.signed_by(&key_pair, &issuer)?;
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let chain_pem = format!("{}\n{}", cert_pem, ca.cert_pem);

    fs::create_dir_all(CERT_DIR)?;
    File::create(&cert_path)?.write_all(cert_pem.as_bytes())?;
    File::create(&key_path)?.write_all(key_pem.as_bytes())?;
    File::create(&chain_path)?.write_all(chain_pem.as_bytes())?;
    info!("Generated server certificate for {}: cert_path={}, key_path={}, chain_path={}", hostname, cert_path, key_path, chain_pem);

    Ok((cert_path, key_path, chain_pem))
}
