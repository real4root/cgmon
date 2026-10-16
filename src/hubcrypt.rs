//! Отчёт на центр сбора — тот же формат, что в Go (hubcrypt.go):
//! 0x01 | nonce(12) | AES-256-GCM(ключ = SHA-256("cgmon-hub-v1"+token),
//! JSON {"ts": unix, "report": ...}, AAD = "cgmon-report-v1").

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

pub const PROTO_V1: u8 = 0x01;
pub const AAD: &[u8] = b"cgmon-report-v1";

pub fn key(token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"cgmon-hub-v1");
    h.update(token.as_bytes());
    h.finalize().into()
}

fn random(buf: &mut [u8]) -> bool {
    let n = unsafe { libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    n == buf.len() as isize
}

/// Зашифровать plain (уже собранный {"ts":..,"report":..}).
pub fn seal(token: &str, plain: &[u8]) -> Option<Vec<u8>> {
    let c = Aes256Gcm::new_from_slice(&key(token)).ok()?;
    let mut nonce = [0u8; 12];
    if !random(&mut nonce) {
        return None;
    }
    let ct = c.encrypt(Nonce::from_slice(&nonce), Payload { msg: plain, aad: AAD }).ok()?;
    let mut out = Vec::with_capacity(1 + 12 + ct.len());
    out.push(PROTO_V1);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Some(out)
}

/// Расшифровать (для центра сбора и тестов); проверка ts/повторов — снаружи.
pub fn open(token: &str, b: &[u8]) -> Option<Vec<u8>> {
    if b.len() < 1 + 12 + 16 || b[0] != PROTO_V1 {
        return None;
    }
    let c = Aes256Gcm::new_from_slice(&key(token)).ok()?;
    c.decrypt(Nonce::from_slice(&b[1..13]), Payload { msg: &b[13..], aad: AAD }).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let s = seal("0123456789abcdef-token", b"{\"ts\":1}").unwrap();
        assert_eq!(open("0123456789abcdef-token", &s).unwrap(), b"{\"ts\":1}");
        assert!(open("another-token-000000", &s).is_none());
    }

    /// Отчёт, зашифрованный Go 1.3.x (sealReport, Router "vec", ts 1700000000):
    /// центр на Go и агенты на Rust должны понимать друг друга.
    #[test]
    fn opens_go_report() {
        let hex = "012aadb65d3dbb362a82f36b7379a83a2bb87fb82bbf5e064468915bd9251237c5fea5586dfd85d7f3835b7506d5c0dc728d6d42281471c89dcde789561fbd047aa8aa0601e89d41d2e0ff8a349f811167deecf1a7bda0a1a3eaac9e18703b5caca17b077a9c4c1cf81d0250258bd6a490c0ef2c42a5cc24326286e51d8ea33338cc82e78a5c336838afdef20bf2de5af96b0f7985d8067dd83fee6750595970348c0fd5d3de19245dc5ad3c629e35a6501ce8c418fb7f5186b8a4d78a19269d578e5c0fd5ba47bab52d5f04ae8e9bf46f4968f8ab73e3a587fb703924e695a4c2cf4db9c554921754a7884c95d888844c11c4aa84e321";
        let b: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        let plain = String::from_utf8(open("vector-token-0123456789", &b).expect("Go vector must open")).unwrap();
        assert!(plain.starts_with("{\"ts\":1700000000,\"report\":{"), "{plain}");
        assert!(plain.contains("\"router\":\"vec\""), "{plain}");
    }
}
