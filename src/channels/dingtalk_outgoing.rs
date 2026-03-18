//! DingTalk Outgoing channel — custom bot HTTP callback + sessionWebhook reply.
//!
//! Flow: open.dingtalk.com/document/dingstart/custom-bot-to-send-group-chat-messages
//! 1. Create custom bot (群设置 → 智能群助手 → 添加机器人 → 自定义)
//! 2. Enable Outgoing in security settings; set sign_token, outgoing_token, POST URL
//! 3. ZeroClaw receives callback, replies via sessionWebhook

use super::traits::{Channel, ChannelMessage, SendMessage};
use async_trait::async_trait;
use ring::digest;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// DingTalk Outgoing channel — receives messages via HTTP callback.
/// Sends replies via sessionWebhook from each incoming message.
pub struct DingTalkOutgoingChannel {
    sign_token: String,
    encoding_aes_key: String,
    allowed_users: Vec<String>,
    /// Per-session webhooks for sending replies (chat_id -> webhook URL)
    session_webhooks: Arc<RwLock<HashMap<String, String>>>,
}

impl DingTalkOutgoingChannel {
    pub fn new(sign_token: String, encoding_aes_key: String, allowed_users: Vec<String>) -> Self {
        Self {
            sign_token,
            encoding_aes_key,
            allowed_users,
            session_webhooks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn http_client(&self) -> reqwest::Client {
        crate::config::build_runtime_proxy_client("channel.dingtalk_outgoing")
    }

    fn is_user_allowed(&self, user_id: &str) -> bool {
        self.allowed_users.iter().any(|u| u == "*" || u == user_id)
    }

    pub fn sign_token(&self) -> &str {
        &self.sign_token
    }

    pub fn encoding_aes_key(&self) -> &str {
        &self.encoding_aes_key
    }

    /// Verify DingTalk callback signature.
    /// signature = sha1(sort([token, timestamp, nonce]).join(""))
    pub fn verify_signature(token: &str, timestamp: &str, nonce: &str, signature: &str) -> bool {
        let mut arr = [token, timestamp, nonce];
        arr.sort_unstable();
        let s = format!("{}{}{}", arr[0], arr[1], arr[2]);
        let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, s.as_bytes());
        let computed = hex::encode(hash.as_ref());
        constant_time_compare(computed.as_bytes(), signature.as_bytes())
    }

    /// Decrypt DingTalk callback encrypt field.
    /// EncodingAESKey is 43 chars base64; decode to 32 bytes.
    /// AES-256-CBC: key=first 16 bytes, iv=last 16 bytes of decoded key.
    /// Plaintext format: random(16) + msg_len(4, big-endian) + msg + corpid
    pub fn decrypt_message(aes_key_b64: &str, encrypt: &str) -> anyhow::Result<String> {
        use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        use aes::Aes256;
        use base64::Engine;

        type Aes256CbcDec = cbc::Decryptor<Aes256>;

        let key_b64 = if aes_key_b64.len() % 4 == 0 {
            aes_key_b64.to_string()
        } else {
            format!("{}=", aes_key_b64)
        };
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&key_b64)
            .map_err(|e| anyhow::anyhow!("Invalid EncodingAESKey base64: {e}"))?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "EncodingAESKey must decode to 32 bytes, got {}",
                key_bytes.len()
            );
        }

        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(encrypt)
            .map_err(|e| anyhow::anyhow!("Invalid encrypt base64: {e}"))?;

        let (key, iv) = key_bytes.split_at(16);
        let cipher = Aes256CbcDec::new_from_slices(key, iv)
            .map_err(|e| anyhow::anyhow!("AES init error: {e}"))?;
        let decrypted = cipher
            .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
            .map_err(|e| anyhow::anyhow!("AES decrypt error: {e}"))?;

        // Strip: random(16) + msg_len(4) + msg
        if decrypted.len() < 20 {
            anyhow::bail!("Decrypted message too short");
        }
        let msg_len = u32::from_be_bytes(decrypted[16..20].try_into().unwrap()) as usize;
        if 20 + msg_len > decrypted.len() {
            anyhow::bail!("Invalid message length in decrypted payload");
        }
        let msg = String::from_utf8(decrypted[20..20 + msg_len].to_vec())
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in decrypted message: {e}"))?;
        Ok(msg)
    }

    /// Encrypt a message for DingTalk callback response.
    pub fn encrypt_message(aes_key_b64: &str, plaintext: &str) -> anyhow::Result<String> {
        use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        use aes::Aes256;
        use base64::Engine;

        type Aes256CbcEnc = cbc::Encryptor<Aes256>;

        let key_b64 = if aes_key_b64.len() % 4 == 0 {
            aes_key_b64.to_string()
        } else {
            format!("{}=", aes_key_b64)
        };
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&key_b64)
            .map_err(|e| anyhow::anyhow!("Invalid EncodingAESKey base64: {e}"))?;
        if key_bytes.len() != 32 {
            anyhow::bail!(
                "EncodingAESKey must decode to 32 bytes, got {}",
                key_bytes.len()
            );
        }

        let mut to_encrypt = Vec::with_capacity(16 + 4 + plaintext.len());
        to_encrypt.extend_from_slice(&[0u8; 16]); // random prefix (zero for response is acceptable)
        to_encrypt.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        to_encrypt.extend_from_slice(plaintext.as_bytes());

        let (key, iv) = key_bytes.split_at(16);
        let cipher = Aes256CbcEnc::new_from_slices(key, iv)
            .map_err(|e| anyhow::anyhow!("AES init error: {e}"))?;
        let encrypted = cipher.encrypt_padded_vec_mut::<Pkcs7>(&to_encrypt);

        Ok(base64::engine::general_purpose::STANDARD.encode(encrypted))
    }

    /// Parse decrypted JSON (encrypted callback format: EventType, msgInfo).
    pub fn parse_callback_json(&self, decrypted: &str) -> Vec<ChannelMessage> {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(decrypted) else {
            return vec![];
        };

        // EventType: "check_url" for URL verification, "chat_message_send" for messages
        let event_type = v.get("EventType").and_then(|t| t.as_str()).unwrap_or("");
        if event_type == "check_url" {
            return vec![];
        }
        if event_type != "chat_message_send" && event_type != "chat_update_title" {
            tracing::debug!("DingTalk outgoing: unsupported EventType {event_type}");
            return vec![];
        }

        if event_type == "chat_update_title" {
            return vec![];
        }

        let msg_info = match v.get("msgInfo") {
            Some(m) => m,
            None => return vec![],
        };

        self.extract_message_from_payload(msg_info)
    }

    /// Parse plain JSON (HTTP mode per dingstart robot-receive-message doc).
    /// Format: text.content or content, sessionWebhook, senderStaffId or senderId, conversationId.
    pub fn parse_plain_callback_json(&self, payload: &serde_json::Value) -> Vec<ChannelMessage> {
        let content = payload
            .get("text")
            .and_then(|t| t.get("content"))
            .and_then(|c| c.as_str())
            .or_else(|| payload.get("content").and_then(|c| c.as_str()))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if content.is_empty() {
            return vec![];
        }

        let sender_id = payload
            .get("senderStaffId")
            .and_then(|s| s.as_str())
            .or_else(|| payload.get("senderId").and_then(|s| s.as_str()))
            .unwrap_or("unknown");

        if !self.is_user_allowed(sender_id) {
            tracing::warn!(
                "DingTalk outgoing: ignoring message from unauthorized user: {sender_id}"
            );
            return vec![];
        }

        let session_webhook = payload
            .get("sessionWebhook")
            .and_then(|w| w.as_str())
            .unwrap_or("")
            .to_string();

        let conversation_id = payload
            .get("conversationId")
            .and_then(|c| c.as_str())
            .unwrap_or(sender_id)
            .to_string();

        self.build_channel_message(sender_id, &conversation_id, &session_webhook, &content)
    }

    fn extract_message_from_payload(&self, msg_info: &serde_json::Value) -> Vec<ChannelMessage> {
        let content = msg_info
            .get("content")
            .and_then(|c| c.as_str())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if content.is_empty() {
            return vec![];
        }

        let sender_id = msg_info
            .get("senderId")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");

        if !self.is_user_allowed(sender_id) {
            tracing::warn!(
                "DingTalk outgoing: ignoring message from unauthorized user: {sender_id}"
            );
            return vec![];
        }

        let session_webhook = msg_info
            .get("sessionWebhook")
            .and_then(|w| w.as_str())
            .unwrap_or("")
            .to_string();

        let conversation_id = msg_info
            .get("conversationId")
            .and_then(|c| c.as_str())
            .unwrap_or(sender_id)
            .to_string();

        self.build_channel_message(sender_id, &conversation_id, &session_webhook, &content)
    }

    fn build_channel_message(
        &self,
        sender_id: &str,
        conversation_id: &str,
        session_webhook: &str,
        content: &str,
    ) -> Vec<ChannelMessage> {
        let reply_target = if session_webhook.is_empty() {
            sender_id.to_string()
        } else {
            conversation_id.to_string()
        };

        if !session_webhook.is_empty() {
            if let Ok(mut webhooks) = self.session_webhooks.write() {
                webhooks.insert(reply_target.clone(), session_webhook.to_string());
                webhooks.insert(sender_id.to_string(), session_webhook.to_string());
            }
        }

        vec![ChannelMessage {
            id: Uuid::new_v4().to_string(),
            sender: sender_id.to_string(),
            reply_target,
            content: content.to_string(),
            channel: "dingtalk_outgoing".to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            thread_ts: None,
        }]
    }
}

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[async_trait]
impl Channel for DingTalkOutgoingChannel {
    fn name(&self) -> &str {
        "dingtalk_outgoing"
    }

    async fn send(&self, message: &SendMessage) -> anyhow::Result<()> {
        let webhook_url = {
            let webhooks = self
                .session_webhooks
                .read()
                .map_err(|e| anyhow::anyhow!("RwLock poisoned: {e}"))?;
            webhooks
                .get(&message.recipient)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No session webhook for {}. User must send a message first to establish session.",
                        message.recipient
                    )
                })?
                .clone()
        };

        let title = message.subject.as_deref().unwrap_or("ZeroClaw");
        let body = serde_json::json!({
            "msgtype": "markdown",
            "markdown": {
                "title": title,
                "text": message.content,
            }
        });

        let resp = self
            .http_client()
            .post(webhook_url)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err = resp.text().await.unwrap_or_default();
            anyhow::bail!("DingTalk outgoing webhook send failed ({status}): {err}");
        }

        Ok(())
    }

    async fn listen(&self, _tx: tokio::sync::mpsc::Sender<ChannelMessage>) -> anyhow::Result<()> {
        tracing::info!(
            "DingTalk outgoing channel active (webhook mode). \
             Configure DingTalk callback URL to POST to your gateway's /dingtalk-outgoing endpoint. \
             Get public IP with: curl cip.cc"
        );
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }

    async fn health_check(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        let ch = DingTalkOutgoingChannel::new(
            "token".into(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            vec![],
        );
        assert_eq!(ch.name(), "dingtalk_outgoing");
    }

    #[test]
    fn test_verify_signature() {
        // DingTalk/WeChat: sort token,timestamp,nonce by ordinal, then sha1
        let token = "abc";
        let timestamp = "123";
        let nonce = "xyz";
        let mut arr = [token, timestamp, nonce];
        arr.sort_unstable();
        let s = format!("{}{}{}", arr[0], arr[1], arr[2]); // "123abcxyz"
        let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, s.as_bytes());
        let expected = hex::encode(hash.as_ref());
        assert!(DingTalkOutgoingChannel::verify_signature(
            token, timestamp, nonce, &expected
        ));
    }
}
