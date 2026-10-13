//! LLM Provider 抽象（NL2SQL 方案 X11：前端永不直连 provider，全部经后端代理）
//!
//! 当前实现 **OpenAI 兼容协议**（`POST {base_url}/chat/completions`），
//! 覆盖 OpenAI / DeepSeek / 通义千问（DashScope 兼容模式）/ Ollama（/v1）/ vLLM 等。
//! 新增 provider 只需实现 [`AiProvider`] trait，路由与服务层零改动。

use anyhow::{Context, Result};
use serde::Deserialize;

/// Token 用量观测（§5.57 AI-02 token 计费可见性）：
/// OpenAI 兼容协议响应 `usage` 字段的标准三值；provider 未返回时为 None。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenUsage {
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub total_tokens: i64,
}

/// 单轮补全结果（文本 + 可选用量）
#[derive(Debug, Clone)]
pub struct CompletionResult {
    pub text: String,
    pub usage: Option<TokenUsage>,
}

/// Provider 能力抽象（ NL2SQL v4-X11：仅后端持有密钥与出站调用）
#[async_trait::async_trait]
pub trait AiProvider: Send + Sync {
    /// 单轮补全：给定 system 提示与用户问题，返回模型文本
    async fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        Ok(self
            .complete_detailed(system_prompt, user_prompt)
            .await?
            .text)
    }

    /// 单轮补全（带用量观测）：默认实现委托 [`Self::complete`] 且 usage=None；
    /// 支持 usage 的 provider（如 OpenAI 兼容协议）覆写本方法返回真实用量。
    async fn complete_detailed(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<CompletionResult> {
        Ok(CompletionResult {
            text: self.complete(system_prompt, user_prompt).await?,
            usage: None,
        })
    }
}

/// OpenAI 兼容 provider（覆盖绝大多数 LLM 服务与本地推理栈）
pub struct OpenAiCompatibleProvider {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub timeout_secs: u64,
    pub client: reqwest::Client,
}

#[derive(serde::Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: [ChatMessage<'a>; 2],
    temperature: f32,
}

#[derive(serde::Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
    /// OpenAI 兼容协议的用量字段（部分 provider 不返回——Option 容忍）
    usage: Option<ChatUsage>,
}

#[derive(Deserialize)]
struct ChatUsage {
    prompt_tokens: Option<i64>,
    completion_tokens: Option<i64>,
    total_tokens: Option<i64>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessageOut,
}

#[derive(Deserialize)]
struct ChatMessageOut {
    content: Option<String>,
}

impl OpenAiCompatibleProvider {
    pub fn new(base_url: &str, api_key: &str, model: &str, timeout_secs: u64) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            model: model.to_string(),
            timeout_secs,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .build()
                .unwrap_or_default(),
        }
    }
}

#[async_trait::async_trait]
impl AiProvider for OpenAiCompatibleProvider {
    async fn complete(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        Ok(self
            .complete_detailed(system_prompt, user_prompt)
            .await?
            .text)
    }

    async fn complete_detailed(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<CompletionResult> {
        if self.base_url.is_empty() {
            anyhow::bail!("AI base_url 未配置（config [ai].base_url）");
        }
        if self.api_key.is_empty() {
            anyhow::bail!("AI api_key 未配置（建议通过环境变量 AI_API_KEY 注入）");
        }
        let url = format!("{}/chat/completions", self.base_url);
        let body = ChatRequest {
            model: &self.model,
            messages: [
                ChatMessage {
                    role: "system",
                    content: system_prompt,
                },
                ChatMessage {
                    role: "user",
                    content: user_prompt,
                },
            ],
            temperature: 0.1, // SQL 生成要确定性，压低随机性
        };
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .context("LLM 请求发送失败")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            // 不透传 provider 原始错误体（可能含密钥/内部信息），只给状态码
            anyhow::bail!("LLM 服务返回异常状态: {status}");
        }
        let parsed: ChatResponse = serde_json::from_str(&text).context("LLM 响应解析失败")?;
        let content = parsed
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .context("LLM 响应缺少 choices[0].message.content")?;
        let usage = parsed.usage.map(|u| TokenUsage {
            prompt_tokens: u.prompt_tokens.unwrap_or(0),
            completion_tokens: u.completion_tokens.unwrap_or(0),
            total_tokens: u.total_tokens.unwrap_or(0),
        });
        Ok(CompletionResult {
            text: content,
            usage,
        })
    }
}
