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
            // 超时**两处都挂**（客户端级 + 每请求级），因为原先这里是
            // `.build().unwrap_or_default()`：构建失败（TLS/代理环境异常）时
            // `Default::default()` 给的是一个**没有任何超时**的客户端 ⇒ 上游挂住
            // 就整条 AI 链路无限等待（本仓 fail-closed 取向禁止"取不到就换默认"）。
            // 退回默认客户端这件事本身可以接受（请求照样能发），但超时必须是
            // 结构上存在的——所以补了 `complete_detailed` 里的 `.timeout(...)`。
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
                .build()
                .unwrap_or_else(|e| {
                    tracing::error!(
                        error = %e,
                        timeout_secs,
                        "AI provider HTTP 客户端构建失败，已退回默认客户端并按请求级超时兜底"
                    );
                    reqwest::Client::new()
                }),
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
        // b72（AGENTS #4）：LLM 出站遥测。本函数有 5 条失败出口（未配置 base_url/api_key、
        // 发送失败、非 2xx、解析失败、缺 choices 字段），故用 RAII 守卫保证"任何路径都记一次"。
        let mut tel = crate::observability::metrics::OutboundGuard::start("ai");
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
            // 请求级超时（与客户端级同值，取 max(1) 防"配 0 = 永不超时"的挂死形态）
            .timeout(std::time::Duration::from_secs(self.timeout_secs.max(1)))
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
        tel.succeeded();
        Ok(CompletionResult {
            text: content,
            usage,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::common::prod_scan::{ProdFile, Scan, prod_file};

    const FILE: &str = "src/ai/provider.rs";

    /// 把行集拼成"无空白"文本：`.build()` 与 `.unwrap_or_default()` 分行写也算同一句链式调用
    /// （真实缺陷形状就是分行的，逐行匹配看不见它）。
    fn unbounded_build_sites(lines: &[String]) -> usize {
        let joined: String = lines
            .iter()
            .flat_map(|l| l.chars().filter(|c| !c.is_whitespace()))
            .collect();
        let needle: String = concat!(".build()", ".unwrap_or_default()").to_string();
        joined.matches(&needle).count()
    }

    /// b89 项 E1：客户端构建失败不得退回"无超时默认客户端"，且必须有两处超时
    /// （客户端级 + 请求级）。这条锁的是**兜底路径的形状**，不是 happy path。
    #[test]
    fn provider_must_never_build_an_unbounded_http_client() {
        let ProdFile { lines, .. } = prod_file(FILE, &Scan::default());
        let bad = unbounded_build_sites(&lines);
        assert_eq!(
            bad, 0,
            "{FILE} 里出现 `.build().unwrap_or_default()`（{bad} 处）：构建失败时得到的是\
             **没有任何超时**的客户端，上游挂住就无限等待"
        );
        let text = lines.join("\n");
        let timeouts = text.matches(".timeout(").count();
        assert!(
            timeouts >= 2,
            "{FILE} 只数到 {timeouts} 处 `.timeout(`——客户端级与请求级必须各一处\
             （请求级是构建失败时的唯一兜底）"
        );
    }

    /// 判据自身双向：缺陷形状必须被抓、合规形状必须不抓（否则上一条测试等于没判）
    #[test]
    fn unbounded_build_detector_is_falsifiable() {
        let defect = vec![
            "client: reqwest::Client::builder()".to_string(),
            "    .timeout(d)".to_string(),
            "    .build()".to_string(),
            "    .unwrap_or_default(),".to_string(),
        ];
        assert_eq!(
            unbounded_build_sites(&defect),
            1,
            "分行写的链式调用必须被抓到（逐行匹配的写法在这里会漏）"
        );
        let ok = vec![
            "client: reqwest::Client::builder()".to_string(),
            "    .timeout(d)".to_string(),
            "    .build()".to_string(),
            "    .unwrap_or_else(|e| { tracing::error!(%e); reqwest::Client::new() }),".to_string(),
        ];
        assert_eq!(unbounded_build_sites(&ok), 0, "合规的响亮兜底不得误报");
    }
}
