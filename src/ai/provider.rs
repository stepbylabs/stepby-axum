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
    /// 出站客户端；`None` 表示**系统信任库与内嵌根证书两路都建不起来**
    /// （[`crate::common::outbound_client`] 的终态）。此时每次请求给出可归因的错误，
    /// 而不是揣着一个必然失败的客户端。
    pub client: Option<reqwest::Client>,
    /// `client == None` 的原因原文——"取不到"必须说得出为什么取不到。
    build_failure: Option<String>,
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
        // b144：裸 `Client::builder().build()` 的兜底是 `reqwest::Client::new()`——
        // 而 `new()` 内部就是 `builder().build().expect(...)`：**兜底路径自己会 panic**，
        // panic 的场景恰好是它要兜的那一个（宿主缺 `ca-certificates`，批八十一实测形状）。
        // 现在走 `outbound_client::build_with`：系统信任库失败 ⇒ 内嵌根证书；两路都失败 ⇒
        // `client = None`，请求期给可归因错误。超时仍**两处都挂**（客户端级 + 每请求级），
        // 因为原先 `.unwrap_or_default()` 给的是没有任何超时的客户端 ⇒ 上游挂住就整链无限等待
        // （本仓 fail-closed 取向禁止"取不到就换默认"）。
        let built = crate::common::outbound_client::build_with("ai", |b| {
            b.timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
        });
        let (client, build_failure) = match built {
            Ok(c) => (Some(c), None),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    timeout_secs,
                    "AI provider HTTP 客户端构建失败（系统信任库与内嵌根证书两路都不通），AI 请求将逐次报错"
                );
                (None, Some(e))
            }
        };
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            model: model.to_string(),
            timeout_secs,
            client,
            build_failure,
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
        // 客户端取不到时**这次请求不得发出**，并把原因说清楚（缺的是哪一路信任库），
        // 而不是让运维在 provider 侧的报错里猜"是不是密钥/地址写错了"。
        let client = self.client.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "LLM 出站客户端不可用：{}",
                self.build_failure.as_deref().unwrap_or("未知原因")
            )
        })?;
        let resp = client
            .post(&url)
            // 请求级超时（与客户端级同值，取 max(1) 防"配 0 = 永不超时"的挂死形态）
            .timeout(std::time::Duration::from_secs(self.timeout_secs.max(1)))
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .context("LLM 请求发送失败")?;
        let status = resp.status();
        if !status.is_success() {
            // b145：先分岔再读体。旧写法在错误路径上已经把整个响应体拉进内存再丢弃
            // （provider 的 4xx 页面可以是大 HTML）。
            // 对外仍只给状态码——provider 错误体可能回显密钥/内部信息，这是 C.9 的既有取舍；
            // 但遮蔽后的摘要必须进服务端日志：运维不该只剩"HTTP 403"这一件事可看。
            let snippet =
                crate::common::outbound_error_body::read_error_body(resp, "ai:chat").await;
            tracing::warn!("LLM 服务返回异常状态 {status}，响应体摘要：{snippet}");
            anyhow::bail!("LLM 服务返回异常状态: {status}");
        }
        // 读失败必须上抛：旧写法折成空串后交给下一句的是"响应解析失败"，
        // 把"上游断开"报成了"上游给了坏 JSON"（同一族的第二个断面）
        let text = resp
            .text()
            .await
            .context("LLM 响应体读取失败（上游可能已断开连接）")?;
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
