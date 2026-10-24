# frozen_string_literal: true

# Simplified Chinese catalogue for the human-readable text report.
#
# English is the source of truth and lives inline in the call sites as the
# `default:` argument. This file only carries the translations, so deleting
# an entry degrades that one line to English instead of breaking the report.
module PHP2ShellPOC2026
  TRANSLATIONS = {
    "zh" => {
      # -- banner / conclusion ------------------------------------------------
      "text.banner.title" => "php2shell-poc2026 %{version} — PHP2Shell 漏洞检查",
      "text.banner.target" => "目标",
      "text.banner.targets" => "目标",
      "text.banner.request" => "请求",
      "text.banner.requests" => "请求",
      "text.banner.meta" =>
        "扫描深度 %{profile} · %{count} 个%{target_word} · %{requests} 次%{request_word} · " \
        "%{duration} · %{generated_at}",
      "text.banner.authorized" => "仅限授权评估。只发送 GET 请求；不使用载荷，不改变任何状态。",
      "text.banner.browser_ua" => "User-Agent：浏览器兼容模式 — 仅在你的授权允许时使用。",

      # -- plain-language report ---------------------------------------------
      "text.summary.hackable" => "可被入侵？",
      "text.summary.php" => "PHP",
      "text.summary.note" => "说明",
      "text.legend.line1" => "是 = 可被入侵 · 否 = 在已测试页面上未发现 · 未知 = 无法检查",
      "text.legend.line2" => "“未知”绝不等于“否”。",
      "text.section.plain" => "这意味着什么",
      "text.plain.result" => "结果",
      "text.plain.why" => "原因",
      "text.plain.confidence" => "置信度",
      "text.plain.evidence" => "证据",
      "text.plain.php" => "PHP",
      "text.plain.blocked_by" => "拦截方",
      "text.plain.fix" => "修复",
      "text.plain.result_hackable" => "可被入侵",
      "text.plain.result_not_hackable" => "不可被入侵",
      "text.plain.result_unknown" => "未知",
      "text.plain.confidence_none" => "低 — 未看到 PHP 版本。",
      "text.plain.confidence_high" => "高 — 版本来自响应头。",
      "text.plain.confidence_medium" => "中 — 版本来自应用输出。",
      "text.plain.confidence_low" => "低 — 版本为推断结果。",
      "text.plain.confidence_blocked" => "低 — 版本来自被拦截的响应。",
      "text.plain.confidence_branch" => "低 — 只显示了分支，未显示补丁版本。",
      "text.plain.coverage_none" => "未检查任何页面。",
      "text.plain.coverage" => "%{attempted} 个页面中有 %{usable} 个正常响应",
      "text.plain.version_none" => "未看到",
      "text.plain.version_hidden" => "存在，但版本隐藏",
      "text.plain.source_header" => "来自响应头",
      "text.plain.source_phpinfo" => "来自 phpinfo()",
      "text.plain.fix_vulnerable" => "将 PHP 升级到 %{floor} 或更高版本。",
      "text.plain.fix_eol" => "升级到受支持的 PHP 分支（%{floors}），或使用发行版修复包。",
      "text.plain.reason.vulnerable" => "PHP 版本低于该漏洞的修复版本。",
      "text.plain.reason.eol" => "PHP 分支已停止维护，不会再提供修复。",
      "text.plain.reason.patched" => "PHP 版本已达到或高于修复版本。",
      "text.plain.reason.no_php" => "已测试页面未发现 PHP。",
      "text.plain.reason.no_version" => "检测到 PHP，但未暴露版本。",
      "text.plain.reason.branch_only" => "只暴露了 PHP 分支，未暴露补丁版本。",
      "text.plain.reason.newer_than_table" => "PHP 分支比本工具的修复表更新。",
      "text.plain.reason.blocked" => "边缘在到达应用之前拦截了扫描。",
      "text.plain.reason.restricted" => "主页受保护，扫描无法看到应用。",
      "text.plain.reason.auth_wall" => "站点需要登录后才显示应用。",
      "text.plain.reason.rate_limited" => "站点对扫描触发了限速。",
      "text.plain.reason.soft_404" => "站点对所有路径返回同一页面，页面结果不可信。",
      "text.plain.reason.server_error" => "扫描期间站点返回了服务器错误。",
      "text.plain.reason.unreachable" => "站点没有响应。",
      "text.note.blocked_by" => "被 %{vendor} 拦截",
      "text.note.blocked" => "被边缘拦截",
      "text.note.vulnerable" => "低于 %{floor}",
      "text.note.eol" => "停止维护的分支",
      "text.note.patched" => "已修复",
      "text.note.no_php" => "未发现 PHP",
      "text.note.branch_only" => "未显示版本",
      "text.note.newer_than_table" => "较新的 PHP 分支",
      "text.note.no_version" => "未显示版本",
      "text.note.auth_wall" => "需要登录",
      "text.note.rate_limited" => "触发限速",
      "text.note.soft_404" => "全捕获页面",
      "text.note.server_error" => "服务器错误",
      "text.note.unreachable" => "无法连接",
      "text.note.restricted" => "路径受限",
      "text.summary.checked" => "已检查",
      "text.summary.checked_value" =>
        "%{total} 个%{host_word}：%{hackable} 个可被入侵，%{not_hackable} 个不可被入侵，%{unknown} 个无法检查",
      "text.common.host" => "主机",
      "text.common.hosts" => "主机",

      "text.bottom_line.label" => "  结论：        ",
      "text.bottom_line.next_label" => "  下一步：      ",
      "text.bottom_line.none" => "未扫描任何目标。",
      "text.bottom_line.exposed" => "是 — %{count} 个%{target_word}可被 PHP2Shell 入侵；请立即修复或升级。",
      "text.bottom_line.other_unverified" => "另有 %{count} 个%{target_word}无法评估。",
      "text.bottom_line.unverified" => "未知 — 扫描器无法检查 %{count} 个%{target_word}",
      "text.bottom_line.reasons" => "（%{reasons}）",
      "text.bottom_line.unverified_full" => "%{result}。请勿将其视为安全。",
      "text.bottom_line.clean" => "否 — 在已测试页面上，没有目标可被 PHP2Shell 入侵。",

      "text.next.patch_many" => "先修复所有已暴露主机；每台主机的修复方法见下文。",
      "text.next.patch_one" => "修复或升级该主机的 PHP；参见“如何修复”。",
      "text.next.multi" => "按下方各主机的“后续步骤”逐项处理，优先处理未知的主机。",
      "text.next.blocked" => "从已批准的连接重试，或在主机上检查 PHP 版本。",
      "text.next.blocked_browser_ua" =>
        "边缘拦截了扫描器（%{vendor}）；若已授权，请使用 --browser-ua 重试，或在主机上检查 PHP 版本。",
      "text.next.blocked_browser_ua_generic" =>
        "边缘拦截了扫描器；若已授权，请使用 --browser-ua 重试，或在主机上检查 PHP 版本。",
      "text.next.auth_wall" => "若你的授权允许，请使用授权凭据重试。",
      "text.next.rate_limited" => "使用 --delay 2000 --threads 1 降低速率后重试。",
      "text.next.soft_404" => "运行更深的扫描，或测试一个正常提供应用的其他主机。",
      "text.next.unreachable" => "在得出结论前，先检查 DNS、路由和 TLS 证书。",
      "text.next.unverified" => "运行更深的扫描，或在主机上检查 PHP 版本。",
      "text.next.no_php" => "在已测试页面上未发现 PHP。如果该路由本应运行 PHP，请检查同域其他主机或其他端口。",
      "text.next.none" => "无需操作；下次 PHP 更新后再检查。",

      # -- shared labels ------------------------------------------------------
      "text.common.target" => "目标",
      "text.common.targets" => "目标",
      "text.common.unknown" => "未知",
      "text.common.na" => "不适用",
      "text.common.none" => "无",
      "text.common.error" => "错误",
      "text.common.list_separator" => "、",
      "text.common.detail_separator" => "；",
      "text.common.colon" => "：",
      "text.common.edge" => "边缘",

      # -- findings table -----------------------------------------------------
      "text.summary.title" => "结果概览",
      "text.summary.target" => "目标",
      "text.summary.verdict" => "结论",
      "text.summary.access" => "访问",
      "text.summary.version" => "版本",
      "text.summary.risk" => "风险",
      "text.summary.probes" => "探测",
      "text.summary.targets" => "目标",
      "text.summary.targets_value" => "%{total}（暴露 %{exposed}，已修复 %{patched}，无 PHP %{no_php}）",
      "text.summary.unverified" => "未验证",
      "text.summary.errors" => "错误",
      "text.summary.coverage" => "覆盖率",
      "text.summary.coverage_value" =>
        "%{usable}/%{attempted} 次探测可用（%{percent}%）· %{assessable}/%{total} 个目标可评估",
      "text.summary.requests" => "请求",
      "text.summary.requests_value" => "%{requests} 次，用时 %{duration}",
      "text.summary.scope" => "范围",
      "text.summary.scope_value" => "%{count} 个目标因超出范围被跳过",
      "text.summary.reason.blocked" => "被拦截 %{count}",
      "text.summary.reason.auth_wall" => "认证墙 %{count}",
      "text.summary.reason.rate_limited" => "限速 %{count}",
      "text.summary.reason.soft_404" => "软 404 %{count}",
      "text.summary.reason.unreachable" => "不可达 %{count}",
      "text.summary.reason.unknown" => "版本未知 %{count}",
      "text.summary.reasons" => "（%{reasons}）",

      "text.legend.label" => "  图例：",
      "text.legend.verdicts" =>
        "存在漏洞/已停止维护 = 暴露 · 已修复/无 PHP = 安全 · 未验证/无法判定 = 未验证",
      "text.legend.access" => "拦截=边缘拒绝 · 受限=路径受限 · 登录=认证墙 · 限速=触发限速",
      "text.legend.other" => "软404=全捕获路由 · 不可达=连接失败 · 5XX=服务器错误 · ?=未分类",
      "text.legend.coverage" => "探测 = 可用/尝试 · 风险“不适用” = 未验证 · “无法判定”绝不等于“安全”",

      # -- assessment card ----------------------------------------------------
      "text.section.assessment" => "技术细节",
      "text.section.evidence" => "已检查页面",
      "text.section.attack" => "攻击路径（MITRE ATT&CK）",
      "text.section.detections" => "防御检查",
      "text.section.red_team" => "攻击者笔记",
      "text.section.toolchain" => "工具（相关）",
      "text.section.toolchain_full" => "工具（完整列表）",
      "text.section.trace" => "请求跟踪",
      "text.section.technical" => "技术信号",
      "text.section.next_actions" => "后续步骤",
      "text.section.remediation" => "如何修复",
      "text.section.run_summary" => "运行摘要",

      "text.field.reason" => "原因",
      "text.field.surface" => "观察到的 PHP 特征",
      "text.field.sapi_note" => "PHP 运行方式说明",

      "text.assessment.field" => "字段",
      "text.assessment.value" => "值",
      "text.assessment.verdict" => "技术结论",
      "text.assessment.access" => "访问路径",
      "text.assessment.exposure" => "严重度（类 CVSS）",
      "text.assessment.confidence" => "置信度",
      "text.assessment.version" => "版本",
      "text.assessment.evidence" => "可用页面",
      "text.assessment.probes_usable" => "%{count} 个页面可用",
      "text.assessment.hackability" => "证据评级",
      "text.assessment.control" => "控制页面",
      "text.assessment.server" => "服务器",
      "text.assessment.edge" => "边缘",
      "text.assessment.cdn" => "CDN",
      "text.assessment.waf" => "边缘防护（WAF）",
      "text.assessment.block_page" => "拦截页面",
      "text.assessment.sapi" => "PHP 运行方式（SAPI）",
      "text.assessment.framework" => "框架",
      "text.assessment.hosting" => "托管",
      "text.assessment.friction" => "利用难度",
      "text.assessment.control_similarity" => "%{status}（相似度 %{similarity}）",
      "text.assessment.friction_value" => "%{level}（%{factors}）",

      "text.evidence.none" => "（未记录探测）",
      "text.evidence.path" => "路径",
      "text.evidence.method" => "方法",
      "text.evidence.status" => "状态",
      "text.evidence.time" => "耗时",
      "text.evidence.size" => "大小",
      "text.evidence.signal" => "信号",

      "text.attack.assessment" => "评估路径：",
      "text.attack.none" => "无",
      "text.attack.kill_chain" => "杀伤链：",
      "text.attack.no_chain" => "无（未确认存在易受攻击的解释器）",
      "text.attack.assessment_detail" => "评估路径详情：",
      "text.attack.kill_chain_detail" => "杀伤链详情：",

      "text.detections.none" => "（无）",
      "text.toolchain.omitted" => "（已省略攻击与后渗透条目；传入 --authorized 可包含。）",

      "text.technical.hackability" => "证据评级",
      "text.technical.ratio" => "比率",
      "text.technical.confidence" => "置信度",
      "text.technical.coverage" => "覆盖率",
      "text.technical.evidence" => "证据",
      "text.technical.positive" => "正向",
      "text.technical.negative" => "负向",
      "text.technical.neutral" => "中性",
      "text.technical.signals" => "信号：",
      "text.technical.none" => "（无）",
      "text.technical.friction" => "利用难度",
      "text.technical.prerequisites" => "攻击者需要什么：",
      "text.technical.reliability" => "可靠性",
      "text.technical.impact" => "影响",
      "text.technical.hackability_value" => "%{answer} — %{label}（比率 %{ratio}）",

      "text.next_actions.authorized_tag" => "[已授权]",
      "text.next_actions.why" => "原因：",

      "text.tip.label" => "  提示：",
      "text.tip.verbose" => "-v 查看技术细节",
      "text.tip.toolchain" => "-c 查看工具",
      "text.tip.redteam" => "-r 查看攻击者笔记",
      "text.tip.quiet" => "-q 查看精简版",
      "text.tip.exit_codes" => "退出码 0/1/2/3/4",
      "text.tip.sentence_end" => "。",

      "text.version.branch" => "（分支）",
      "text.version.floor" => " · 修复下限 %{floor}",

      "text.risk.na" => "不适用（%{grade}）",
      "text.risk.value" => "%{score}/10（%{grade}）",

      # -- enums --------------------------------------------------------------
      "text.verdict.vulnerable" => "存在漏洞",
      "text.verdict.eol" => "已停止维护",
      "text.verdict.patched" => "已修复",
      "text.verdict.unknown" => "未验证",
      "text.verdict.no_php" => "无 PHP",
      "text.verdict.inconclusive" => "无法判定",

      "text.access.code.open" => "开放",
      "text.access.code.blocked" => "拦截",
      "text.access.code.restricted" => "受限",
      "text.access.code.auth_wall" => "登录",
      "text.access.code.rate_limited" => "限速",
      "text.access.code.soft_404" => "软404",
      "text.access.code.server_error" => "5XX",
      "text.access.code.unreachable" => "不可达",
      "text.access.code.unknown" => "?",

      "text.access.label.open" => "应用正常响应",
      "text.access.label.blocked" => "边缘拦截了所有探测",
      "text.access.label.restricted" => "根路径被拒绝，控制路径可达",
      "text.access.label.auth_wall" => "登录认证墙",
      "text.access.label.rate_limited" => "触发限速",
      "text.access.label.soft_404" => "全捕获/软 404 路由",
      "text.access.label.server_error" => "源站服务器错误",
      "text.access.label.unreachable" => "无法连接",
      "text.access.label.unknown" => "未分类",
      "text.access.detail_http" => "%{label}（HTTP %{status}）",

      "text.confidence.high" => "高",
      "text.confidence.medium" => "中",
      "text.confidence.low" => "低",

      "text.grade.critical" => "严重",
      "text.grade.high" => "高",
      "text.grade.medium" => "中",
      "text.grade.low" => "低",
      "text.grade.none" => "无",
      "text.grade.unknown" => "未知",

      "text.hackability.exposed" => "已暴露",
      "text.hackability.likely" => "很可能暴露",
      "text.hackability.inconclusive" => "无法判定",
      "text.hackability.not_exposed" => "未暴露",

      # -- decision card -------------------------------------------------------
      "text.decision.key" => "决策",
      "text.decision.action_key" => "行动",
      "text.decision.format" => "%{rating} — %{answer}",
      "text.decision.yes" => "是",
      "text.decision.no" => "否",
      "text.decision.unknown" => "未知",
      "text.decision.yes_line" => "是 — 该主机可被 PHP2Shell 入侵。",
      "text.decision.likely_line" => "很可能 — 在确认 PHP 版本前，按可被入侵处理。",
      "text.decision.no_line" => "否 — 在已测试页面上未发现 PHP2Shell 暴露。",
      "text.decision.unknown_line" => "未知 — 扫描器无法判断。",
      "text.decision.exposed" => "远程攻击者无需登录即可利用该主机。",
      "text.decision.likely" => "证据指向暴露，但版本尚未确认。",
      "text.decision.not_exposed" => "找到的 PHP 版本已修复，或在已测试页面上未发现 PHP。",
      "text.decision.inconclusive" => "扫描器看不到足够的信息，无法安全作答。",
      "text.decision.caveat" => "注意：版本来自被拦截的响应；据此行动前，请从已批准的连接复核。",
      "text.decision.blocked_by" => "拦截方：%{vendor} — %{summary}",

      "text.sapi.mod_php_likely" => "mod_php（很可能）",
      "text.sapi.mod_php_possible" => "mod_php（可能）",
      "text.sapi.php_fpm_likely" => "php-fpm（很可能）",
      "text.sapi.php_fpm_possible" => "php-fpm（可能）",
      "text.sapi.php_cgi_possible" => "php-cgi（可能）",
      "text.sapi.litespeed" => "LiteSpeed",

      "text.edge.unidentified_edge_control" => "未识别的边缘防护",
      "text.edge.ovhcloud" => "OVHcloud",
      "text.edge.rate_limiter" => "限速器",

      "text.tactic.reconnaissance" => "侦察",
      "text.tactic.initial_access" => "初始访问",
      "text.tactic.execution" => "执行",
      "text.tactic.persistence" => "持久化",
      "text.tactic.collection" => "收集",
      "text.tactic.discovery" => "发现",
      "text.tactic.command_and_control" => "命令与控制",
      "text.tactic.privilege_escalation" => "权限提升",
      "text.tactic.defense_evasion" => "防御规避",
      "text.tactic.credential_access" => "凭据访问",
      "text.tactic.lateral_movement" => "横向移动",
      "text.tactic.exfiltration" => "数据外泄",
      "text.tactic.impact" => "影响",
      "text.tactic.resource_development" => "资源开发",

      "text.phase.reconnaissance" => "侦察",
      "text.phase.scanning_enumeration" => "扫描与枚举",
      "text.phase.framework_fingerprinting" => "框架识别",
      "text.phase.vulnerability_assessment" => "漏洞评估",
      "text.phase.verification" => "验证",
      "text.phase.exploitation_authorized" => "利用（已授权）",
      "text.phase.post_exploitation_authorized" => "后渗透（已授权）",
      "text.phase.opsec_reporting" => "行动安全与报告",

      "text.friction_factor.waf" => "WAF",
      "text.friction_factor.cdn" => "CDN",
      "text.friction_factor.sapi" => "FPM",
      "text.friction_factor.auth" => "认证",
      "text.friction_factor.rate_limit" => "限速",
      "text.friction_factor.edge_block" => "边缘拦截",
      "text.friction_factor.soft_404" => "软 404",

      "text.friction_level.high" => "高",
      "text.friction_level.medium" => "中",
      "text.friction_level.low" => "低",
      "text.friction_level.none" => "无",

      "text.surface.value" =>
        "PHP %{php} · phpinfo %{phpinfo} · 活跃 .php %{live} · 上传进度 %{upload} · 错误 %{errors}",
      "text.bool.yes" => "是",
      "text.bool.no" => "否",
      "text.bool.not_observed" => "未观察到",
      "text.framework.entry" => "%{name}（%{confidence}）",

      "text.probe.control" => "控制路径",
      "text.probe.discovery" => "发现",
      "text.probe.denied" => "拒绝",
      "text.probe.rate_limited" => "限速",
      "text.probe.not_found" => "未找到",
      "text.probe.server_error" => "服务器错误",
      "text.probe.redirect" => "重定向",
      "text.probe.ok" => "正常",
      "text.probe.phpinfo" => "phpinfo",
      "text.probe.fpm_not_found" => "fpm-404",
      "text.probe.error.dns" => "DNS 失败",
      "text.probe.error.connect" => "连接失败",
      "text.probe.error.tls" => "TLS 失败",
      "text.probe.error.timeout" => "超时",
      "text.probe.error.protocol" => "协议错误",
      "text.probe.error.redirect" => "重定向",
      "text.probe.error.too_large" => "响应过大",
      "text.probe.error.uri" => "URL 错误",
      "text.probe.error.budget" => "预算耗尽",
      "text.probe.error.internal" => "内部错误",
      "text.probe.marker.version-header" => "版本头",
      "text.probe.marker.phpinfo" => "phpinfo",
      "text.probe.marker.session-cookie" => "会话 Cookie",
      "text.probe.marker.error-page" => "错误页",
      "text.probe.marker.fpm-not-found" => "fpm-404",

      # -- verdict reasons ----------------------------------------------------
      "data.verdict.caveat.error_response" => " — 该版本来自错误响应；%{reason}",
      "data.verdict.caveat.restricted" => " — 根路径受限；%{reason}",
      "data.verdict.unverified" => "%{reason} — 暴露情况尚未验证，不能视为不存在",
      "data.verdict.restricted" => "%{reason} — 无法评估该解释器",
      "data.verdict.auth_wall" =>
        "%{reason} — 请在主机侧读取版本；只有在获得授权时才评估认证后的暴露面",
      "data.verdict.soft_404" => "%{reason} — 未暴露版本头，因此暴露情况未验证",
      "data.verdict.no_version" =>
        "检测到 PHP，但未暴露版本 — 暴露情况未确认；请尝试 --profile deep，或在主机侧读取版本",
      "data.verdict.no_php" =>
        "在可达路径上未观察到 PHP 标记，且控制路径行为正常 — 该路由未发现 PHP 暴露面" \
        "（这不代表其他虚拟主机也没有 PHP）",
      "data.verdict.branch_only" =>
        "仅暴露了分支级版本（%{version}）；补丁级别未知 — 请在主机侧与 %{floor} 比对%{suffix}",
      "data.verdict.eol_branch" =>
        "PHP 分支 %{branch} 已停止维护 — 上游没有修复版本；只能依靠发行版向后移植或升级来解决%{suffix}",
      "data.verdict.patched" => "PHP %{version} 已达到 %{branch} 分支的修复下限（%{floor}）%{suffix}",
      "data.verdict.vulnerable" =>
        "PHP %{version} 低于 %{branch} 分支的修复下限（%{floor}）— 请立即更新%{suffix}",
      "data.verdict.eol" =>
        "PHP %{version}（分支 %{branch}）已停止维护 — 上游没有修复版本；" \
        "只能依靠发行版向后移植或升级来解决%{suffix}",
      "data.verdict.newer_than_table" =>
        "PHP %{version} 比本工具的修复表（%{max}.x）更新 — 请对照当前 PHP 发布说明核实%{suffix}",
      "data.verdict.outside_table" =>
        "PHP %{version}（分支 %{branch}）不在受支持的修复表内 — 在厂商公告另有说明前，按已停止维护处理%{suffix}",

      # -- access reasons -----------------------------------------------------
      "data.access.no_probes" => "没有完成任何探测",
      "data.access.rate_limited" =>
        "源站返回 HTTP 429（限速）— 扫描速率过高，或边缘正在限流",
      "data.access.root_failed" =>
        "根路径探测失败（%{kind}：%{error}），但其他路径有响应 — 应用可部分访问，但无法评估根路径",
      "data.access.restricted_404" =>
        "根路径返回 HTTP %{status}，但随机控制路径返回 404 — 属于路径级访问控制，而非边缘全面拦截",
      "data.access.restricted_other" =>
        "根路径返回 HTTP %{status}，控制路径行为不同 — 应用可访问，但该路径受保护",
      "data.access.auth_wall" =>
        "站点重定向到或渲染了认证页面 — PHP 可能存在，但暴露面在登录之后",
      "data.access.soft_404" =>
        "随机不存在的路径返回 HTTP %{status}，且内容与根路径相似 — 服务器使用全捕获/软 404 路由，" \
        "因此路径状态码不可信",
      "data.access.server_error" =>
        "根路径探测时源站返回 HTTP 5xx — 应用处于异常状态，不代表未打补丁",
      "data.access.unreachable_error" => "没有可用响应 — %{kind}：%{error}",
      "data.access.unreachable" => "目标没有返回可用响应",
      "data.access.open" => "应用正常响应",
      "data.access.blocked.statuses" =>
        "所有探测（包括随机控制路径）都返回 HTTP %{statuses}",
      "data.access.blocked.server" => "来自 %{server}",
      "data.access.blocked.edge" => "边缘在应用响应之前拒绝了扫描器",
      "data.access.blocked.separator" => " — ",

      # -- remediation --------------------------------------------------------
      "data.remediation.vulnerable.upgrade" =>
        "将 PHP %{version} 升级到至少 %{floor} — 这是 %{branch} 分支首个包含修复的版本。" \
        "如果发行版软件包落后于上游，请应用厂商向后移植，并记录对应的安全公告。",
      "data.remediation.vulnerable.waf" =>
        "临时措施：部署本报告列出的 WAF 规则 — 在 POST 正文中拦截 PHP_SESSION_UPLOAD_PROGRESS，" \
        "并限制解码后的正文大小、分段数量和嵌套深度。无需修改应用代码即可覆盖该漏洞的两个利用方向。",
      "data.remediation.vulnerable.harden" =>
        "加固主机：session.upload_progress.enabled=Off，使用客户端无法覆盖的固定 php_admin_value " \
        "memory_limit，并降低 post_max_size。修改后重启所有 FPM/Apache 工作进程。",
      "data.remediation.vulnerable.verify" =>
        "通过真实的 Web 请求（phpinfo）验证生效配置，而不是 CLI — FPM 与 CLI 经常读取不同的 php.ini，" \
        "CLI 的答案是不对的。",
      "data.remediation.eol.migrate" =>
        "PHP %{version}（分支 %{branch}）没有修复版本 — 请规划迁移到受支持的分支（8.4 或 8.5）。" \
        "以下均为补偿措施，不是修复。",
      "data.remediation.eol.backport" =>
        "如果暂时无法开始迁移：在存在的情况下应用 7.4/8.0/8.1 的发行版/厂商向后移植，" \
        "并记录其跟踪的安全公告，让例外有明确的到期日。",
      "data.remediation.eol.edge" =>
        "同时在前端补偿 — 部署本报告列出的 WAF 规则，并锁定源站，使泄露的直连 IP 无法绕过这些规则。",
      "data.remediation.eol.sweep" =>
        "停止维护的解释器常集中在被遗忘的主机上：关闭该发现前，请扫描子域名、虚拟主机和预发布环境中的同一分支。",
      "data.remediation.patched.none" =>
        "该漏洞类别无需操作：%{version} 已达到分支修复下限（%{floor}）。",
      "data.remediation.patched.updates" =>
        "保持该分支的安全更新 — 降级或使用过期基础镜像都会让结论翻回存在漏洞，而这两件事比计划中更常发生。",
      "data.remediation.patched.rerun" =>
        "升级或迁移后重新运行本工具：退出码 2 表示存在暴露，--fail-on inconclusive 也会让被拦截或未验证的结果使 CI 失败。",
      "data.remediation.no_php.routes" =>
        "已测试路由无需 PHP 操作：控制路径行为正常，且未观察到 PHP 标记。该结论仅限这些路由。",
      "data.remediation.no_php.routing" =>
        "如果该主机本应运行 PHP，请检查虚拟主机路由、重写规则和其他端口 — 静态响应可能通过不同的 " \
        "Host 头隐藏 PHP 后端。",
      "data.remediation.no_php.siblings" =>
        "对同级子域名和预发布主机重复检查；PHP 的存在情况很少在整个资产面上完全一致。",
      "data.remediation.no_php.config" =>
        "本报告中的配置审计步骤，对任何你发现的 PHP 主机仍然值得验证。",
      "data.remediation.unknown.branch_only" =>
        "仅暴露了分支级版本（%{version}）。请在主机侧读取精确补丁级别（php -v、包管理器或受保护的 " \
        "phpinfo 页面），并与 %{floor} 比对。",
      "data.remediation.unknown.newer_than_table" =>
        "观察到的版本（%{version}）比本工具的修复表更新。在将其视为安全之前，请检查当前 PHP 发布说明和厂商公告。",
      "data.remediation.unknown.version" =>
        "确认解释器版本：在主机侧读取（包管理器）、临时在访问控制后暴露 phpinfo，或使用 --profile deep 重试。",
      "data.remediation.unknown.header" =>
        "如果 X-Powered-By 是被刻意移除的，头部卫生不等于补丁卫生 — 请从主机侧核实分支。",
      "data.remediation.unknown.unversioned" =>
        "不要把未返回版本的响应当作已修复。解析器级漏洞可能仍然存在。",
      "data.remediation.unknown.config" =>
        "本报告中的配置审计检查适用于任何 PHP 主机：无论版本最终如何，都应验证。",
      "data.remediation.inconclusive.blocked.block_page" =>
        "边缘返回了 %{vendor} 拦截页面（%{summary}）。这是机器人/边缘防护，不是补丁结论。若已授权，可使用 " \
        "--browser-ua 或从批准的出口重试，或请主机所有者提供主机侧版本。",
      "data.remediation.inconclusive.blocked.not_evidence" =>
        "边缘拒绝了包括随机控制路径在内的所有探测。这不能证明 PHP 不存在或已修复 — " \
        "请重新核对范围/授权书，并确认拦截是有意为之。",
      "data.remediation.inconclusive.blocked.retry" =>
        "如果获得授权，请从批准的出口或项目代理重试，或请主机所有者提供主机侧版本读取。" \
        "不要试图绕过该控制措施。",
      "data.remediation.inconclusive.blocked.origin" =>
        "检查源站是否能在边缘之外直接访问；CDN 返回 403 并不能说明源站的补丁级别。",
      "data.remediation.inconclusive.blocked.logs" =>
        "在边缘日志中检查本次扫描的探针路径请求；将其视为侦察行为。",
      "data.remediation.inconclusive.restricted.verify" =>
        "根路径受保护，而控制路径可以解析。请在主机侧或同一虚拟主机的其他路由上验证解释器。",
      "data.remediation.inconclusive.restricted.auth" =>
        "如果获得认证测试授权，请单独评估认证后的暴露面；不要假设登录保护了解析器 — " \
        "它在应用认证之前运行。",
      "data.remediation.inconclusive.auth_wall.version" =>
        "站点位于登录之后。请在主机侧或受保护的诊断页面读取 PHP 版本；认证测试需要单独授权。",
      "data.remediation.inconclusive.auth_wall.parser" =>
        "请记住，该漏洞类别在请求解析阶段、认证代码运行之前触发：登录墙本身并不能关闭它。",
      "data.remediation.inconclusive.rate_limited.backoff" =>
        "源站返回 HTTP 429。请提高 --delay、降低 --threads，并稍后重试；429 不是不存在的证据。",
      "data.remediation.inconclusive.rate_limited.coordinate" =>
        "如果项目公布了速率限制，请远低于该限制，并与目标 SOC 协调大批量工作。",
      "data.remediation.inconclusive.soft_404.status_codes" =>
        "服务器对不存在的路径返回 200。不要在该主机上相信路径状态码或目录爆破结果；" \
        "请使用响应头、Cookie 和正文差异。",
      "data.remediation.inconclusive.soft_404.version" =>
        "请在主机侧或从响应明显不同的路径确认解释器版本。",
      "data.remediation.inconclusive.unreachable.retry" =>
        "未收到可用响应。请检查 DNS、TCP 可达性、TLS 和超时设置；从批准的观察点重试。",
      "data.remediation.inconclusive.unreachable.insecure" =>
        "仅对获得授权的自签名源站使用 --insecure，并且必须先确认主机身份。",
      "data.remediation.inconclusive.server_error.logs" =>
        "源站在每次探测时都返回 5xx。请稍后重试并检查主机错误日志；应用不健康不等于已打补丁。",
      "data.remediation.inconclusive.server_error.owner" =>
        "如果 5xx 持续存在，请先与主机所有者协调，再得出任何暴露结论。",
      "data.remediation.inconclusive.other" =>
        "扫描未能获得可用的应用证据。请使用 -v、其他配置档或主机侧版本读取重试。",
      "data.remediation.edge.cdn" =>
        "将源站锁定到 CDN 网段（%{cdn}），使上述规则无法通过泄露的直连 IP 绕过 — " \
        "证书透明日志和旧 DNS 记录最终会暴露它。",
      "data.remediation.edge.waf" =>
        "确认 WAF（%{waf}）确实运行了覆盖此 CVE 版本的 PHP 托管规则集 — 有 WAF 不等于有规则覆盖。",

      # -- detections ---------------------------------------------------------
      "data.detection.layer.waf" => "WAF",
      "data.detection.layer.waf_proxy" => "WAF/代理",
      "data.detection.layer.php_logs" => "PHP 日志",
      "data.detection.layer.web_tier" => "Web 层",
      "data.detection.layer.edr" => "EDR",
      "data.detection.layer.application" => "应用",
      "data.detection.layer.network" => "网络",
      "data.detection.layer.edge" => "边缘",
      "data.detection.layer.recon_detection" => "侦察检测",
      "data.detection.layer.verification" => "验证",
      "data.detection.layer.config_audit" => "配置审计",
      "data.detection.exposure.upload.control" => "拦截上传进度利用方向（CVE-2026-109619）",
      "data.detection.exposure.upload.detail" =>
        "AWS WAF：自定义规则匹配正文包含 PHP_SESSION_UPLOAD_PROGRESS 和 PHPSESSID（正文或 Cookie）的 POST 请求；" \
        "AWS WAF PHP 托管规则组 v2.3+ 已覆盖。ModSecurity：检查预期上传表单之外的多段正文中的 " \
        "PHP_SESSION_UPLOAD_PROGRESS。",
      "data.detection.exposure.oom.control" => "缩小 OOM 触发面（CVE-2026-109618）",
      "data.detection.exposure.oom.detail" =>
        "对*解码后*的请求强制执行正文大小限制（AWS WAF SizeRestrictions_BODY，若不需要上传则为 8 KB）、" \
        "多段数量、字段数量、请求头数量和嵌套深度 — 包括没有可用 Content-Length 的请求。",
      "data.detection.exposure.logs.control" => "追查请求启动阶段的内存耗尽",
      "data.detection.exposure.logs.detail" =>
        "在 FPM/Apache 错误日志中搜索“Allowed memory size of ... exhausted”“Cannot allocate memory”" \
        "以及在脚本名出现*之前*的致命错误 — 这种顺序是 CVE-2026-109618 的特征。",
      "data.detection.exposure.workers.control" => "工作进程健康异常",
      "data.detection.exposure.workers.detail" =>
        "mod_php：Apache 子进程段错误/重启、核心转储。FPM：工作进程异常退出和快速重生风暴。" \
        "利用也可能在没有任何崩溃的情况下成功 — 没有段错误不等于干净。",
      "data.detection.exposure.edr.control" => "Web 工作进程用户启动 shell",
      "data.detection.exposure.edr.detail" =>
        "对入站 HTTP 请求后立即由 www-data/apache 启动的 /bin/sh、bash、curl、wget 或 python 告警；" \
        "无论哪个 CVE 得手，这都是后渗透的支点。",
      "data.detection.exposure.disclosure.control" => "内存泄露响应异常",
      "data.detection.exposure.disclosure.detail" =>
        "返回异常大或非 HTML 正文的端点，或会话 Cookie 反映了意外的内存内容 — 这是该漏洞类别的信息泄露方向。",
      "data.detection.origin.control" => "源站可达性审计",
      "data.detection.origin.detail" =>
        "CDN（%{cdn}）位于应用前端，但直连源站的请求会绕过其规则。请确认源站端口只接受来自 CDN 网段的流量。",
      "data.detection.edge.blocked.control" => "统一拒绝 — 确认意图，不要当作已修复",
      "data.detection.edge.blocked.detail" =>
        "所有探测（包括随机控制路径）都返回相同的拒绝（%{statuses}）。请确认这是地理/IP 封禁、" \
        "机器人管理还是 WAF 规则。将探针路径请求记录为侦察行为，并确保源站在边缘之外无法直接访问。",
      "data.detection.edge.restricted.control" => "路径级访问控制",
      "data.detection.edge.restricted.detail" =>
        "根路径被拒绝，而随机控制路径的解析结果不同。请检查该限制是否有意为之，以及其他虚拟主机或路径是否暴露同一解释器。",
      "data.detection.edge.auth.control" => "认证墙",
      "data.detection.edge.auth.detail" =>
        "暴露面重定向到登录页。响应头中的版本证据仍可能泄露；除非获得认证测试授权，主机侧验证才是可靠路径。",
      "data.detection.edge.canary.control" => "随机探针路径请求",
      "data.detection.edge.canary.detail" =>
        "本次扫描会请求一个随机不存在的路径，以区分全面拒绝和真实 404。请对单一来源的随机路径突发请求告警；" \
        "这是可靠的扫描器特征。",
      "data.detection.soft_404.control" => "全捕获/软 404 路由",
      "data.detection.soft_404.detail" =>
        "源站对不存在的路径返回 200，因此路径状态码和目录爆破结果不可靠。优先使用响应头、Cookie 和 phpinfo 证据；" \
        "用正文/内容差异验证发现。",
      "data.detection.rate_limit.control" => "观察到限速（HTTP 429）",
      "data.detection.rate_limit.detail" =>
        "源站正在限流。请遵守 Retry-After、提高扫描器延迟，不要把 429 解释为应用不存在。",
      "data.detection.no_php.control" => "已测试路由上没有 PHP",
      "data.detection.no_php.detail" =>
        "未观察到 PHP 标记，且控制路径行为正常。这只覆盖已测试的路径：在断定整个资产面没有 PHP 之前，" \
        "请检查其他虚拟主机、端口、子域名和应用路由。",
      "data.detection.config.control" => "验证实际生效的 PHP 加固配置（主机侧）",
      "data.detection.config.detail" =>
        "session.upload_progress.enabled=Off、memory_limit=-1（使用 php_admin_value，不可覆盖）、" \
        "8.5 上 fatal_error_backtraces=0、较低的 post_max_size。通过真实 Web 请求（phpinfo）验证，" \
        "而不是 CLI — 修改后重启所有工作进程。",

      # -- red-team notes -----------------------------------------------------
      "data.red_team.exposed.parser" =>
        "请求解析器在应用代码之前运行，因此每个 .php 路由都是入口 — 不需要凭据、会话或用户交互。",
      "data.red_team.exposed.wordpress" =>
        "已确认 WordPress：wp-login.php、xmlrpc.php 和 /wp-json/ 都是确定的 .php 路由，" \
        "解析器漏洞不在乎选哪一个。",
      "data.red_team.exposed.framework" =>
        "已确认 %{framework}；其标准 .php 端点都是额外的入口。",
      "data.red_team.exposed.sapi" =>
        "按 PHP 项目的说法，mod_php 是风险最高的形态：一个请求一个进程，受害者之间没有工作进程回收。" \
        "FPM 会降低概率（两个请求必须命中同一工作进程），但不会消除风险。",
      "data.red_team.exposed.eol" =>
        "EOL PHP（%{version}，分支 %{branch}）：上游没有修复版本。防御方只能依靠向后移植、配置缓解或网络隔离 — " \
        "预计这类目标会被攻击者优先处理。",
      "data.red_team.exposed.waf" =>
        "WAF 指纹：%{waf}。这改变的是利用可靠性，而不是暴露程度 — 其后的解释器仍然未打补丁。" \
        "找到源站通常是更省力的路径。",
      "data.red_team.exposed.cdn" =>
        "前端有 CDN（%{cdn}）：WAF 规则只保护前门。如果源站 IP 泄露（旧 DNS 记录、邮件头、" \
        "Censys/Shodan 上的证书），直连源站的流量会跳过所有控制。",
      "data.red_team.exposed.opsec" =>
        "行动安全：内存泄露方向会在不使工作进程崩溃的情况下泄露数据，因此仅靠可用性监控不会发现探测阶段。" \
        "利用尝试可能看起来像普通的大型表单提交。",
      "data.red_team.unverified.blocked" =>
        "403 是对边缘的观察，而不是对解释器的结论。攻击者会尝试其他出口、其他主机名或源站，然后才下结论。",
      "data.red_team.unverified.auth_wall" =>
        "登录墙不能关闭该漏洞类别：解析器在认证之前运行。但在获得凭据（或授权的认证测试）之前，" \
        "可达暴露面确实更窄。",
      "data.red_team.unverified.soft_404" =>
        "全捕获路由让路径模糊测试在这里失去意义；攻击者会转向响应头/Cookie 证据和主机侧指纹识别。",
      "data.red_team.unverified.no_response" =>
        "未获得可用的应用响应。请将该主机视为未评估，并从另一个观察点验证后再下结论。",
      "data.red_team.unverified.canary" =>
        "本扫描器请求的随机探针路径是可检测的特征；关注它的防御方可以区分侦察和正常流量。",
      "data.red_team.unverified.origin" =>
        "如果存在 CDN，下一步是源站发现：证书透明日志、历史 DNS 和全网扫描数据通常会暴露真实主机。",
      "data.red_team.unverified.waf" =>
        "如果存在 WAF（%{waf}），不要假设它覆盖了此 CVE — 存在不等于规则覆盖。",
      "data.red_team.patched.no_chain" =>
        "该漏洞类别没有杀伤链：解释器已达到修复下限。请转向应用层漏洞、框架/插件版本和配置错误。",
      "data.red_team.patched.siblings" =>
        "旗舰主机已修复，不代表同级子域名、预发布环境或被遗忘的虚拟主机也安全；同一分支通常在那里存活。",
      "data.red_team.no_php.routes" =>
        "在已测试路由上未观察到 PHP。在断定整个资产面没有 PHP 之前，请检查其他虚拟主机、端口和应用。",
      "data.red_team.no_php.static" =>
        "静态前端可能通过不同的 Host 头或路径隐藏 PHP 管理后台或 API。",

      # -- next actions -------------------------------------------------------
      "data.actions.verify.label" => "从自己的出口验证响应",
      "data.actions.verify.why" => "在不使用扫描器专属 User-Agent 的情况下确认状态行和响应头。",
      "data.actions.browser_ua.label" => "使用浏览器兼容 User-Agent 重试（已授权）",
      "data.actions.browser_ua.why" =>
        "边缘正在拒绝扫描器的标识 User-Agent。浏览器兼容 UA 可能绕过拦截页面并到达应用；仅在你的授权允许时使用。",
      "data.actions.blocked_retry.label" => "从批准的代理或出口重试（已授权）",
      "data.actions.blocked_retry.why" =>
        "不同的观察点可能看到应用而不是边缘拦截。未经授权不得用它绕过控制措施。",
      "data.actions.host_version.label" => "在主机侧读取 PHP 版本",
      "data.actions.host_version.why" => "边缘拒绝外部探测时，这是权威答案。",
      "data.actions.slow_down.label" => "降低速率后重试",
      "data.actions.slow_down.why" => "429 是限流，不是不存在；更慢的扫描可能完成。",
      "data.actions.distinct_path.label" => "从不同路径或主机侧读取版本",
      "data.actions.distinct_path.why" =>
        "全捕获路由让路径状态码不可靠；更深的探测可能命中不同的响应。",
      "data.actions.widen.label" => "扩大探测范围",
      "data.actions.widen.why" => "更多路径和请求轨迹可能把无法判定的结果变成证据。",
      "data.actions.deep_why" =>
        "深度模式会增加 phpinfo 候选、框架路径以及从 robots/sitemap 派生的 .php 路径。",
      "data.actions.corroborate.label" => "佐证技术栈",
      "data.actions.corroborate.why" => "第二次被动指纹识别可能揭示响应头隐藏的版本。",
      "data.actions.other_ports.label" => "检查其他端口和虚拟主机（已授权）",
      "data.actions.other_ports.why" => "PHP 可能位于与已测试端口或 Host 头不同的位置。",
      "data.actions.siblings.label" => "识别同级主机",
      "data.actions.siblings.why" => "确认“无 PHP”结果仅针对该路由还是整个主机。",
      "data.actions.rescan_after_fix.label" => "升级后重新扫描",
      "data.actions.rescan_after_fix.why" => "确认已暴露主机现在报告的是修复后的 PHP 版本。",
      "data.actions.rescan_after_update.label" => "下次 PHP 更新后重新扫描",
      "data.actions.rescan_after_update.why" => "确认更新周期后主机仍处于修复版本。",
      "data.actions.sarif.label" => "生成可供 CI 使用的 SARIF 报告",
      "data.actions.sarif.why" => "把发现变成安全待办可导入的机器可读产物。",
      "data.actions.inventory.label" => "盘点同级主机（已授权）",
      "data.actions.inventory.why" => "在关闭该发现前，找出同一分支上的其他主机。",
      "data.actions.ci.label" => "在 CI 中保持补丁状态",
      "data.actions.ci.why" =>
        "存在暴露时退出 2，被拦截/未验证时退出 3，使静默的边缘拦截无法伪装成安全。",
      "data.actions.tls.label" => "检查 TLS 证书",
      "data.actions.tls.why" => "证书 SAN 和签发者是被动的源站发现信号。",
      "data.actions.dns.label" => "解析 DNS",
      "data.actions.dns.why" => "确认主机名指向何处，以及是否能看出 CDN/源站分离。",
      "data.actions.scope.label" => "下次运行时强制执行范围",
      "data.actions.scope.why" => "目标不在授权列表内时失败关闭（退出码 4）。",

      # -- tooling ------------------------------------------------------------
      "data.tooling.subfinder.purpose" => "被动子域名枚举，带来源去重和解析检查。",
      "data.tooling.subfinder.relevance" =>
        "旁站、预发布环境和被遗忘的虚拟主机往往落后于旗舰主机的补丁级别。PHP2Shell 修复的新旧程度，" \
        "取决于你维护得最差的那个子域名。",
      "data.tooling.ct.purpose" => "在公开证书日志中搜索主机名和源站证书。",
      "data.tooling.ct.relevance" =>
        "证书透明日志经常暴露 CDN 后的真实源站，以及共享同一解释器的同级主机。",
      "data.tooling.shodan.purpose" =>
        "全网横幅搜索：服务器响应头、证书，以及没人记得存在过的暴露面板。",
      "data.tooling.shodan.relevance" =>
        "用于佐证服务器/边缘指纹，并在有 CDN 时寻找源站。",
      "data.tooling.gau.purpose" => "拉取公开爬虫为该域名记录过的所有 URL。",
      "data.tooling.gau.relevance" =>
        "退役的 .php 端点常常多年仍路由到在线后端；每个都是解析器漏洞的独立入口。",
      "data.tooling.httpx.purpose" =>
        "探测主机列表，只返回带状态、标题和技术指纹的在线端点。",
      "data.tooling.httpx.relevance" =>
        "在消耗扫描预算前区分存活主机和死 DNS — 这是两小时侦察和两天侦察的差别。",
      "data.tooling.whatweb.purpose" => "从响应识别技术栈：CMS、框架、服务器栈和版本线索。",
      "data.tooling.whatweb.relevance" =>
        "佐证本工具读取的被动响应头。结果不一致通常意味着 CDN 掩盖了源站技术栈。",
      "data.tooling.curl.purpose" => "最小化、可脚本化的 HTTP 客户端，完全控制方法、头和正文。",
      "data.tooling.curl.relevance" =>
        "三行 GET 是对本扫描器所见内容最诚实的复现；用它从自己的出口验证状态。",
      "data.tooling.openssl.purpose" => "直接读取 TLS 证书链和 DNS 记录。",
      "data.tooling.openssl.relevance" =>
        "证书 SAN、签发者和 DNS 历史都是被动的源站发现信号；两者都安全且只在服务端进行。",
      "data.tooling.nmap.purpose" => "跨开放端口的服务和版本检测，配合 HTTP 枚举脚本。",
      "data.tooling.nmap.relevance" =>
        "PHP 不只在 443 上。暴露的 FPM 套接字（9000）、奇怪端口上的管理面板和绑定 0.0.0.0 的开发服务器，" \
        "只能靠端口扫描发现，Web 爬虫永远找不到。",
      "data.tooling.ffuf.purpose" => "目录和文件发现，并递归进入匹配的文件夹。",
      "data.tooling.ffuf.relevance" =>
        "梳理 .php 入口 — 登录、定时任务、xmlrpc、上传处理器、被遗忘的测试脚本。只能在授权范围内、" \
        "以目标可承受的速率运行。",
      "data.tooling.wafw00f.purpose" => "探测边缘对良性请求的反应，识别 WAF 厂商或确认其不存在。",
      "data.tooling.wafw00f.relevance" =>
        "判断本报告中的检测建议是否已在边缘覆盖，以及源站暴露是否需要单独检查。",
      "data.tooling.wpscan.purpose" => "WordPress 核心、主题和插件枚举，并映射已知漏洞。",
      "data.tooling.wpscan.relevance" =>
        "WordPress 本身就是 PHP，插件/主题漂移是未打补丁解释器藏得最久的地方。",
      "data.tooling.droopescan.purpose" => "Drupal/Joomla/SilverStripe 版本和插件枚举。",
      "data.tooling.droopescan.relevance" =>
        "仅在检测到这些框架时相关；它把泛化发现变成具体的组件清单。",
      "data.tooling.nuclei.purpose" => "模板驱动的技术和暴露检查；为 X-Powered-By 下限写一个模板。",
      "data.tooling.nuclei.relevance" =>
        "一个模板就能标记所有低于修复下限的主机，并把检查带入持续监控。",
      "data.tooling.searchsploit.purpose" => "公开漏洞代码搜索，本地镜像。",
      "data.tooling.searchsploit.relevance" =>
        "判断某个漏洞类别是否已经商品化 — 这反映攻击者的技能门槛，而不只是你的补丁队列。",
      "data.tooling.burp.purpose" => "拦截代理，用于重放、变异和字节级请求比较。",
      "data.tooling.burp.relevance" =>
        "解析器漏洞藏在畸形正文和异常请求头顺序里 — 正是盲目扫描器丢弃的流量。",
      "data.tooling.host_read.purpose" => "在主机上读取 php -v、包管理器或受保护的 phpinfo 页面。",
      "data.tooling.host_read.relevance" =>
        "边缘拦截或响应头被移除时，这是唯一权威答案。CLI 和 FPM 可能读取不同的 php.ini，" \
        "所以要验证 Web SAPI。",
      "data.tooling.egress.purpose" =>
        "从普通浏览器或批准的代理复现请求，以区分扫描器拦截和应用响应。",
      "data.tooling.egress.relevance" =>
        "非浏览器客户端收到 403 往往是机器人管理，而不是补丁。下结论前先确认。",
      "data.tooling.metasploit.purpose" =>
        "对已确认存在漏洞的解释器投递经过测试的载荷，带 handler 和会话管理。",
      "data.tooling.metasploit.relevance" =>
        "mod_php 接近一击必中；FPM 强制两个请求命中同一工作进程，因此要预期重试。",
      "data.tooling.repeater.purpose" => "一次一个变异地迭代构造的多段正文。",
      "data.tooling.repeater.relevance" => "针对解析器的漏洞开发需要对原始请求进行行级控制。",
      "data.tooling.pwntools.purpose" => "可脚本化的协议交互，带时序控制。",
      "data.tooling.pwntools.relevance" =>
        "OOM 方向是与工作进程内存赛跑；脚本化测试框架比反复点 Replay 更有效。",
      "data.tooling.linpeas.purpose" => "权限提升枚举和就地取材路径。",
      "data.tooling.linpeas.relevance" => "该漏洞拿到的是 www-data；shell 落地后下一步就是提权枚举。",
      "data.tooling.chisel.purpose" => "面向分段 Web 层的隧道和横向移动工具。",
      "data.tooling.chisel.relevance" => "Web 层很少有可用出口；稳定通道是后渗透的前提。",
      "data.tooling.mitmproxy.purpose" => "检查自己的扫描器流量和请求头顺序。",
      "data.tooling.mitmproxy.relevance" =>
        "一半的“WAF 拦了我们”其实是我们自己的工具发送了特征明显的 User-Agent 或异常请求头顺序。" \
        "先检查自己，再怪边缘。",
      "data.tooling.faraday.purpose" => "发现管理、证据和报告组装。",
      "data.tooling.faraday.relevance" => "蓝队能导入的结构化输出，是“发现”和“修复”之间的差别。",
      "data.tooling.origin.purpose" => "重建 %{cdn} 后的真实源站。",
      "data.tooling.origin.relevance" =>
        "优先处理，因为该主机位于前端之后：如果源站能直接响应，所有边缘规则和速率限制都只是摆设。",
      "data.tooling.php2shell.purpose" => "大规模检查解释器版本和上传进度暴露面。",
      "data.tooling.php2shell.relevance" =>
        "主机确认暴露后，下一步有用的是找出所有同版本的兄弟主机 — 而不是反复确认这一台。",

      # -- ATT&CK notes -------------------------------------------------------
      "data.attack.t1190.note" =>
        "一个精心构造的 HTTP 请求会在任何应用代码之前到达 PHP 解析器；应用层认证、IAM 或 SSO 都无法阻止。",
      "data.attack.t1059.note" => "已确认的利用路径会以 Web 工作进程（www-data/apache/nginx）身份执行攻击者命令。",
      "data.attack.t1505.note" =>
        "落在长生命周期工作进程（mod_php/FPM）内，使持久化 webshell 的植入变得轻而易举；" \
        "成功执行无需崩溃或重启工作进程，因此能保持安静。",
      "data.attack.t1005.note" =>
        "泄露方向会泄漏进程内存（Heartbleed 式）：环境变量、云密钥、会话材料 — 无需实现代码执行即可访问。",
      "data.attack.t1082.note" => "通过被劫持的解释器进行侦察，在没有 EDR 的情况下看起来就像普通应用流量。",
      "data.attack.t1071.note" => "C2 和数据外泄会混入 Web 层正常的 HTTPS 出站流量。",
      "data.attack.t1595.note" =>
        "%{requests} 个普通 GET 请求%{profile_note}；不使用载荷、不改变状态、不进行利用。本次扫描会出现在 Web 日志中。",
      "data.attack.t1595.profile" => "（配置档 %{profile}）",
      "data.attack.t1592.unverified" =>
        "被动读取了响应头、TLS 证书、服务器/边缘指纹、Cookie 和框架标记。边缘拒绝或遮蔽了应用，" \
        "因此在将目标视为已修复之前，请从主机侧或批准的出口验证解释器。",
      "data.attack.t1592.note" =>
        "被动读取了响应头、TLS 证书、服务器/边缘指纹、Cookie 和框架标记，以识别部署形态。",
      "data.attack.t1596.cdn" =>
        "证书透明日志、历史 DNS 和全网扫描数据可以揭示 %{cdn} 后的源站；直连源站的流量会绕过边缘规则。",
      "data.attack.t1590.note" => "绘制源站的网络位置，并确认它只接受来自 CDN 网段的流量。",
      "data.attack.t1596.unverified" =>
        "使用证书透明日志、DNS 历史和 Shodan/Censys 佐证该主机，并寻找暴露同一解释器的旁站资产。",
      "data.attack.t1046.note" =>
        "该路由未观察到 PHP；获得授权的端口/服务扫描可能发现运行 PHP 的其他 Web 层或开发服务器。",

      # -- hackability --------------------------------------------------------
      "data.hackability.signal.vulnerable" =>
        "解释器 %{version} 低于 %{branch} 分支的修复下限（%{floor}）",
      "data.hackability.signal.eol" => "分支 %{branch} 已停止维护 — 不存在上游修复",
      "data.hackability.signal.patched" => "解释器 %{version} 已达到修复下限（%{floor}）",
      "data.hackability.signal.no_php" => "可达路径上没有 PHP 标记；控制路径行为正常",
      "data.hackability.signal.unknown" => "存在 PHP，但未暴露版本",
      "data.hackability.signal.inconclusive" => "没有可用的应用证据 — %{reason}",
      "data.hackability.signal.php" => "观察到 PHP 行为",
      "data.hackability.signal.upload" => "下发了 PHPSESSID — 上传进度路径可达",
      "data.hackability.signal.phpinfo" => "phpinfo() 可公开读取",
      "data.hackability.signal.errors" => "响应中包含详细 PHP 错误文本",
      "data.hackability.signal.live_php" => "对照 404 控制路径确认了活跃 .php 路由",
      "data.hackability.signal.framework" => "检测到 PHP 框架：%{framework}",
      "data.hackability.signal.pre_auth" => "在认证之前触发 — 解析器先于应用代码运行",
      "data.hackability.signal.waf" => "前端有 WAF（%{waf}）",
      "data.hackability.signal.cdn" => "CDN（%{cdn}）掩盖了源站",
      "data.hackability.signal.fpm" => "php-fpm 形态 — 需要同工作进程请求配对",
      "data.hackability.signal.blocked" => "边缘拒绝了所有探测（HTTP %{statuses}）",
      "data.hackability.signal.soft_404" => "全捕获 200 响应 — 路径证据不可靠",
      "data.hackability.signal.branch_only" => "仅报告分支级版本 — 补丁级别未知",
      "data.hackability.prereq.reachability" => "到 Web 端口的 TCP 可达性 — 不需要凭据、会话或用户交互",
      "data.hackability.prereq.upload" =>
        "接受带 PHP_SESSION_UPLOAD_PROGRESS + PHPSESSID 的多段 POST（CVE-2026-109619 方向）",
      "data.hackability.prereq.oom" =>
        "上传进度接受情况未确认 — CVE-2026-109618（OOM）方向不需要特殊请求字段",
      "data.hackability.prereq.fpm" => "两个构造请求必须落在同一个 FPM 工作进程",
      "data.hackability.prereq.route" => "任意活跃 .php 路由 — 不需要特定路径、权限或会话",
      "data.hackability.prereq.patched" => "无 — 该漏洞类别已在解释器修复层面关闭",
      "data.hackability.prereq.no_php" =>
        "探测路径之外的 PHP 端点 — 本发现只覆盖实际测试过的路由",
      "data.hackability.prereq.unverified" => "需要可用的应用响应或主机侧版本读取，才能评估暴露",
      "data.hackability.reliability.patched" => "已关闭 — 解释器达到修复下限；无需评估",
      "data.hackability.reliability.no_php" => "不适用 — 探测路径上未观察到 PHP 暴露面",
      "data.hackability.reliability.unverified" =>
        "无法确定 — 没有可用的应用响应；请从批准的观察点测量",
      "data.hackability.reliability.mod_php" =>
        "高 — mod_php 每个请求一个进程，受害者之间没有回收；首次尝试成功是现实的",
      "data.hackability.reliability.fpm" =>
        "中 — FPM 强制请求配对到单一工作进程；预计会有重试和部分失败",
      "data.hackability.reliability.unknown" =>
        "无法确定 — 无法从外部识别 SAPI；在信任任一模型前先测量工作进程行为",
      "data.hackability.impact.exposed" =>
        "以 Web 工作进程 UID 执行代码（T1059.004）并植入 webshell 持久化（T1505.003）；" \
        "或在无崩溃的情况下静默泄露环境变量、密钥和会话材料（T1005）",
      "data.hackability.impact.patched" =>
        "解析器级利用已在修复层面关闭 — 残余风险是应用漏洞和配置错误",
      "data.hackability.impact.no_php" => "不适用于探测路由 — 该漏洞类别需要 PHP 解释器",
      "data.hackability.impact.unknown" => "无法确定 — 在确认解释器版本前无法评估影响",
      "data.hackability.action.yes" => "立即升级 PHP；在修复完成前隔离该主机。",
      "data.hackability.action.no" => "已测试页面无需操作；下次 PHP 更新后再检查。",
      "data.hackability.action.no_php" =>
        "已测试页面未发现 PHP；在认定整个资产面安全之前，请检查同级主机或其他端口。",
      "data.hackability.action.unknown" => "先运行更深的扫描，或在主机上检查 PHP 版本，再作决定。",

      # -- risk ---------------------------------------------------------------
      "data.risk.scale" => "暴露严重度（CVSS 形态，不是 CVSS 向量）",
      "data.risk.friction.waf" => "%{waf} 可能拦截构造请求",
      "data.risk.friction.cdn" => "%{cdn} 掩盖源站；直连源站可能绕过边缘规则",
      "data.risk.friction.sapi" => "FPM 需要两个利用请求落在同一工作进程",
      "data.risk.friction.auth" => "认证墙限制了可达路径",
      "data.risk.friction.rate_limit" => "限速会减慢或阻断请求序列",
      "data.risk.friction.edge_block" => "边缘拒绝了所有探测；没有应用层证据",
      "data.risk.friction.soft_404" => "全捕获路由使基于路径的证据不可靠",

      # -- environment --------------------------------------------------------
      "data.environment.sapi.litespeed" => "LiteSpeed SAPI — 按 PHP 公告属于受影响范围",
      "data.environment.sapi.mod_php_likely" =>
        "Apache 服务器头且前端无 CDN — 按 PHP 团队说法是风险最高的配置",
      "data.environment.sapi.mod_php_possible" =>
        "Apache 位于 %{cdn} 之后；无法从外部确认源站 SAPI",
      "data.environment.sapi.fpm_openresty" =>
        "openresty 基于 nginx，通常代理到 PHP-FPM；工作进程亲和性未确认",
      "data.environment.sapi.fpm_likely" =>
        "nginx/fastcgi 指纹 — FPM 受影响，但需要同工作进程请求配对",
      "data.environment.sapi.cgi_iis" =>
        "IIS 前端且存在 PHP 标记 — CGI/FastCGI SAPI，工作进程模型未确认",
      "data.environment.sapi.fpm_front_end" =>
        "%{edge} 前端且存在 PHP 标记 — 通常代理到 FPM",
      "data.environment.sapi.unobservable" => "边缘先于源站响应；无法从该响应判断 SAPI",
      "data.environment.sapi.unknown" => "未暴露 SAPI 指纹"
    }
  }.freeze
end
