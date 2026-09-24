export interface Env {
  HONEYPOT_KV: KVNamespace;
  WHITELIST_IPS?: string;
  STATUS_404_WINDOW_SECONDS?: string;
  STATUS_404_THRESHOLD?: string;
  HIGH_RISK_THRESHOLD?: string;
  HONEYPOT_PATHS?: string;
  ALLOWED_AI_BOT_PATTERN?: string;
  BAD_BOT_PATTERN?: string;
  CRITICAL_EXPLOIT_PATTERN?: string;
  HIGH_RISK_PATTERN?: string;
}

// 内存 Strike 结构：隔离特征命中与状态码计数
interface MemStrikeRecord {
  patternHits: number;           // High Risk 探测命中计数
  status404Hits: number;         // 60 秒滑动窗口内 404/403 命中计数
  status404WindowStart: number;  // 404 滑动窗口起始时间戳 (毫秒)
}

// 实例本地临时计数器（开销为 0）
const memStrikes = new Map<string, MemStrikeRecord>();

// 递进阶梯封禁时长配置（秒）：1h -> 24h -> 7d -> 365d
const ESCALATION_TIERS: Record<number, number | undefined> = {
  1: 3600,       // Level 1: 1 小时
  2: 86400,      // Level 2: 24 小时
  3: 604800,     // Level 3: 7 天
  4: 31536000,   // Level 4: 365 天
};

// ==========================================
// 辅助工具函数
// ==========================================

// 1. 安全 URL 解码，防止 %ZZ 等畸形编码导致 Worker 500
function safeDecodeUrl(rawUrl: string): string {
  try {
    return decodeURIComponent(rawUrl);
  } catch {
    return rawUrl;
  }
}

// 2. 正则安全编译辅助
function safeRegExp(patternStr?: string, flags: string = 'i'): RegExp | null {
  if (!patternStr || patternStr.trim() === '') return null;
  try {
    return new RegExp(patternStr, flags);
  } catch (err) {
    console.error(`[RegExp Compile Error] Pattern: ${patternStr}`, err);
    return null;
  }
}

// 3. 安全获取客户端 IP
function getClientIp(request: Request): string {
  return request.headers.get('cf-connecting-ip') || '127.0.0.1';
}

// 4. 单 IP 原子阶梯封禁逻辑
async function executeBan(
  ip: string,
  reason: string,
  env: Env,
  ctx: ExecutionContext
) {
  memStrikes.delete(ip);

  ctx.waitUntil(
    (async () => {
      const banKey = `ban:${ip}`;
      let currentLevel = 1;

      try {
        const rawHistory = await env.HONEYPOT_KV.get(banKey);
        if (rawHistory) {
          const parsed = JSON.parse(rawHistory);
          currentLevel = Math.min((parsed.level || 1) + 1, 4);
        }
      } catch {
        currentLevel = 1;
      }

      const ttl = ESCALATION_TIERS[currentLevel];
      const banPayload = JSON.stringify({
        level: currentLevel,
        reason,
        bannedAt: new Date().toISOString(),
        ttlSeconds: ttl || 'PERMANENT',
      });

      console.warn(`[WAF BAN] IP: ${ip}, Level: ${currentLevel}, Reason: ${reason}`);

      if (ttl) {
        await env.HONEYPOT_KV.put(banKey, banPayload, { expirationTtl: ttl });
      } else {
        await env.HONEYPOT_KV.put(banKey, banPayload);
      }
    })()
  );
}

// ==========================================
// 主业务流程
// ==========================================

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const ip = getClientIp(request);
    const url = new URL(request.url);
    const safePath = safeDecodeUrl(url.pathname);
    const userAgent = request.headers.get('user-agent') || '';
    const now = Date.now();

    // ----------------------------------------------------
    // 第 0 层：白名单与已有封禁快速阻断 (零回源)
    // ----------------------------------------------------

    // 1. IP 静态白名单放行
    if (env.WHITELIST_IPS) {
      const whiteList = env.WHITELIST_IPS.split(',').map((item) => item.trim());
      if (whiteList.includes(ip)) {
        return fetch(request);
      }
    }

    // 2. Cloudflare 认证的合法搜索引擎爬虫放行 (Googlebot, Bingbot 等)
    // @ts-ignore Cloudflare 特有属性
    const cfData = request.cf;
    if (cfData && cfData.verifiedBot) {
      return fetch(request);
    }

    // 3. 查验该 IP 是否已被封禁
    const banRecord = await env.HONEYPOT_KV.get(`ban:${ip}`);
    if (banRecord) {
      return new Response('Access Denied (IP Blocked by Security Gateway)', {
        status: 403,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      });
    }

    // ----------------------------------------------------
    // 第一层：确定性指纹防御 (零容忍，不回源)
    // ----------------------------------------------------

    // 1. 蜜罐路径拦截 (Honeypot Trigger)
    const honeypotRegex = safeRegExp(env.HONEYPOT_PATHS);
    if (honeypotRegex && honeypotRegex.test(safePath)) {
      await executeBan(ip, `Trap Triggered (Honeypot: ${safePath})`, env, ctx);
      return new Response('Not Found', { status: 404 });
    }

    // 2. 爬虫分类治理 (放行主流 AI 爬虫，拦截垃圾采集与扫描脚本)
    const aiBotRegex = safeRegExp(env.ALLOWED_AI_BOT_PATTERN);
    const isAiBot = aiBotRegex ? aiBotRegex.test(userAgent) : false;

    if (!isAiBot) {
      const badBotRegex = safeRegExp(env.BAD_BOT_PATTERN);
      if (badBotRegex && badBotRegex.test(userAgent)) {
        await executeBan(ip, `Bad Bot Detected (${userAgent})`, env, ctx);
        return new Response('Forbidden: Bot Not Allowed', { status: 403 });
      }
    }

    // 3. Critical Exploit 绝对致命指纹检测 (一击必杀)
    const criticalRegex = safeRegExp(env.CRITICAL_EXPLOIT_PATTERN);
    if (criticalRegex && criticalRegex.test(safePath)) {
      await executeBan(ip, `Critical Exploit Probe (${safePath})`, env, ctx);
      return new Response('Not Found', { status: 404 });
    }

    // 4. High Risk 可疑探测检测 (累积阈值后 Ban)
    let currentStrike = memStrikes.get(ip) || {
      patternHits: 0,
      status404Hits: 0,
      status404WindowStart: now,
    };

    const highRiskRegex = safeRegExp(env.HIGH_RISK_PATTERN);
    if (highRiskRegex && highRiskRegex.test(safePath)) {
      currentStrike.patternHits += 1;
      memStrikes.set(ip, currentStrike);

      const highRiskLimit = parseInt(env.HIGH_RISK_THRESHOLD || '3', 10);
      if (currentStrike.patternHits >= highRiskLimit) {
        await executeBan(
          ip,
          `High Risk Probe Exceeded (${currentStrike.patternHits} hits)`,
          env,
          ctx
        );
        return new Response('Forbidden', { status: 403 });
      }
      return new Response('Not Found', { status: 404 });
    }

    // ----------------------------------------------------
    // 发起回源请求 (核心：开启 404 边缘短缓存，拦截暴扫穿透)
    // ----------------------------------------------------

    const originResponse = await fetch(request, {
      cf: {
        cacheTtlByStatus: {
          '404': 30, // 404 结果在 CF 边缘节点缓存 30 秒，防止把 WordPress/PHP 扫崩
          '403': 60,
          '500-599': 0,
        },
      },
    });

    // ----------------------------------------------------
    // 第二层 & 第三层：回源状态码滑动窗口分析
    // ----------------------------------------------------

    const status = originResponse.status;

    if (status === 404 || status === 403) {
      const windowSeconds = parseInt(env.STATUS_404_WINDOW_SECONDS || '60', 10);
      const threshold404 = parseInt(env.STATUS_404_THRESHOLD || '8', 10);

      // 滑动窗口检查
      if (now - currentStrike.status404WindowStart > windowSeconds * 1000) {
        // 第三层：超过 60 秒的偶发 404，重置计数，放行普通访客
        currentStrike.status404Hits = 1;
        currentStrike.status404WindowStart = now;
      } else {
        currentStrike.status404Hits += 1;
      }

      memStrikes.set(ip, currentStrike);

      // 第二层：60 秒内 404 达到阈值，判定为暴力扫站，执行阶梯封禁
      if (currentStrike.status404Hits >= threshold404) {
        await executeBan(
          ip,
          `High Frequency 404 Scanning (${currentStrike.status404Hits} hits / ${windowSeconds}s)`,
          env,
          ctx
        );

        return new Response('Forbidden: Excessive Scanning Detected', {
          status: 403,
          headers: { 'Content-Type': 'text/plain; charset=utf-8' },
        });
      }
    }

    return originResponse;
  },
};