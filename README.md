# WP Edge Shield (Cloudflare Worker WAF)

针对 WordPress / PHP 源站设计的 Cloudflare 边缘防护网关与高频 404 扫站熔断器。

## 架构特性
1. **第 0 层快速阻断**：内存 IP 白名单直通；查验 KV 已封禁 IP 并直接 403 阻断。
2. **第一层致命指纹检测**：针对 `.env`、`.git`、密钥文件、Honeypot 等直接拦截并封禁，零回源。
3. **第二层高频 404 熔断**：60 秒滑动窗口时序监控，遏制暴力爬虫对未注册 URL 的扫描。
4. **第三层偶发容差**：普通访客或正常抓取偶发 404 自动放行。
5. **单 IP 阶梯封禁**：1h -> 24h -> 7d -> 365d，通过 KV 原生 TTL 自动清理。
6. **边缘 404 缓存**：源站返回 404 在边缘缓存 30 秒，防止同节点反复击穿 WordPress。

## 本地开发与部署

```bash
# 1. 安装依赖
npm install

# 2. 本地调试
npm run dev

# 3. 正式发布部署
npm run deploy

# 4. 实时查看拦截日志
npm run tail



### 三、 本地 Git 初始化并推送到 GitHub 步骤

你不需要把 GitHub 账号或密码给我，直接在你的本地电脑终端（Terminal / PowerShell）中运行以下几步即可完成推送：

#### 步骤 1：去 GitHub 网页新建仓库
1. 打开 [github.com](https://github.com)，点击右上角 **+** 号 -> **New repository**。
2. 填写仓库名（如 `wp-edge-shield`），选择 **Private（私有）**。
3. **不要**勾选 "Add a README file"、".gitignore" 等初始化选项（因为我们本地已经全部写好了），直接点击 **Create repository**。
4. 复制页面生成的仓库 Git 地址（如 `git@github.com:你的用户名/wp-edge-shield.git` 或 `[https://github.com/你的用户名/wp-edge-shield.git](https://github.com/你的用户名/wp-edge-shield.git)`）。

#### 步骤 2：在本地项目文件夹执行推送命令
打开本地终端，进入刚才建好的项目文件夹：

```bash
# 1. 初始化本地 Git 仓库
git init

# 2. 检查所有文件并添加到暂存区
git add .

# 3. 提交初始版本
git commit -m "feat: initial commit with 3-tier circuit breaker WAF for WordPress"

# 4. 设置默认分支为 main
git branch -M main

# 5. 关联你的 GitHub 远程仓库 (替换成你在步骤 1 复制的地址)
git remote add origin https://github.com/你的用户名/wp-edge-shield.git

# 6. 推送到 GitHub
git push -u origin main