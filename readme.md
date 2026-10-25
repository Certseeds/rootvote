# rootvote

> a cli tool to remove a few https certs in Ur system

## where the certs come from

使用 <https://github.com/crtsh/ccadb_data> 作为数据源, 默认对某些国家和其余的证书进行预填充.

## 支持的 target

| 平台 | 默认 target |
|---|---|
| Windows | `system,firefox,thunderbird` |
| Linux | `firefox,thunderbird,chromium` |

Linux 上 `chromium` 指向 `~/.pki/nssdb`;Chrome/Chromium 共用该 NSS 库。Windows 上 Chromium 走系统证书存储,`chromium` target 会被跳过。

`system` 在 Windows 上写入 `Disallowed` 证书存储。`firefox` / `thunderbird` 通过 NSS `certutil` 修改各 profile 的 `cert9.db`。

自定义 profile:

```bash
rootvote apply --targets firefox --cert9-path firefox:/path/to/profile/cert9.db
```

`--cert9-path` 的值是 `cert9.db` 的完整路径,可重复。`--browsers` 与 `--firefox-profile` 是兼容用的隐藏别名。

## Linux

Linux 依赖系统 `certutil`:

```bash
sudo apt install libnss3-tools
```

用户级 NSS(Firefox / Thunderbird / Chrome / Chromium):

```bash
rootvote apply --scope user --targets firefox,thunderbird,chromium
rootvote status
rootvote undo --scope user --all
```

Linux 发行包不包含 `tools/nss`,运行时从 `PATH` 查找 `certutil`。Snap/Flatpak/自定义 NSS 库用 `--cert9-path` 指定。

`undo --force` 只删除 rootvote 昵称,无法恢复被改过 trust 的既有条目。
