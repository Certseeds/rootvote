# rootvote

> a cli tool to remove a few https certs in Ur system

## where the certs come from

使用 <https://github.com/crtsh/ccadb_data> 作为数据源, 默认对某些国家和其余的证书进行预填充.

## 支持的 target

| 平台 | 默认 target |
|---|---|
| Windows | `system,firefox,thunderbird` |
| Linux | `firefox,thunderbird` |

`system` 在 Windows 上写入 `Disallowed` 证书存储。`firefox` / `thunderbird` 通过 NSS `certutil` 修改各 profile 的 `cert9.db`。

自定义 profile:

```bash
rootvote apply --targets firefox --cert9-path firefox:/path/to/profile/cert9.db
```

`--cert9-path` 的值是 `cert9.db` 的完整路径,可重复。`--browsers` 与 `--firefox-profile` 是兼容用的隐藏别名。
