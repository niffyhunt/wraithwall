# Incident — Outlaw/"mdrfckr" SSH-key persistence worm

- **Date:** 2026-05-31 (window 10:57–11:05 UTC)
- **Detected by:** Cowrie intelligence pipeline → Telegram/Discord (6× "HIGH-THREAT SESSION", score 85/100)
- **Target:** Cowrie honeypot `COWRIE_VPS_IP` (no real-world exposure — all activity simulated)
- **Verdict:** Single coordinated botnet campaign, not 6 separate incidents.

## Signature
After a successful `root` login each node ran the identical payload:
```
cd ~; chattr -ia .ssh; lockr -ia .ssh
cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3N...mdrfckr" >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
```
Same SSH public key + `mdrfckr` comment on all 6 → Outlaw/Dota family worm.
MITRE: **T1098.004** (SSH Authorized Keys), **T1222.002** (chmod/chattr).

## Nodes
| IP | Country | ASN / Network | Root pw sprayed |
|---|---|---|---|
| 65.181.127.40 | GB | AS36454 WHG Hosting | 868686 |
| 58.229.253.119 | KR | AS9318 SK Broadband | aaaa1111 |
| 47.250.117.108 | US/CN | AS45102 Alibaba | @Aa123456 |
| 171.25.158.68 | SE | AS35100 Patrik Lagerman | 6969 |
| 103.187.147.214 | ID/SG | AS138608 Cloud Host | PAssw0rd |
| 103.143.231.24 | HK | AS138152 YISU Cloud | 6969 |

## Response taken
1. **Blocked** all 6 IPs: `gateway:blocked:{ip}` (7-day TTL).
2. **IOC persisted:** Redis `ioc:campaign:outlaw_mdrfckr_2026-05-31` (30-day TTL).
3. **Classifier tuned** (`cowrie_intelligence._apply_behavioral_overrides`): sub-15s
   scripted sessions and the `mdrfckr` signature now classify as `botnet_node`
   instead of the LLM's `human_operator` guess.
4. **Alert grouping** (`_check_threshold_alerts`): high-threat sessions sharing an
   identical command payload now collapse to one alert per `ALERT_DEDUP_WINDOW`
   (default 900s); source-IP spread tracked under `cowrie_campaign_ips:{sig}`.
