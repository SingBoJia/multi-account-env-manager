"""配置导入导出：把环境、节点、指纹、订阅打包成一份 JSON，便于备份与迁移。

安全取舍：
- 默认导出**不含**任何凭据（代理密码、UUID、私钥）；
- 需要完整备份时显式传 includeSecrets=True；
- 导出的文件带版本号，导入时做兼容校验。
"""

import json
import time

EXPORT_VERSION = 1

# 这些字段属于凭据，默认不导出
SECRET_FIELDS = (
    "password", "uuid", "username",
    "realityPublicKey", "realityShortId",
)


class ConfigIO:

    def __init__(self, store, pool, engine, subs):
        self.store = store
        self.pool = pool
        self.engine = engine
        self.subs = subs

    # ---------- 导出 ----------

    def export_all(self, include_secrets=False, include_fingerprints=True, include_subs=True):
        envs = self.store.all()
        nodes = self.pool.all()
        fps = self.engine.all() if include_fingerprints else {}
        subs = self.subs.all() if include_subs else {}

        env_list = []
        for env_id, meta in envs.items():
            backend = str(meta.get("browserBackend") or "firefox").lower()
            if backend == "ads" or backend not in ("local", "firefox"):
                backend = "firefox"
            item = {
                "id": env_id,
                "name": meta.get("name", ""),
                "platform": meta.get("platform", ""),
                "remark": meta.get("remark", ""),
                "startUrl": meta.get("startUrl", ""),
                "browserBackend": backend,
                # 用节点名而不是 ID：跨机器导入时 ID 会变
                "nodeName": (nodes.get(meta.get("nodeId") or "", {}) or {}).get("name", ""),
            }
            env_list.append(item)

        node_list = []
        for node in nodes.values():
            item = dict(node)
            item.pop("id", None)
            if not include_secrets:
                for k in SECRET_FIELDS:
                    if k in item:
                        item[k] = "***"
            node_list.append(item)

        sub_list = []
        if include_subs:
            for sub in subs.values():
                sub_list.append({
                    "name": sub.get("name", ""),
                    "url": sub.get("url", "") if include_secrets else _mask(sub.get("url", "")),
                    "group": sub.get("group", ""),
                    "autoAssign": sub.get("autoAssign", False),
                    "enabled": sub.get("enabled", True),
                })

        return {
            "version": EXPORT_VERSION,
            "exportedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
            "includeSecrets": bool(include_secrets),
            "environments": env_list,
            "nodes": node_list,
            "subscriptions": sub_list,
            "fingerprints": list(fps.values()) if include_fingerprints else [],
        }

    # ---------- 导入 ----------

    def import_all(self, data, overwrite=False, lock_password=""):
        """导入配置，返回统计结果。

        已存在的环境/节点默认跳过，overwrite=True 时覆盖环境配置
        （指纹仍保留原值，避免设备身份突变引发平台验证）。
        已上锁的环境必须提供正确的锁密码（lock_password）才会被覆盖，
        否则跳过并计入 locked 列表——防止导入/云恢复绕过环境锁。
        """
        if not isinstance(data, dict):
            raise ValueError("导入内容不是合法 JSON 对象")
        ver = data.get("version")
        if ver != EXPORT_VERSION:
            raise ValueError("不支持的文件版本: %r（期望 %d）" % (ver, EXPORT_VERSION))

        result = {
            "environments": {"added": 0, "skipped": 0, "updated": 0, "locked": []},
            "nodes": {"added": 0, "skipped": 0},
            "subscriptions": {"added": 0, "skipped": 0},
            "fingerprints": {"added": 0, "skipped": 0},
        }

        # 先导节点，环境的 nodeName 才能在节点存在后解析
        name_to_node = {}
        for node in data.get("nodes") or []:
            name = node.get("name") or ""
            if not name:
                result["nodes"]["skipped"] += 1
                continue
            if _node_exists_by_name(self.pool, name):
                result["nodes"]["skipped"] += 1
                continue
            record = dict(node)
            record.pop("id", None)
            # 占位符还原为空，避免把 *** 当成真实密码
            for k in SECRET_FIELDS:
                if record.get(k) == "***":
                    record.pop(k, None)
            ids = self.pool.add_many([record], group=record.get("group", ""))
            if ids:
                name_to_node[name] = ids[0]
                result["nodes"]["added"] += 1

        # 再导环境
        for env in data.get("environments") or []:
            env_id = env.get("id")
            if not env_id:
                result["environments"]["skipped"] += 1
                continue
            exists = bool(self.store.get(env_id))
            if exists and not overwrite:
                result["environments"]["skipped"] += 1
                continue
            node_id = name_to_node.get(env.get("nodeName") or "")
            if not node_id:
                # 节点已存在时按名称找回
                node_id = _find_node_id_by_name(self.pool, env.get("nodeName") or "")
            backend = str(env.get("browserBackend") or "firefox").lower()
            if backend == "ads" or backend not in ("local", "firefox"):
                backend = "firefox"
            try:
                # 已上锁环境：密码不对就跳过，导入/云恢复不能绕过环境锁
                if exists and self.store.is_locked(env_id) \
                        and not self.store.check_password(env_id, lock_password or ""):
                    result["environments"]["locked"].append(env_id)
                    continue
                if exists:
                    self.store.update(
                        env_id,
                        name=env.get("name", ""),
                        platform=env.get("platform", ""),
                        remark=env.get("remark", ""),
                        startUrl=env.get("startUrl", ""),
                        nodeId=node_id or "",
                        browserBackend=backend,
                        kernelVersion=env.get("kernelVersion") or "",
                    )
                    result["environments"]["updated"] += 1
                else:
                    self.store.create(
                        env_id,
                        name=env.get("name", ""),
                        platform=env.get("platform", ""),
                        remark=env.get("remark", ""),
                        start_url=env.get("startUrl", ""),
                        node_id=node_id or "",
                        browser_backend=backend,
                        kernel_version=env.get("kernelVersion") or "",
                    )
                    result["environments"]["added"] += 1
            except ValueError:
                result["environments"]["skipped"] += 1

        # 最后导指纹：已存在的一律保留，避免改变设备身份
        for fp in data.get("fingerprints") or []:
            env_id = fp.get("envId")
            if not env_id:
                result["fingerprints"]["skipped"] += 1
                continue
            if self.engine.get(env_id):
                result["fingerprints"]["skipped"] += 1
                continue
            try:
                self.engine.save(env_id, fp)
                result["fingerprints"]["added"] += 1
            except ValueError:
                result["fingerprints"]["skipped"] += 1

        # 订阅
        for sub in data.get("subscriptions") or []:
            url = sub.get("url") or ""
            if not url or url == "***" or "***" in url:
                result["subscriptions"]["skipped"] += 1
                continue
            if _sub_exists_by_url(self.subs, url):
                result["subscriptions"]["skipped"] += 1
                continue
            self.subs.add(
                url,
                name=sub.get("name", ""),
                group=sub.get("group", ""),
                auto_assign=sub.get("autoAssign", False),
            )
            result["subscriptions"]["added"] += 1

        return result

    def import_envs_only(self, data):
        """只导环境列表（用于从别的工具批量建环境）。"""
        rows = data.get("environments") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            raise ValueError("文件里没有 environments 数组")
        added, skipped = 0, 0
        for row in rows:
            env_id = row.get("id")
            if not env_id or self.store.get(env_id):
                skipped += 1
                continue
            try:
                self.store.create(
                    env_id,
                    name=row.get("name", ""),
                    platform=row.get("platform", ""),
                    remark=row.get("remark", ""),
                    start_url=row.get("startUrl", ""),
                )
                self.engine.load_or_create(env_id)
                added += 1
            except ValueError:
                skipped += 1
        return {"added": added, "skipped": skipped}


def _mask(url):
    if not url:
        return ""
    try:
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        p = urlsplit(url)
        if not p.query:
            return url
        q = [(k, ("***" if len(v) > 8 else v)) for k, v in parse_qsl(p.query, keep_blank_values=True)]
        return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment))
    except ValueError:
        return url


def _node_exists_by_name(pool, name):
    for node in pool.all().values():
        if node.get("name") == name:
            return True
    return False


def _find_node_id_by_name(pool, name):
    if not name:
        return ""
    for node_id, node in pool.all().items():
        if node.get("name") == name:
            return node_id
    return ""


def _sub_exists_by_url(subs, url):
    for sub in subs.all().values():
        if sub.get("url") == url:
            return True
    return False
