"""浏览器后端路由：本地 Chrome / 本地 Firefox 150。"""


class BrowserBackends:

    def __init__(self, local, firefox, store):
        self.local = local
        self.firefox = firefox
        self.store = store

    # ---------- 配置 ----------

    def backend(self, env_id):
        meta = self.store.get(env_id) or {}
        backend = str(meta.get("browserBackend") or "local").lower()
        # 旧数据里可能残留 ads：AdsPower 运行时已移除，统一迁移到本地 Firefox 150
        if backend == "ads":
            return "firefox"
        return backend if backend in ("local", "firefox") else "local"

    @property
    def chrome(self):
        return getattr(self.local, "chrome", None)

    def chrome_available(self):
        return bool(self.local and self.local.chrome_available())

    def firefox_available(self, version=None):
        return bool(self.firefox and self.firefox.available(version))

    # ---------- 生命周期 ----------

    def start(self, env_id, url="https://www.taobao.com", proxy_port=None, display_name=""):
        if self.backend(env_id) == "firefox":
            meta = self.store.get(env_id) or {}
            return self.firefox.start(
                env_id, url=url, proxy_port=proxy_port, display_name=display_name,
                version=meta.get("kernelVersion"))
        return self.local.start(env_id, url=url, proxy_port=proxy_port, display_name=display_name)

    def stop(self, env_id):
        # 两个后端都尝试，避免运行中切换后端导致旧实例关不掉
        try:
            self.firefox.stop(env_id)
        except Exception:
            pass
        try:
            self.local.stop(env_id)
        except Exception:
            pass
        return True

    def forget(self, env_id):
        """环境被回收/彻底删除时清理状态。"""
        try:
            self.firefox.stop(env_id)
        except Exception:
            pass
        try:
            self.local.stop(env_id)
        except Exception:
            pass

    def stop_all(self):
        self.firefox.stop_all()
        self.local.stop_all()

    # ---------- 查询 ----------

    def running(self, env_id):
        return bool(self.firefox.running(env_id) or self.local.running(env_id))

    def debug_port(self, env_id):
        if self.backend(env_id) == "firefox":
            return self.firefox.debug_port(env_id) or self.local.debug_port(env_id)
        return self.local.debug_port(env_id) or self.firefox.debug_port(env_id)

    def profile_dir(self, env_id):
        if self.backend(env_id) == "firefox":
            return self.firefox.profile_dir(env_id) or self.local.profile_dir(env_id)
        return self.local.profile_dir(env_id) or self.firefox.profile_dir(env_id)

    def list_running(self):
        merged = self.local.list_running()
        merged.update(self.firefox.list_running())
        return merged

    # ---------- CDP 专用能力 ----------

    def page_targets(self, port):
        if self.backend_by_port(port) == "firefox":
            raise RuntimeError("Firefox 内核使用 WebDriver BiDi，不支持 CDP 窗口同步")
        return self.local.page_targets(port)

    def backend_by_port(self, port):
        for env_id in list((self.store.all() or {}).keys()):
            if self.backend(env_id) == "firefox" and self.firefox.debug_port(env_id) == port:
                return "firefox"
        return "local"
