"""Authenticated private Streamable HTTP boundary for a trusted gateway upstream.

This is a static upstream credential, NOT an Okta/OAuth authorization server.
"""
import json
import re
import secrets
from pathlib import Path
from mcp.server.transport_security import TransportSecuritySettings


class PrivateHTTP:
    def __init__(self, app, token, allowed_hosts):
        if not isinstance(token,str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}",token):
            raise ValueError("HTTP bearer secret must be 32–256 URL-safe characters")
        if not allowed_hosts or any(not re.fullmatch(r"[a-zA-Z0-9.-]+(?::[0-9]{1,5})?",h) for h in allowed_hosts):
            raise ValueError("Explicit non-wildcard HTTP Host allowlist required")
        self.app,self.token,self.hosts=app,token,{h.lower() for h in allowed_hosts}

    async def reject(self,send,status,message):
        headers=[(b"content-type",b"application/json"),(b"cache-control",b"no-store")]
        if status==401:headers.append((b"www-authenticate",b"Bearer"))
        body=json.dumps({"status":"ok","router_connectivity":"not_tested"} if status==200 else {"error":message}).encode()
        await send({"type":"http.response.start","status":status,"headers":headers})
        await send({"type":"http.response.body","body":body})

    async def __call__(self,scope,receive,send):
        if scope["type"]=="lifespan":
            return await self.app(scope,receive,send)
        if scope["type"]!="http":
            if scope["type"]=="websocket":await send({"type":"websocket.close","code":1008})
            return
        headers={}
        for key,value in scope.get("headers",[]):headers.setdefault(key.lower(),[]).append(value)
        hosts=headers.get(b"host",[])
        if len(hosts)!=1 or hosts[0].decode("latin1").lower() not in self.hosts:
            return await self.reject(send,421,"Host not allowed")
        # Gateway-to-backend requests have no browser Origin. Direct browser access is denied.
        if b"origin" in headers:
            return await self.reject(send,403,"Browser Origin not allowed")
        if scope.get("query_string"):
            return await self.reject(send,400,"Query parameters not accepted")
        auth=headers.get(b"authorization",[])
        expected=("Bearer "+self.token).encode()
        if len(auth)!=1 or not secrets.compare_digest(auth[0],expected):
            return await self.reject(send,401,"Authentication required")
        if scope.get("path")=="/healthz":
            return await self.reject(send,200,"process_ready; router connectivity not tested")
        return await self.app(scope,receive,send)


def http_app(server,token_file,allowed_hosts):
    token=Path(token_file).read_text().strip()
    server.settings.transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,allowed_hosts=allowed_hosts,allowed_origins=[])
    return PrivateHTTP(server.streamable_http_app(),token,allowed_hosts)
