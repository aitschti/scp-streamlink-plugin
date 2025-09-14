from asyncio import streams
import logging
import re
import io
import tempfile 
import socket
import subprocess
import time 
import os
from typing import Optional
from urllib.parse import urlparse, quote
from pathlib import Path 
import streamlink 

from streamlink.plugin import Plugin, pluginmatcher
from streamlink.plugin.api import validate
from streamlink.stream.hls import HLSStream
from streamlink.exceptions import PluginError
from streamlink.options import Arguments

@pluginmatcher(re.compile(
    r"http://localhost(?::\d+)?/stripchat/(?P<username>[a-zA-Z0-9_-]+(?:\.m3u8)?)(?:/.*)?$",
    re.IGNORECASE
))
class StripchatProxy(Plugin):
    # Schema for API response validation (if needed, but proxy handles it)
    _data_schema = validate.Schema(
        validate.any(
            None,
            {
                "cam": {
                    "streamName": str,
                    "topic": str,
                },
                "user": {
                    "user": {
                        "status": str,
                        "isLive": bool
                    }
                }
            }
        )
    )

    def __init__(self, session, url: str, options: Optional[Arguments] = None):
        # Check Streamlink version for compatibility (options added in 6.0.0)
        version = tuple(map(int, streamlink.__version__.split('.')))
        if version >= (6, 0, 0):
            super().__init__(session, url, options)
        else:
            super().__init__(session, url)
        
        self.author: Optional[str] = None
        self.title: Optional[str] = None
        # New: Track proxy subprocess and whether we started it
        self._proxy_process: Optional[subprocess.Popen] = None
        self._started_proxy: bool = False

    def __del__(self):
        """Cleanup: Terminate the proxy subprocess if we started it."""
        logger = logging.getLogger(__name__)  # Use standard logging for consistency
        if self._started_proxy and self._proxy_process and self._proxy_process.poll() is None:
            try:
                logger.info("Terminating proxy subprocess...")
                self._proxy_process.terminate()
                self._proxy_process.wait(timeout=5)  # Wait up to 5s for graceful shutdown
                logger.info("Proxy subprocess terminated.")
            except subprocess.TimeoutExpired:
                logger.warning("Proxy subprocess did not terminate gracefully; force killing...")
                self._proxy_process.kill()
                self._proxy_process.wait()
            except Exception as e:
                logger.error(f"Error terminating proxy subprocess: {e}")
        self._proxy_process = None
        self._started_proxy = False

    def get_title(self) -> Optional[str]:
        return self.title

    def get_author(self) -> Optional[str]:
        return self.author

    def get_category(self) -> str:
        return "NSFW LIVE"

    def _is_port_open(self, host, port):
        """Check if the port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _start_proxy(self, host, port):
        """Start the proxy server if not running."""
        plugin_dir = os.path.dirname(os.path.abspath(__file__))
        proxy_script_path = os.path.join(plugin_dir, 'stripchat_proxy.py')  # Update if path differs
        
        if not os.path.exists(proxy_script_path):
            self.logger.error(f"Proxy script not found at {proxy_script_path}. Please place 'stripchat_proxy.py' in the same directory as the plugin.")
            return False
        
        try:
            self.logger.info(f"Starting proxy on {host}:{port}")
            # Start and store the process
            self._proxy_process = subprocess.Popen(['python', proxy_script_path, '--host', host, '--port', str(port)], 
                                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._started_proxy = True  # Mark that we started it
            time.sleep(2)  # Wait for proxy to start
            return True
        except Exception as e:
            self.logger.error(f"Failed to start proxy: {e}")
            self._proxy_process = None
            self._started_proxy = False
            return False

    def _get_streams(self):
        username = self.match.group("username")
        if username.endswith('.m3u8'):
            username = username[:-5]  # Strip .m3u8 from username
        if not username:
            raise PluginError("Invalid username in proxy URL")

        # Parse the proxy URL to extract host and port
        parsed = urlparse(self.url)
        host = parsed.hostname
        port = parsed.port

        # Check if proxy is running, start if not
        if not self._is_port_open(host, port):
            if not self._start_proxy(host, port):
                raise PluginError("Failed to start proxy server")

        # API URL to get stream details
        api_url = f"https://stripchat.com/api/front/v2/models/username/{username}/cam"

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"https://www.stripchat.com/{username}",
            "Origin": "https://www.stripchat.com",
            "User-Agent": self.session.http.headers.get("User-Agent", "")
        }

        try:
            # Fetch API data
            res = self.session.http.get(api_url, headers=headers)
            data = self.session.http.json(res, schema=self._data_schema)

            if not data or not data.get("cam") or not data.get("user"):
                self.logger.error("Invalid API response or stream offline")
                return

            user_data = data["user"]["user"]
            if not user_data["isLive"] or user_data["status"] != "public":
                self.logger.info(f"Stream offline or private (status: {user_data['status']})")
                return

            stream_name = data["cam"]["streamName"]
            m3u8_url = f"https://edge-hls.doppiocdn.com/hls/{stream_name}/master/{stream_name}_auto.m3u8"
            m3u8_url_fallback = f"https://edge-hls.doppiocdn.com/hls/{stream_name}/master/{stream_name}.m3u8"

            # Try primary M3U8 URL first
            try:
                proxy_url = f"http://{host}:{port}/?url={quote(m3u8_url)}"
                m3u8_res = self.session.http.get(proxy_url, headers=headers)
                raw_m3u8 = m3u8_res.text
                streams = HLSStream.parse_variant_playlist(self.session, proxy_url, headers=headers)
                yield from streams.items()
            except Exception as e:
                self.logger.warning(f"Failed with primary M3U8 URL: {e}, trying fallback")
                # Try fallback M3U8 URL
                try:
                    proxy_url = f"http://{host}:{port}/?url={quote(m3u8_url_fallback)}"
                    m3u8_res = self.session.http.get(proxy_url, headers=headers)
                    raw_m3u8 = m3u8_res.text
                    streams = HLSStream.parse_variant_playlist(self.session, proxy_url, headers=headers)
                    yield from streams.items()
                except Exception as e2:
                    self.logger.error(f"Failed with fallback M3U8 URL: {e2}")
                    return

        except Exception as e:
            self.logger.error(f"Failed to fetch or parse M3U8: {e}")
            return

__plugin__ = StripchatProxy