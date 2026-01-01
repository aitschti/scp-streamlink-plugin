# StripChatProxied - A Streamlink Plugin

**JAN '26 UPDATE: Two versions available now. V2 (recommended) is more flexible with key selection.**

This is a Streamlink plugin for StripChat, integrating a proxy for m3u8 playlist file handling and decoding of scrambled playlist URLs.

## Versions

- **stripchat_proxied_v2.py** (RECOMMENDED): The new v2-only implementation with robust PSCH line selection. Uses `keys.txt` with format `pkey:pdkey` to automatically match the correct v2 encryption line from master playlists, no matter which position the key has in the playlist. This version is more flexible as Stripchat may possibly rotate between multiple v2 keys, and the proxy automatically selects the matching one.

- **stripchat_proxied.py** (LEGACY): The original implementation. Uses `key.txt` for single key storage and is set to use last available pkey. This version will be replaced by v2 in the future.

## Files

### V2 Version (Recommended)

- **stripchat_proxied_v2.py / stripchat_proxy_v2.py**: The recommended v2 proxy implementation. Handles v2 playlist decryption with key matching. Uses `keys.txt` for key storage in `pkey:pdkey` format.

- **keys.txt**: Required for v2 version. Stores key pair in format `pkey:pdkey` (e.g., `Zeec...:ubah...`). The pkey determines which v2 PSCH line to use, pdkey decrypts the segments.

### Legacy Version

- **stripchat_proxy.py / stripchat_proxied.py**: The legacy proxy implementation. Uses `key.txt` for single key storage.

- **key.txt**: Used by legacy version only. Stores single decryption key. Proxy will use last available pkey, no matter what.

## Installation

### For V2 Version (Recommended)

1. Put `stripchat_proxied_v2.py` and `stripchat_proxy_v2.py` in your Streamlink plugins directory.
2. Create a `keys.txt` file in the same directory with format `pkey:pdkey` (e.g., `Zeec...:ubah...`).

### For Legacy Version

1. Put `stripchat_proxied.py` and `stripchat_proxy.py` in your Streamlink plugins directory.
2. Create a `key.txt` file in the same directory with the decryption key.

## Usage from the command line

Stream on the same machine starting default player

```cmd
streamlink --player-passthrough hls http://localhost:<port>/stripchat/<username> <quality>
```

or through http-external command for delivering the stream into your network or other apps on the same machine

```cmd
streamlink --player-external-http http://localhost:<port>/stripchat/<username> <quality>

With specific port:

streamlink --player-external-http --player-external-http-port <external_port> http://localhost:<port>/stripchat/<username> <quality>

URL to open:
http://<ip from command log>:<external_port or from command log>

```

Instead of the normal stripchat URL plus username, you will be using the proxied URL. `<port>` is the port number to use. You can put any port number you like in there (e.g. 8080), as long as it is not used by another service. The proxy will start automatically in the background when you open the streamlink command. Multiple instances should be possible this way using different ports. `<quality>` is your choice of stream quality (e.g. `best`, `worst`, `720p`, etc.), if available. Starting streamlink without quality option, streamlink will show all available qualities as usual.

When using `--player-external-http`, you may need to adjust your firewall settings to allow incoming connections on the specified port `<external_port>` or the one you see in the command output.

## Notes

- Both proxy versions require manual key management - no automatic key fetching
- Working and tested on Windows and MacOS, Linux untested
- **IMPORTANT**: Only use ONE proxy version in your plugins directory at a time

This plugin is for educational purposes only. Use it at your own risk. I am not responsible for any consequences that may arise from using this plugin.
