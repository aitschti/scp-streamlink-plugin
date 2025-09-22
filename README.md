# StripChatProxied - A Streamlink Plugin

This is a Streamlink plugin for StripChat, integrating a proxy for m3u8 playlist file handling.

## Installation

Put the `stripchat_proxied.py` and `stripchat_proxy.py` in your Streamlink plugins directory.

A file called `key.txt` in the same directory will be created on first run and changed on retrieving a new key on key changes. This reflects a solution to the latest playlist url scrambling by Stripchat in late August 2025.

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

- Working and tested on Windows and MacOS, Linux untested

This plugin is for educational purposes only. Use it at your own risk. I am not responsible for any consequences that may arise from using this plugin. It is completely vibe coded, so expect bugs and issues.
