# StripChatProxied - A Streamlink Plugin

This is a Streamlink plugin for StripChat that allows you to proxy the playlist files through a local server and decoded the newly added encryption of playlist files.

## Installation

Put the `stripchat_proxied.py` and `stripchat_proxy.py` in your Streamlink plugins directory.

Additionally, you need a file called `key.txt` in the same directory, containing a working decode key. I WILL NOT PROVIDE THIS KEY FOR YOU. This plugin will not work without it!

## Usage from the command line

```
streamlink http://localhost:8080/stripchat/<username> <quality>
```

Instead of the normal stripchat URL plus username, you will be using the proxied URL. 8080 is the port number to use. You can put any port number you like in there, as long as it is not used by another service.
The proxy will start automatically when you use the proxied URL with streamlink. Multiple instances should be possible this way using different ports. Quality is your choice of stream quality (e.g. `best`, `worst`, `720p`, etc.).

## Limitations

- Working on Windows only at the moment
- Mac playback only works for the first segment
- Linux not tested, may not work at all
- No cleanup of temp files (uses a temp file for the decryptedplaylist)

## Notes

This plugin is for educational purposes only. Use it at your own risk. I am not responsible for any consequences that may arise from using this plugin. It was vibe coded in an hour, so expect bugs and issues.
