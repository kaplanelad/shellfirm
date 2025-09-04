# shellfirm_core

**🛡️ The Smart Command Validator - Never Accidentally Delete Everything Again**

`shellfirm_core` is the powerful validation engine that prevents catastrophic command mistakes. Whether you're building a terminal app, web interface, or cross-platform tool, this crate gives you bulletproof protection against dangerous shell commands.

**Stop these disasters before they happen:**

- `rm -rf /` - Deleting your entire system
- `git reset --hard` - Losing all your work
- `kubectl delete ns production` - Taking down production

## Why shellfirm_core?

### ⚡ **Lightning Fast**

- **Compile-time Optimization**: All patterns embedded for maximum performance
- **Minimal Footprint**: Tiny runtime overhead
- **WASM Ready**: Runs everywhere - browsers, Node.js, mobile apps

### 🎯 **Developer Friendly**

- **Simple API**: Just call `validate_command()` and get instant results
- **Flexible Integration**: Works in Rust, JavaScript, and any WASM environment
- **Rich Metadata**: Get severity levels, descriptions, and challenge types

## License

MIT License - see [LICENSE](../LICENSE) for details.

## Related Projects

- **[shellfirm](https://github.com/kaplanelad/shellfirm)** - The main shellfirm CLI tool
- **[shellfirm MCP](https://github.com/kaplanelad/shellfirm/tree/mcp)** - Model Context Protocol integration

---

**Ready to protect your users?** Add `shellfirm_core` to your project today! 🚀
