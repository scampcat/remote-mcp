# Remote MCP Server with Reflection Capabilities

A production-ready remote Model Context Protocol (MCP) server built with C# and ASP.NET Core, featuring comprehensive reflection tools for dynamic introspection and self-documentation.

## 🚀 Features

- **16 Tools** across 4 categories (Math, Utility, Data, Reflection)
- **Self-Documenting** with 5 powerful reflection tools
- **Network Ready** - accepts connections from any IP
- **Production Grade** - built with ASP.NET Core and Kestrel
- **Universal MCP Client Support** - works with Claude Code, Cursor, VS Code
- **Comprehensive Error Handling** and validation
- **Type-Safe Parameters** with rich descriptions

## 📋 Tool Categories

### Math Tools (4)
- `Add` - Adds two numbers together
- `Subtract` - Subtracts the second number from the first
- `Multiply` - Multiplies two numbers together  
- `Divide` - Divides the first number by the second (with zero-division protection)

### Utility Tools (3)
- `Echo` - Echoes input messages back to the client
- `GetCurrentTime` - Returns current server time in UTC
- `GenerateRandomNumber` - Generates random numbers with configurable range

### Data Tools (4)
- `FormatJson` - Converts JSON strings to formatted, indented JSON
- `ToUpperCase` - Converts text to uppercase
- `ToLowerCase` - Converts text to lowercase
- `ReverseText` - Reverses input text

### Reflection Tools (5) ⭐
- `ListAllTools` - Complete inventory of all available tools with metadata
- `GetToolInfo` - Detailed analysis of specific tools including parameters
- `ListToolsByCategory` - Filter tools by category (Math, Utility, Data, Reflection)
- `SearchTools` - Intelligent keyword search across tool names and descriptions
- `GetServerMetadata` - Server introspection including .NET version and capabilities

## 🛠 Quick Start

### Prerequisites
- [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- [Node.js](https://nodejs.org/) (for mcp-remote proxy)
- [Claude Code](https://claude.ai/code)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/scampcat/remote-mcp.git
   cd remote-mcp
   ```

2. **Restore packages**
   ```bash
   dotnet restore
   ```

3. **Build the project**
   ```bash
   dotnet build
   ```

4. **Run the server**
   ```bash
   dotnet run
   ```
   
   The server will start on `http://0.0.0.0:3001` and accept connections from any network interface.

### Testing the Server

**Health Check:**
```bash
curl http://localhost:3001/health
# Expected: {"status":"healthy","timestamp":"2025-XX-XX..."}
```

**Server Info:**
```bash
curl http://localhost:3001/info
# Returns server metadata and available endpoints
```

**MCP Protocol Test:**
```bash
curl http://localhost:3001/
# Expected: MCP protocol error (this confirms MCP is active)
```

## 🔗 Claude Code Integration

### Option 1: Automatic Configuration
The repository includes a `.mcp.json` file for immediate Claude Code integration:

```bash
claude mcp add remote-math-server --scope project npx mcp-remote http://localhost:3001/
```

### Option 2: Manual Configuration
Add to your Claude Code MCP configuration:

```json
{
  "mcpServers": {
    "remote-math-server": {
      "command": "npx",
      "args": ["mcp-remote", "http://localhost:3001/"],
      "description": "Remote MCP server with math, utility, data, and reflection tools"
    }
  }
}
```

### Verification
```bash
claude mcp list
# Should show: remote-math-server: npx mcp-remote http://localhost:3001/ - ✓ Connected
```

## 🧪 Testing Reflection Features

Try these commands in Claude Code:

**Complete Tool Discovery:**
> "List all available tools"

**Tool Analysis:**
> "Show me detailed information about the divide tool"

**Category Filtering:**
> "What tools are in the Math category?"

**Intelligent Search:**
> "Search for tools related to text processing"

**System Information:**
> "What's the server metadata?"

## 🏗 Architecture

### Core Components

- **Transport Layer**: Streamable HTTP with CORS support
- **Tool Discovery**: Attribute-based auto-registration using `[McpServerToolType]` and `[McpServerTool]`
- **Reflection System**: .NET reflection APIs for runtime introspection
- **Error Handling**: Comprehensive validation and graceful error responses
- **Security**: Scoped assembly reflection with attribute-based filtering

### Key Patterns

**Tool Implementation:**
```csharp
[McpServerToolType]
public static class YourTools
{
    [McpServerTool, Description("What your tool does")]
    public static ReturnType YourMethod(
        [Description("Parameter description")] ParameterType param)
    {
        // Implementation with proper error handling
        return result;
    }
}
```

**Reflection Safety:**
```csharp
// ✅ Safe: Scoped to current assembly only
Assembly.GetExecutingAssembly()

// ✅ Safe: Attribute-based filtering  
.Where(t => t.GetCustomAttribute<McpServerToolTypeAttribute>() != null)

// ✅ Safe: JSON-serializable responses
return new { found = true, data = structuredObject };
```

## 🚀 Production Deployment

### Network Configuration
The server binds to `0.0.0.0:3001` for network access. Configure your firewall to allow port 3001:

```bash
# macOS/Linux - allow port 3001
sudo ufw allow 3001

# Find your server's IP for remote connections
hostname -I
```

### Docker Deployment
```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app
COPY bin/Release/net9.0/publish/ .
EXPOSE 3001
ENTRYPOINT ["dotnet", "remote-mcp.dll"]
```

### Environment Variables
```bash
# Production settings
export ASPNETCORE_ENVIRONMENT=Production
export ASPNETCORE_URLS=http://0.0.0.0:3001
```

## 🔧 Development

### Project Structure
```
remote-mcp/
├── Program.cs              # Server configuration and startup
├── Tools/                  # SOLID-compliant tool organization
│   ├── MathTools.cs       # Math operations (Add, Subtract, Multiply, Divide)
│   ├── UtilityTools.cs    # Utility functions (Echo, Time, Random)
│   ├── DataTools.cs       # Data manipulation (JSON, Case, Reverse)
│   └── ReflectionTools.cs # Introspection tools (5 reflection capabilities)
├── remote-mcp.csproj       # Project configuration
├── .mcp.json              # MCP client integration
├── CLAUDE.md              # Development guide
├── LICENSE                # MIT License
└── README.md              # This file
```

### SOLID Principles Compliance
- **Single Responsibility**: Each tool class has one focused purpose
- **Open/Closed**: Add new tool categories without modifying existing code
- **Clean Separation**: Server configuration separate from business logic
- **Maintainable**: Easy to locate, test, and extend specific tool categories

### Adding New Tools

1. **Create a new tool file** in the `Tools/` directory:
```csharp
// Tools/MyCustomTools.cs
using ModelContextProtocol.Server;
using System.ComponentModel;

[McpServerToolType]
public static class MyCustomTools
{
    [McpServerTool, Description("Description of what your tool does")]
    public static string MyTool([Description("Parameter description")] string input)
    {
        // Your logic here
        return $"Processed: {input}";
    }
}
```

2. **Automatic Discovery**: The tool will be automatically discovered via assembly scanning
3. **Verification**: Use the reflection tools (`ListAllTools()`) to verify registration
4. **Organization**: Follow the established patterns in existing tool files

### Debugging
- Health endpoint: `http://localhost:3001/health`
- Server info: `http://localhost:3001/info`  
- MCP Inspector: `npx @modelcontextprotocol/inspector@latest http://localhost:3001/`
- Reflection tools: Use `ListAllTools()` to verify your tools are registered

## 📖 Documentation

- **[CLAUDE.md](./CLAUDE.md)** - Development commands and architecture
- **[Medium Article Series](./Medium_Article.md)** - Step-by-step implementation guide

## 🔒 Security Considerations

### Safe Practices ✅
- Scoped reflection to executing assembly only
- Attribute-based filtering prevents unintended exposure
- No dynamic code execution
- Comprehensive input validation
- CORS configured for development (restrict for production)

### Production Security
- Add authentication middleware
- Implement rate limiting
- Use HTTPS in production
- Restrict CORS origins
- Configure firewall rules
- Monitor for abuse

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow the established MCP architectural patterns
- Add comprehensive descriptions to all tools
- Include proper error handling
- Update documentation for new features
- Test with reflection tools to verify integration

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [ModelContextProtocol.AspNetCore](https://www.nuget.org/packages/ModelContextProtocol.AspNetCore)
- Inspired by Anthropic's MCP specification

## 📊 Stats

- **16 Tools** across 4 categories
- **5 Reflection Tools** for self-documentation
- **Production Ready** with ASP.NET Core
- **Network Enabled** for distributed access
- **Comprehensive Testing** with health checks and MCP Inspector support