# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Build and Run
- `dotnet restore` - Restore NuGet packages
- `dotnet build` - Build the project
- `dotnet run` - Run the server (starts on http://0.0.0.0:3001)

### Project Setup (for new instances)
```bash
dotnet new web --force
# Replace Program.cs and .csproj with provided files
dotnet restore
dotnet build
dotnet run
```

### Testing Endpoints
- Server info: `http://localhost:3001/info`
- Health check: `http://localhost:3001/health`
- MCP endpoint: `http://localhost:3001/` (root path)

### MCP Inspector Testing
```bash
npx @modelcontextprotocol/inspector@latest
# Connect to: http://localhost:3001/
```

## Architecture

This is a **Remote Model Context Protocol (MCP) Server** built with C# and ASP.NET Core using the official `ModelContextProtocol.AspNetCore` SDK.

### Key Components

**Transport Layer:**
- Uses Streamable HTTP transport (modern MCP standard)
- CORS enabled for browser clients
- Endpoints: `/mcp` (MCP protocol), `/health`, `/` (server info)

**Tool Discovery System:**
- Auto-discovery via `[McpServerToolType]` and `[McpServerTool]` attributes
- Tools organized in static classes by category
- All tools have typed parameters with descriptions

**Tool Categories:**
- `MathTools`: Basic arithmetic operations (add, subtract, multiply, divide)
- `UtilityTools`: General utilities (echo, time, random numbers)
- `DataTools`: Text/data manipulation (JSON formatting, case conversion, text reversal)
- `ReflectionTools`: Runtime introspection (tool discovery, metadata, search)

**SOLID Architecture:**
- Tools organized in separate files under `Tools/` directory
- Single Responsibility: Each tool class has one focused purpose
- Clean separation between server configuration and business logic

### Configuration
- Server runs on port 3001 by default (binds to 0.0.0.0 for network access)
- Logging configured to stderr (MCP convention)
- Dependency injection setup for MCP services
- All tools automatically registered via assembly scanning
- SOLID-compliant file organization in Tools/ directory

### Client Integration
Compatible with:
- Claude Code (via mcp-remote proxy)
- Cursor IDE
- VS Code with GitHub Copilot 
- MCP Inspector for testing
- Any MCP client supporting Streamable HTTP transport

### Adding New Tools
1. Create new tool file in `Tools/` directory
2. Use `[McpServerToolType]` attribute on static class
3. Use `[McpServerTool]` and `[Description]` attributes on methods
4. Follow existing tool file patterns
5. Tools are automatically discovered via assembly scanning