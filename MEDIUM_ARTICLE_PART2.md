# How I Accidentally Solved OAuth for AI Agents (And Why It Almost Broke Me)
## Part 2: The Enterprise Authentication Nightmare That Claude Sonnet Couldn't Solve

*This is Part 2 of my journey building MCP servers. [Part 1](https://medium.com/@stephen.k.ellis/build-a-remote-mcp-server-that-actually-works-right-now-fcbf41a31d95) covered the basics. This part covers what happens when you need enterprise authentication. Spoiler: It gets ugly.*

---

Remember when I said building an MCP server was straightforward? I lied. Well, not intentionally. The basic server *is* straightforward. But the moment you need enterprise authentication — specifically Microsoft Azure AD — you enter a special circle of hell that even Dante couldn't have imagined.

Let me tell you a story about how I spent 48 hours discovering that the Model Context Protocol has a fundamental design flaw, how Claude Sonnet repeatedly failed to solve it, and how Claude Opus finally cracked it by essentially breaking every rule in the OAuth playbook.

## The "Simple" Requirement

My client's request seemed reasonable enough:

> "We need the MCP server to authenticate users through our Microsoft Azure AD. Standard enterprise stuff."

Standard enterprise stuff. Famous last words.

Here's what I thought would happen:
1. User connects to MCP server
2. Server redirects to Microsoft login
3. User authenticates
4. Server gets token
5. Done

Here's what actually happened:
1. User connects to MCP server
2. Server redirects to Microsoft login
3. User authenticates
4. Server gets token
5. MCP client has no idea what's happening
6. Everything explodes
7. Infinite redirect loop
8. Contemplation of career change

## The Fundamental Problem Nobody Talks About

Here's the dirty secret about MCP that nobody mentions: **MCP clients are not web browsers**.

I know, revolutionary insight, right? But here's why it matters:

OAuth was designed for web browsers. It assumes you can:
- Store cookies
- Maintain sessions
- Handle redirects
- Keep state between requests

MCP clients (like `mcp-remote`) can do exactly none of these things. Each request is completely independent. No cookies. No sessions. No state.

It's like trying to have a conversation with someone who has amnesia that resets every 10 seconds. 

## My Descent Into Madness

### Hour 1-4: "This Should Be Easy"

Started with the obvious approach. Just implement OAuth:

```csharp
services.AddAuthentication()
    .AddMicrosoftIdentityWebApp(Configuration.GetSection("AzureAd"));
```

Result: Infinite redirect loop. The MCP client would hit the server, get redirected to login, and... nothing. Just kept spinning.

### Hour 5-8: "Maybe It's the Tokens"

Okay, maybe I need to handle the tokens differently:

```csharp
public async Task<IActionResult> Token(TokenRequest request)
{
    // Just pass Microsoft's token to the client
    var msToken = await GetMicrosoftToken(request.Code);
    return Json(new { access_token = msToken });
}
```

Result: `IDX10511: Signature validation failed`. Microsoft's tokens are signed by Microsoft, not by us. Our server couldn't validate them because they weren't meant for us.

### Hour 9-16: "Let's Try Sessions"

Fine, I'll use sessions like a normal web app:

```csharp
services.AddSession(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});
```

Result: MCP clients don't support cookies. Each request comes in like it's the first time we've ever met.

### Hour 17-24: "Time to Get Creative"

This is where things got weird. I started trying increasingly desperate solutions:

- Custom authentication handlers
- Token caching mechanisms  
- Hybrid session/token models
- Something involving JWT refresh tokens and prayer

None of it worked.

### Hour 25-32: "Maybe I'm the Problem"

At this point, I switched from Claude Sonnet to Claude Opus. I figured if I was going to fail, I might as well fail with the best.

And that's when Opus said something that changed everything:

> "What if we stop trying to make MCP clients act like browsers and instead make our server act as both an OAuth client AND an OAuth server?"

## The Solution That Shouldn't Work (But Does)

Here's the architecture that finally worked:

```
                    ┌─────────────────┐
                    │   Microsoft     │
                    │   Azure AD      │
                    └────────┬────────┘
                             │
                    OAuth Client Role
                             │
                    ┌────────▼────────┐
                    │   Our Server    │
                    │ (Dual Identity) │
                    └────────┬────────┘
                             │
                 OAuth Server Role
                             │
                    ┌────────▼────────┐
                    │   MCP Client    │
                    └─────────────────┘
```

Our server has a split personality:
1. **To Microsoft**: We're an OAuth client asking for authentication
2. **To MCP clients**: We're an OAuth server issuing our own tokens

The key innovation? **Static memory cache**:

```csharp
private static readonly Dictionary<string, OAuthFlowState> _stateCache = new();
```

Yes, you read that right. Static. Memory. Cache. 

In 2025.

For enterprise authentication.

I can hear the architects screaming.

But here's the thing: **It's the only thing that works with stateless clients**.

## The Code That Made It Work

Here's the magic that bridges the two worlds:

```csharp
public async Task<IActionResult> HandleTokenRequest(TokenRequest request)
{
    // Step 1: We stored Microsoft's code when they called us back
    var state = RetrieveStateFromStaticCache(request.Code);
    
    // Step 2: Exchange Microsoft's code for their token
    var msToken = await ExchangeWithMicrosoft(state.MicrosoftCode);
    
    // Step 3: Create OUR OWN token with the user's info
    var ourToken = CreateOurJwtToken(new
    {
        user = msToken.UserPrincipalName,
        name = msToken.DisplayName,
        iss = "http://localhost:3001",  // US, not Microsoft!
        aud = "mcp-server"
    });
    
    // Step 4: Give our token to the MCP client
    return Json(new 
    { 
        access_token = ourToken,
        token_type = "Bearer",
        expires_in = 28800
    });
}
```

## Why This Is Actually Insane

Let me count the ways this solution breaks conventional wisdom:

1. **Static memory cache in a web server** - This doesn't scale horizontally. One server instance only.

2. **Dual authorization pattern** - We're simultaneously a client and a server in the same OAuth flow.

3. **No refresh tokens** - Stateless clients can't use them anyway.

4. **Manual PKCE management** - We maintain TWO sets of PKCE challenges (theirs and ours).

5. **Token inception** - We get a token to make a token.

## But Wait, There's More: WebAuthn

Because apparently I'm a masochist, I also added biometric authentication:

```csharp
"WebAuthn": {
    "Enabled": true,
    "ServerDomain": "localhost",
    "RequireUserVerification": true
}
```

As far as I can tell, this is the first MCP server with WebAuthn support. Why? Because I could. And because somewhere, someone will need their MCP server to support Face ID.

## The Lessons That Hurt

### Lesson 1: Specifications Lie

The MCP specification says "just use OAuth." It doesn't mention that OAuth fundamentally doesn't work with stateless clients. This is like saying "just use a hammer" when you're trying to perform surgery.

### Lesson 2: AI Models Have Limits

Claude Sonnet couldn't solve this. It kept suggesting standard OAuth patterns that simply don't work in this context. It took Opus — and a lot of systematic debugging — to think outside the conventional patterns.

The difference? Sonnet tried to make the problem fit existing solutions. Opus realized we needed a new solution for a new problem.

### Lesson 3: Sometimes Bad Solutions Are Good Solutions

Static memory cache is "bad" architecture. It doesn't scale. It's not distributed. It's not cloud-native.

It's also the only thing that works.

Sometimes, the "right" solution is the one that actually solves the problem, even if it makes architects cry.

## What This Means for the MCP Ecosystem

We might be first on several fronts:
- First production MCP server with Azure AD authentication
- First with OAuth 2.1 and RFC 9068 compliance
- First with WebAuthn support
- First to document why standard OAuth doesn't work with MCP

But being first also means hitting every single landmine so others don't have to.

## The Working Config (So You Don't Suffer Like I Did)

```json
{
  "Authentication": {
    "Mode": "AuthorizationServer",
    "OAuth": {
      "Issuer": "http://localhost:3001"  // YOU, not Microsoft!
    },
    "ExternalIdP": {
      "Provider": "AzureAD",
      "ClientSecret": "YOUR_SECRET_HERE",
      "AzureAD": {
        "TenantId": "your-tenant-id",
        "ClientId": "your-client-id",
        "Authority": "https://login.microsoftonline.com/your-tenant-id"
      }
    }
  }
}
```

## The Emotional Rollercoaster

Let me be real with you. This problem nearly broke me. 

There's a special kind of frustration that comes from knowing something should work — the docs say it works, the examples show it working — but it just... doesn't. 

You start questioning everything. Maybe I'm reading the docs wrong. Maybe I don't understand OAuth. Maybe I should have become a carpenter like my dad suggested.

Then, at 3 AM, when you've tried everything reasonable and most things unreasonable, you implement something so stupid it couldn't possibly work.

And it does.

And you're not sure whether to laugh or cry.

So you do both.

## What's Next?

The static memory cache needs to die. It works for proof of concept, but production needs:
- Redis for distributed caching
- Proper session affinity in load balancers
- Maybe a rethink of the entire MCP authentication model

But for now, it works. Enterprise users can authenticate with Azure AD. MCP clients can connect. Tools can be called.

Mission accomplished.

Sort of.

## The Call to Action

If you're building MCP servers, learn from my pain:

1. **MCP clients are not browsers** - Design accordingly
2. **Static solutions might be necessary** - At least initially
3. **Test with real MCP clients** - Not curl, not Postman, actual MCP clients
4. **Document everything** - Others will hit the same walls

And if you're on the MCP specification team: Please, PLEASE add a section about stateless client authentication. Save others from this journey.

## Final Thoughts

They say necessity is the mother of invention. In this case, necessity was more like the drunk uncle who shows up at 2 AM demanding you solve impossible problems.

But we did it. We have a C# MCP server with enterprise Azure AD authentication. It might not be pretty, but it works.

And sometimes, that's enough.

Sometimes, that's everything.

---

*The code is on [GitHub](https://github.com/scampcat/remote-mcp). Use it. Learn from it. Improve it. Just don't judge the static memory cache too harshly.*

*Part 3 will cover scaling this to production. If I survive that long.*

*Follow me for more stories about solving problems that shouldn't exist with solutions that shouldn't work.*

---

**Technical Details for the Curious:**
- Runtime: .NET 9.0 with ASP.NET Core
- OAuth: 2.1 with PKCE mandatory
- Tokens: JWT with RFC 9068 profile
- Session: Static memory (I know, I know)
- Sanity: Questionable

**Shoutouts:**
- Claude Opus for thinking outside the box
- David J. Agans for debugging methodology
- Coffee for existing
- My rubber duck for listening

**If this helped you, please clap. If it didn't, I understand. This solution hurts me too.**