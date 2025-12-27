
#  OAuth JWT - Simple OAuth Providers

**Lightning-fast, zero-dependency OAuth providers for GitHub and Google with Express.js**

 **Why choose OAuth JWT?**
-  **Ultra Lightweight** - Zero external dependencies, only requires Express.js
-  **JWT Ready** - Built-in support for JWT token generation and custom authentication flows
-  **Direct Database Integration** - Easy database user management with custom success callbacks
- � **Flexible Custom Logic** - Full control over authentication flow with onSuccess/onError handlers
-  **Production Ready** - Secure OAuth 2.0 implementation following best practices
-  **Modern ES6** - Full ES6 module support with clean, readable code

##  Installation

**Step 1: Install the package**

```bash
npm install oauth-jwt
```


##  Import Statement

```javascript
import express from 'express';
import { GithubProvider, GoogleProvider } from 'oauth-jwt';
```

##  Quick Start Guide

### Step 1: Basic Provider Setup

```javascript
import express from 'express';
import { GithubProvider } from 'oauth-jwt';

const app = express();

# OAuth JWT

Lightning-fast GitHub & Google OAuth helpers for Express with zero extra dependencies.

## Install

```bash
npm install oauth-jwt
```

## Quick start

```js
import express from "express";
import dotenv from "dotenv";
import { GithubProvider, GoogleProvider } from "oauth-jwt";

dotenv.config();
const app = express();

GithubProvider(
	app,
	process.env.GITHUB_CLIENT_ID,
	process.env.GITHUB_CLIENT_SECRET,
	process.env.GITHUB_REDIRECT_URI
);

GoogleProvider(
	app,
	process.env.GOOGLE_CLIENT_ID,
	process.env.GOOGLE_CLIENT_SECRET,
	process.env.GOOGLE_REDIRECT_URI
);

app.listen(process.env.PORT || 3000, () => console.log("http://localhost:3000"));
```

## Required env (.env)

```env
# GitHub
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_REDIRECT_URI=http://localhost:3000/auth/github/callback

# Google
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback

# App
PORT=3000
JWT_SECRET=your-super-secret
FRONTEND_URL=http://localhost:3000
```

Use `process.env.*` as shown in the quick start.

## Routes exposed

| Provider | Login | Callback |
| --- | --- | --- |
| GitHub | `/auth/github` | `/auth/github/callback` |
| Google | `/auth/google` | `/auth/google/callback` |

## 🔧 Provider Parameters Guide

### GithubProvider Parameters:
```javascript
await GithubProvider(app, clientId, clientSecret, redirectUrl, onSuccess, onError)
```

### GoogleProvider Parameters:
```javascript
await GoogleProvider(app, clientId, clientSecret, redirectUrl, onSuccess, onError)
```

**Parameters:**
- `app` - Your Express.js application instance
- `clientId` - OAuth client ID from GitHub/Google
- `clientSecret` - OAuth client secret from GitHub/Google  
- `redirectUrl` - Callback URL (must match OAuth app settings)
- `onSuccess` - *(Optional)* Custom success handler function
- `onError` - *(Optional)* Custom error handler function

## 📊 What Each Provider Returns

### GitHub Provider Returns:
```javascript
{
  userData: {
    id: 12345678,
    login: "username",
    name: "User Name", 
    avatar_url: "https://avatars.githubusercontent.com/u/12345678",
    bio: "Developer bio",
    public_repos: 25,
    followers: 100,
    following: 50
    // ... full GitHub user object
  },
  email: "user@example.com",        // Primary email
  accessToken: "gho_xxxxxxxxxxxx",  // GitHub access token
  provider: "github"
}
```

### Google Provider Returns:
```javascript
{
  userData: {
    id: "1234567890",
    email: "user@gmail.com",
    verified_email: true,
    name: "User Name",
    given_name: "User",
    family_name: "Name", 
    picture: "https://lh3.googleusercontent.com/a/xxxxx",
    locale: "en"
    // ... full Google user object
  },
  email: "user@gmail.com",          // User email
  accessToken: "ya29.xxxxxxxxxxxx", // Google access token  
  provider: "google"
}

## What you get on callback

```js
// GitHub
{
	userData: { id, login, name, avatar_url, ... },
	email: "primary@example.com",
	accessToken: "gho_xxx",
	provider: "github"
}

// Google
{
	userData: { id, email, name, given_name, family_name, picture, ... },
	email: "user@gmail.com",
	accessToken: "ya29.xxx",
	provider: "google"
}
```

## Get OAuth creds fast

**GitHub**
1) https://github.com/settings/developers → New OAuth App.  
2) Callback: `http://localhost:3000/auth/github/callback`.  
3) Copy Client ID/Secret → put in `.env`.

**Google**
1) https://console.cloud.google.com → APIs & Services → Credentials → OAuth client ID.  
2) Authorized redirect URI: `http://localhost:3000/auth/google/callback`.  
3) Copy Client ID/Secret → put in `.env`.

## Production tips

- Use HTTPS and strong `JWT_SECRET`.
- Match redirect URIs with your OAuth app settings.
- Keep secrets in `.env`, not git.

## Support

- Issues: https://github.com/RajanDhamala/oauth-jwt/issues
- Discussions: https://github.com/RajanDhamala/oauth-jwt/discussions
- Email: lucarioqh5@gmail.com

## License

MIT © 2024 Rajan Dhamala
```



