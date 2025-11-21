# 🚀 OAuth JWT - Simple OAuth Providers

**Lightning-fast, zero-dependency OAuth providers for GitHub and Google with Express.js**

🔥 **Why choose OAuth JWT?**
- ⚡ **Ultra Lightweight** - Zero external dependencies, only requires Express.js
- �️ **JWT Ready** - Built-in support for JWT token generation and custom authentication flows
- 🎯 **Direct Database Integration** - Easy database user management with custom success callbacks
- � **Flexible Custom Logic** - Full control over authentication flow with onSuccess/onError handlers
- � **Production Ready** - Secure OAuth 2.0 implementation following best practices
- 📦 **Modern ES6** - Full ES6 module support with clean, readable code

## 📦 Installation

**Step 1: Install the package**

```bash
npm install oauth-jwt
```


## 📚 Import Statement

```javascript
import express from 'express';
import { GithubProvider, GoogleProvider } from 'oauth-jwt';
```

## 🚀 Quick Start Guide

### Step 1: Basic GitHub Provider Setup

```javascript
import express from 'express';
import { GithubProvider } from 'oauth-jwt';

const app = express();

// Basic GitHub OAuth - Returns user data as JSON
await GithubProvider(
  app,                                    // Express app instance
  'your_github_client_id',               // GitHub Client ID
  'your_github_client_secret',           // GitHub Client Secret
  'http://localhost:3000/auth/github/callback'  // Callback URL
);

app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
});
```

### Step 2: Basic Google Provider Setup

```javascript
import express from 'express';
import { GoogleProvider } from 'oauth-jwt';

const app = express();

// Basic Google OAuth - Returns user data as JSON
await GoogleProvider(
  app,                                    // Express app instance
  'your_google_client_id',               // Google Client ID
  'your_google_client_secret',           // Google Client Secret
  'http://localhost:3000/auth/google/callback'  // Callback URL
);

app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
});
```

### Step 3: Complete Setup with Both Providers

```javascript
import express from 'express';
import { GithubProvider, GoogleProvider } from 'oauth-jwt';

const app = express();

// Setup both providers
await GithubProvider(
  app,
  'your_github_client_id',
  'your_github_client_secret', 
  'http://localhost:3000/auth/github/callback'
);

await GoogleProvider(
  app,
  'your_google_client_id',
  'your_google_client_secret',
  'http://localhost:3000/auth/google/callback'
);

app.listen(3000, () => {
  console.log('🚀 Server running on http://localhost:3000');
});
```

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
```

## 🔐 Environment Variables Setup (Recommended)


**Step 1: Create `.env` file in your project root**
```env
# GitHub OAuth Credentials
GITHUB_CLIENT_ID=your_github_client_id_here
GITHUB_CLIENT_SECRET=your_github_client_secret_here
GITHUB_REDIRECT_URI=http://localhost:3000/auth/github/callback

# Google OAuth Credentials  
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback

# Server Configuration
PORT=3000
JWT_SECRET=your_super_secret_jwt_key_here
DATABASE_URL=mongodb://localhost:27017/your_database
```

**Step 2:  Boilerplate**

```javascript

// GitHub OAuth with Environment Variables
await GithubProvider(
  app,
  process.env.GITHUB_CLIENT_ID,
  process.env.GITHUB_CLIENT_SECRET,
  process.env.GITHUB_REDIRECT_URI
);

// Google OAuth with Environment Variables
await GoogleProvider(
  app,
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);
```

## 🎯 Available OAuth Routes

After setup, these routes will be automatically available:

| Provider | Login URL | Callback URL | Description |
|----------|-----------|--------------|-------------|
| GitHub   | `/auth/github` | `/auth/github/callback` | Initiates GitHub OAuth flow |
| Google   | `/auth/google` | `/auth/google/callback` | Initiates Google OAuth flow |

## 🔧 Custom Integration Examples

### 🎫 JWT Token Integration (Recommended)

```javascript
import express from 'express';
import jwt from 'jsonwebtoken';
import { GithubProvider, GoogleProvider } from 'oauth-jwt';

const app = express();

// Custom success handler for JWT
const handleOAuthSuccess = async (req, res, userInfo) => {
  // Create JWT token with user data
};

// Custom error handler
const handleOAuthError = async (req, res, error) => {
  console.error('OAuth Error:', error);
  res.redirect('http://localhost:3000/login?error=oauth_failed');
};

// Setup providers with custom handlers
```

### 🗄️ Direct Database Integration

```javascript
import { GithubProvider, GoogleProvider } from 'oauth-jwt';

// Custom success handler with database integration
const handleDatabaseAuth = async (req, res, userInfo) => {
  try {
    const { userData, email, provider } = userInfo;
    // Find existing user or create new one
    
  } catch (error) {
    console.error('Database Auth Error:', error);
    res.redirect('http://localhost:3000/login?error=database_error');
  }
};

// Setup providers with database integration
await GithubProvider(
  app,
  process.env.GITHUB_CLIENT_ID,
  process.env.GITHUB_CLIENT_SECRET,
  process.env.GITHUB_REDIRECT_URI,
  handleDatabaseAuth
);

await GoogleProvider(
  app,
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI,
  handleDatabaseAuth
);

```

### 🎨 Custom Logic Integration

```javascript
import express from 'express';
import { GithubProvider, GoogleProvider } from 'oauth-jwt';

const app = express();

// Advanced custom success handler
const customAuthLogic = async (req, res, userInfo) => {
  const { userData, email, provider, accessToken } = userInfo;
    
    // Custom user processing

    // Store in session/database/cache as needed
    req.session = { user: processedUser };
  } catch (error) {
    console.error('Custom Auth Error:', error);
    res.status(400).json({ 
      error: 'Authentication failed', 
      message: error.message 
    });
  }
};

// Setup with custom logic
await GithubProvider(
  app,
  process.env.GITHUB_CLIENT_ID,
  process.env.GITHUB_CLIENT_SECRET,
  process.env.GITHUB_REDIRECT_URI,
  customAuthLogic
);

```

## 🛠️ Frontend Integration Examples


```

### ⚛️ React Component (Copy-Paste Ready)

```jsx
import React, { useState } from 'react';

const OAuthLogin = () => {
  const [loading, setLoading] = useState(null);

  const handleOAuthLogin = (provider) => {
    setLoading(provider);
    // Redirect to OAuth provider
    window.location.href = `/auth/${provider}`;
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-600 to-blue-600 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-md">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-800 mb-2">🚀 Welcome Back!</h1>
          <p className="text-gray-600">Sign in to continue to your account</p>
        </div>

        <div className="space-y-4">
          <button 
            onClick={() => handleOAuthLogin('github')}
            disabled={loading === 'github'}
            className="w-full bg-gray-900 hover:bg-gray-800 text-white font-semibold py-4 px-6 rounded-lg transition-all duration-200 flex items-center justify-center space-x-3 disabled:opacity-70"
          >
            {loading === 'github' ? (
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
            ) : (
              <>
                <span className="text-xl">🐙</span>
                <span>Continue with GitHub</span>
              </>
            )}
          </button>

          <button 
            onClick={() => handleOAuthLogin('google')}
            disabled={loading === 'google'}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-4 px-6 rounded-lg transition-all duration-200 flex items-center justify-center space-x-3 disabled:opacity-70"
          >
            {loading === 'google' ? (
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
            ) : (
              <>
                <span className="text-xl">🔍</span>
                <span>Continue with Google</span>
              </>
            )}
          </button>
        </div>

        <div className="mt-8 text-center">
          <p className="text-sm text-gray-500">
            Secure authentication powered by{' '}
            <span className="font-semibold text-blue-600">oauth-jwt</span>
          </p>
        </div>
      </div>
    </div>
  );
};

export default OAuthLogin;
```


## ⚙️ OAuth Application Setup Guide

### 🐙 GitHub OAuth Setup

1. **Go to GitHub Developer Settings**
   - Visit: [https://github.com/settings/developers](https://github.com/settings/developers)
   
2. **Create New OAuth App**
   - Click **"New OAuth App"**
   
3. **Fill Application Details**
   ```
   Application name: Your App Name
   Homepage URL: http://localhost:3000
   Authorization callback URL: http://localhost:3000/auth/github/callback
   ```
   
4. **Get Credentials**
   - Copy **Client ID** and **Client Secret**
   - Add them to your `.env` file

### 🔍 Google OAuth Setup

1. **Go to Google Cloud Console**
   - Visit: [https://console.cloud.google.com/](https://console.cloud.google.com/)
   
2. **Create/Select Project**
   - Create new project or select existing one
   
3. **Enable APIs**
   - Go to **"APIs & Services"** → **"Library"**
   - Search and enable **"Google+ API"** or **"Google Identity"**
   
4. **Create OAuth Credentials**
   - Go to **"Credentials"** → **"Create Credentials"** → **"OAuth 2.0 Client IDs"**
   
5. **Configure Consent Screen**
   - Set up OAuth consent screen with your app details
   
6. **Add Redirect URI**
   ```
   Authorized redirect URIs: http://localhost:3000/auth/google/callback
   ```
   
7. **Get Credentials**
   - Copy **Client ID** and **Client Secret**

```

**Required `.env` file:**

```env
# OAuth Credentials (Replace with your actual values)
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_REDIRECT_URI=http://localhost:3000/auth/github/callback

GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production

# Server Configuration
PORT=3000
FRONTEND_URL=http://localhost:3000

# Optional: Database (if using database integration)
DATABASE_URL=mongodb://localhost:27017/oauth_app
```

**Package.json dependencies:**

```json
{
  "dependencies": {
    "express": "^4.18.2",
    "dotenv": "^16.3.1",
    "jsonwebtoken": "^9.0.2",
    "oauth-jwt": "^1.0.0"
  }
}
```

## 🚨 Important Production Notes

### 🔐 Security Checklist
- ✅ **Never commit secrets** to version control (use `.env` files)
- ✅ **Use HTTPS** in production (required by OAuth providers)
- ✅ **Update redirect URIs** for production domains
- ✅ **Use strong JWT secrets** (minimum 32 characters)
- ✅ **Implement rate limiting** for OAuth endpoints
- ✅ **Validate JWT tokens** on protected routes

### 🌐 Production Deployment
```bash
# Production environment variables
NODE_ENV=production
JWT_SECRET=your-production-jwt-secret-min-32-chars
GITHUB_REDIRECT_URI=https://yourdomain.com/auth/github/callback
GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/google/callback
```

## 🎯 Why Choose OAuth JWT?

| Feature | OAuth JWT | Passport.js | Auth0 | Firebase Auth |
|---------|-----------|-------------|-------|---------------|
| **Bundle Size** | 🟢 Ultra Light | 🟡 Heavy | 🟡 Heavy | 🟡 Heavy |
| **Dependencies** | 🟢 Zero deps | 🔴 Many deps | 🔴 Many deps | 🔴 Many deps |
| **Setup Time** | 🟢 < 5 minutes | 🟡 15-30 min | 🟡 15-30 min | 🟡 15-30 min |
| **Custom Logic** | 🟢 Full control | 🟡 Limited | 🔴 Very limited | 🔴 Very limited |
| **JWT Built-in** | 🟢 Yes | 🔴 Manual setup | 🟢 Yes | 🟢 Yes |
| **Database Flow** | 🟢 Direct control | 🟡 Complex setup | 🔴 Vendor lock | 🔴 Vendor lock |
| **Cost** | 🟢 Free forever | 🟢 Free | 🔴 Paid tiers | 🟡 Free tier |

## 📞 Support & Resources

### 🐛 Getting Help
- **Issues**: [GitHub Issues](https://github.com/RajanDhamala/oauth-jwt/issues)
- **Email**: lucarioqh5@gmail.com
- **Discussions**: [GitHub Discussions](https://github.com/RajanDhamala/oauth-jwt/discussions)

### 📚 Additional Resources
- [JWT.io](https://jwt.io) - JWT token debugger
- [OAuth 2.0 Spec](https://oauth.net/2/) - OAuth specification
- [Express.js Docs](https://expressjs.com/) - Express.js documentation

### 🤝 Contributing
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

### ⭐ Show Your Support
If this package helped you, please:
- ⭐ Star the [GitHub repository](https://github.com/RajanDhamala/oauth-jwt)
- 📦 Leave an NPM review
- 🐦 Share with other developers

## 📄 License

**MIT License** - Use freely in personal and commercial projects!

```
Copyright (c) 2024 Rajan Dhamala

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software.
```

---

<div align="center">

**🚀 Made with ❤️ for developers who want simple, powerful OAuth integration**

*oauth-jwt - Zero dependency, full control, lightning fast* ⚡

</div>

