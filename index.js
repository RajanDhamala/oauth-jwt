const GithubProvider = async (app, clientId, clientSecret, redirectUrl, onSuccess, onError) => {
  app.get("/auth/github", async (req, res) => {

    const redirectUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUrl}&scope=user:email`;
    res.redirect(redirectUrl);
  });

  app.get("/auth/github/callback", async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send("No code provided");

    try {
      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept": "application/json"
        },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUrl,
        }),
      });

      const tokenData = await tokenRes.json();
      const accessToken = tokenData.access_token;

      if (!accessToken) throw new Error("No GitHub access token");

      const [userRes, emailRes] = await Promise.all([
        fetch("https://api.github.com/user", {
          headers: { Authorization: `token ${accessToken}` }
        }),
        fetch("https://api.github.com/user/emails", {
          headers: { Authorization: `token ${accessToken}` }
        }),
      ]);

      const userData = await userRes.json();
      const emails = await emailRes.json();
      const primaryEmail = emails.find(e => e.primary)?.email || userData.email;

      const userInfo = {
        userData,
        email: primaryEmail,
        accessToken,
        provider: 'github'
      };

      if (onSuccess) {
        await onSuccess(req, res, userInfo);
      } else {
        res.json(userInfo);
      }

    } catch (err) {
      console.log(err);
      if (onError) {
        await onError(req, res, err);
      } else {
        res.status(500).json({ error: "GitHub OAuth failed" });
      }
    }
  });
};

const GoogleProvider = async (app, clientId, clientSecret, redirectUrl, onSuccess, onError) => {
  app.get("/auth/google", async (req, res) => {
    const scope = encodeURIComponent("profile email");
    const redirectUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUrl}&response_type=code&scope=${scope}&access_type=offline&prompt=consent`;
    res.redirect(redirectUrl);
  });

  app.get("/auth/google/callback", async (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send("No code provided");

    try {
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUrl,
          grant_type: "authorization_code",
        }),
      });

      const tokenData = await tokenRes.json();
      const accessToken = tokenData.access_token;

      if (!accessToken) throw new Error("No tokens from Google");

      const userRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const userData = await userRes.json();

      const userInfo = {
        userData,
        email: userData.email,
        accessToken,
        provider: 'google'
      };

      if (onSuccess) {
        await onSuccess(req, res, userInfo);
      } else {
        res.json(userInfo);
      }

    } catch (err) {
      console.error("Google OAuth Error:", err);
      if (onError) {
        await onError(req, res, err);
      } else {
        res.status(500).json({ error: "Google OAuth failed" });
      }
    }
  });
};

export { GithubProvider, GoogleProvider };
