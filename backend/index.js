const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());

const users = [
  {
    id: "1",
    username: "john",
    password: "123",
    isAdmin: true,
  },
  {
    id: "2",
    username: "david",
    password: "123",
    isAdmin: false,
  },
  {
    id: "3",
    username: "anna",
    password: "123",
    isAdmin: false,
  },
  {
    id: "4",
    username: "amy",
    password: "123",
    isAdmin: false,
  },
];

let refreshTokens = [];
app.post("/api/refresh", (req, res) => {
  // Take the refresh token from user
  const refreshToken = req.body.token;

  // Send error if there is no token or it's invalid
  if (!refreshToken) {
    return res.status(401).json("You are not authenticated!");
  }
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json("Refresh token is not valid!");
  }
  jwt.verify(refreshToken, "RefreshTranDucAnh", (err, user) => {
    err && console.log(err);
    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);

    res
      .status(200)
      .json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  });

  // if everything is ok, create new access token, refresh token and send to user
});

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "TranDucAnh", {
    expiresIn: "30m",
  });
};
const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "RefreshTranDucAnh", {
    expiresIn: "30d",
  });
};

const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, "TranDucAnh", (err, user) => {
      if (err) {
        return res.status(401).json("Token is not valid!");
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json("You are not authenticated!");
  }
};

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (user) => user.username === username && user.password === password
  );
  if (user) {
    // Generate an access token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);

    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    res.status(404).json("Username or password incorrect");
  }
});

app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== refreshToken);
  res.status(200).json("You logged out successfully!");
});

app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("User has been deleted!");
  } else {
    res.status(403).json("You are not allow to delete this user!");
  }
});

app.listen(5000, () => {
  console.log("Backend server is running");
});
