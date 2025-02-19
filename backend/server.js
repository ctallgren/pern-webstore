import express from "express";
import helmet, { contentSecurityPolicy } from "helmet";
import morgan from "morgan";
import cors from "cors";
import dotenv from "dotenv";
import { sql } from "./config/db.js";
import productRoutes from "./routes/productRoutes.js";
import { aj } from "./lib/arcjet.js";
import path from "path";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const __dirname = path.resolve();

app.use(express.json());
app.use(
  helmet({
    contentSecurityPolicy: false,
  })
); // Helmet is a security middleware that helps you ptotect your app by setting various HTTP headers.
// It can help prevent attacks such as cross-site scripting (XSS), clickjacking, and other common web vulnerabilities.
app.use(cors()); // CORS is a mechanism that allows resources on a web page to be requested from another domain outside the domain from which the first resource was served.
app.use(morgan("dev")); // Morgan is a logging middleware for Express. It logs incoming requests to the console in a readable format.

// Apply Arcjet rate-limit to all routes
app.use(async (req, res, next) => {
  try {
    const decision = await aj.protect(req, {
      requested: 1, // Specifies that each request consumes 1 token
    });

    if (decision.isDenied()) {
      if (decision.reason.isRateLimit()) {
        res.status(429).json({
          error: "Too many requests",
        });
      } else if (decision.reason.isBot()) {
        res.status(403).json({
          error: "Bots are not allowed",
        });
      } else {
        res.status(403).json({
          error: "Access denied",
        });
      }
      return;
    }

    // Check for spoofed bots
    if (
      decision.results.some(
        (result) => result.reason.isBot() && result.reason.isSpoofed()
      )
    ) {
      res.status(403).json({
        error: "Spoofed bot detected",
      });
      return;
    }

    next();
  } catch (error) {
    console.log("Arcjet error: ", error);
    next(error);
  }
});

app.use("/api/products", productRoutes);

if (process.env.NODE_ENV === "production") {
  // Serve our react app
  app.use(express.static(path.join(__dirname, "/frontend/dist")));

  app.get("*", (req, res) => {
    res.sendFile(path.resolve(__dirname, "frontend", "dist", "index.html"));
  });
}

async function initDB() {
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        image VARCHAR(255) NOT NULL,
        price DECIMAL(10, 2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;

    console.log("Database initialized successfully");
  } catch (error) {
    console.log("Error initializing database: ", error);
  }
}

initDB().then(() => {
  app.listen(PORT, () => {
    console.log("Server is running on port " + PORT);
  });
});

// app.listen(PORT, () => {
//   console.log("Server is running on port " + PORT);
// });
