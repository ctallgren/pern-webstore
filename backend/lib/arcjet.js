import arcjet, { tokenBucket, shield, detectBot } from "@arcjet/node";

import "dotenv/config";

// Init Arcjet
export const aj = arcjet({
  key: process.env.ARCNET_KEY,
  characteristics: ["ip.src"],
  rules: [
    // Shield protects your app from common attacks, e.g. SQL injection and XSS and CSRF attacks.
    shield({ mode: "LIVE" }),
    detectBot({
      mode: "LIVE",
      allow: [
        // Block all bots except search engines
        "CATEGORY:SEARCH_ENGINE",
        // See the full list at https://arcjet.com/bot-list
      ],
    }),
    // Rate limiting prevents abuse by throttling requests to a certain rate per IP address
    tokenBucket({
      mode: "LIVE",
      refillRate: 30,
      interval: 5,
      capacity: 20,
    }),
  ],
});
