import http from "http";
import net from "net";

const IP_API_HOST = "ip-api.com";

/* =========================
   IP-API REQUEST
========================= */

function fetchIPAPI(ip) {
  return new Promise((resolve, reject) => {
    const url =
      `http://${IP_API_HOST}/json/${encodeURIComponent(ip)}` +
      `?fields=status,message,query,isp,org,as,asname,proxy,hosting`;

    http.get(
      url,
      {
        headers: {
          "User-Agent": "IP-Detector/1.0",
          "Accept": "application/json"
        }
      },
      res => {
        let body = "";

        res.on("data", chunk => {
          body += chunk;
        });

        res.on("end", () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`HTTP ${res.statusCode}`));
            return;
          }

          try {
            const data = JSON.parse(body);

            if (data.status !== "success") {
              reject(
                new Error(data.message || "IP-API lookup failed")
              );
              return;
            }

            resolve(data);
          } catch {
            reject(new Error("Invalid JSON response"));
          }
        });
      }
    ).on("error", reject);
  });
}

/* =========================
   STRING DETECTION
========================= */

function containsCloudflare(value) {
  if (!value || typeof value !== "string") {
    return false;
  }

  return value.toLowerCase().includes("cloudflare");
}

/* =========================
   CLOUDFLARE DETECTION
========================= */

function detectCloudflare(data) {
  if (!data) {
    return false;
  }

  return (
    containsCloudflare(data.isp) ||
    containsCloudflare(data.org) ||
    containsCloudflare(data.as) ||
    containsCloudflare(data.asname)
  );
}

/* =========================
   MAIN FUNCTION
========================= */

export async function isAIAgent(ip) {
  if (!net.isIP(ip)) {
    console.log("Invalid IP:", ip);
    return false;
  }

  try {
    const data = await fetchIPAPI(ip);

    console.log("IP-API:", {
      ip: data.query,
      isp: data.isp,
      org: data.org,
      as: data.as,
      asname: data.asname,
      proxy: data.proxy,
      hosting: data.hosting
    });

    return detectCloudflare(data);
  } catch (error) {
    console.error(
      `Failed to lookup ${ip}:`,
      error.message
    );

    return false;
  }
}

export default isAIAgent;