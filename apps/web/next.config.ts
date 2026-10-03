import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@cyberpilot/database", "@cyberpilot/integrations", "@cyberpilot/risk-engine"],
};

export default nextConfig;
