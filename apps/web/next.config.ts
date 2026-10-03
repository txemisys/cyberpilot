import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@cyberpilot/database", "@cyberpilot/integrations"],
};

export default nextConfig;
