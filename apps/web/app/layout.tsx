import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CyberPilot",
  description: "Cybersecurity autopilot for small and medium-sized businesses",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
