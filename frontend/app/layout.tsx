import type { Metadata } from "next";
import { IBM_Plex_Sans, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { RootShell } from "@/components/layout/root-shell";
import { Providers } from "@/components/layout/providers";

const plexSans = IBM_Plex_Sans({
  variable: "--font-plex-sans",
  weight: ["400", "500", "600", "700"],
  subsets: ["latin"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  weight: ["400", "500", "700"],
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Threat Intel Platform",
  description: "SOC analyst dashboard for detections and threat intelligence",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${plexSans.variable} ${jetbrainsMono.variable} antialiased`}
      >
        <Providers>
          <RootShell>{children}</RootShell>
        </Providers>
      </body>
    </html>
  );
}
