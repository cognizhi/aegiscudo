import type { Metadata } from "next";
import type { ReactNode } from "react";
import "react-grid-layout/css/styles.css";

import "./globals.css";

export const metadata: Metadata = {
  title: "Aegiscudo Command Center",
  description: "Supply chain security operations console",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html:
              "document.documentElement.dataset.theme=localStorage.getItem('aegiscudo-theme')||'dark'",
          }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}