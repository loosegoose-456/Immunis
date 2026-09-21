import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';

import './globals.css';

export const metadata: Metadata = {
  title: 'War Room — Red vs. Blue',
  description: 'Live view of the autonomous zero-day patching engine: attacks in, mitigations out.',
};

export const viewport: Viewport = {
  themeColor: '#07080d',
  colorScheme: 'dark',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
