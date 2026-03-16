"use client";

import Link from 'next/link';
import Image from 'next/image';
import { useState } from 'react';

export default function Header() {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  const closeMobileMenu = () => {
    setIsMobileMenuOpen(false);
  };

  return (
    <header className="navbar container">
        <Link href="/" className="logo">
            <Image src="/assets/logo.png" alt="Chaos Kitten Logo" width={32} height={32} />
            <span>Chaos Kitten</span>
        </Link>
        <nav className={isMobileMenuOpen ? 'active' : ''}>
            <Link href="/#features" className="nav-link" onClick={closeMobileMenu}>Features</Link>
            <Link href="/quickstart" className="nav-link" onClick={closeMobileMenu}>Quickstart</Link>
            <Link href="/docs" className="nav-link" onClick={closeMobileMenu}>Docs</Link>
            <a href="https://github.com/mdhaarishussain/chaos-kitten" target="_blank" className="btn btn-secondary" onClick={closeMobileMenu}>
                <i className="fab fa-github"></i> GitHub
            </a>
        </nav>
        <button className="mobile-menu-btn" onClick={toggleMobileMenu}>
            <i className={`fas ${isMobileMenuOpen ? 'fa-times' : 'fa-bars'}`}></i>
        </button>
    </header>
  );
}
