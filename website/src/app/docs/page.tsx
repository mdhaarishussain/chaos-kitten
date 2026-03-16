"use client";

import Link from "next/link";
import Image from "next/image";
import Header from "@/components/Header";
import Footer from "@/components/Footer";

export default function Docs() {
  return (
    <>
      <Header />
      <style jsx global>{`
:root {
            --bg-main: #050712;
            --bg-card: #0c0f1b;
            --bg-card-soft: #111525;
            --accent-pink: #ff3b9a;
            --accent-purple: #7b5cff;
            --accent-cyan: #21e6ff;
            --accent-yellow: #ffd66b;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --border-subtle: rgba(148, 163, 184, 0.2);
            --radius-lg: 18px;
            --shadow-card: 0 24px 60px rgba(0, 0, 0, 0.65);
            --font-sans: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text",
                "Segoe UI", Roboto, sans-serif;
            --code-bg: #050816;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--font-sans);
            background: radial-gradient(circle at top left, #1a1037 0, #050712 45%),
                radial-gradient(circle at bottom right, #071e33 0, #050712 55%);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 24px 12px 40px;
        }

        .shell {
            max-width: 1120px;
            margin: 0 auto;
        }

        /* Top bar with Go Back button */
        .top-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 16px;
        }

        .back-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 999px;
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(148, 163, 184, 0.4);
            color: var(--text-secondary);
            font-size: 12px;
            cursor: pointer;
            text-decoration: none;
        }

        .back-btn:hover {
            background: rgba(31, 41, 55, 0.95);
            color: #e5e7eb;
        }

        .back-btn span.icon {
            font-size: 14px;
            transform: translateY(0.5px);
        }

        header.hero {
            display: flex;
            flex-wrap: wrap;
            gap: 32px;
            align-items: flex-start;
            margin-bottom: 32px;
        }

        .hero-text {
            flex: 1 1 320px;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 4px 10px;
            border-radius: 999px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.35);
            font-size: 12px;
            color: #a7f3d0;
            margin-bottom: 18px;
        }

        .badge-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: #22c55e;
            box-shadow: 0 0 0 4px rgba(34, 197, 94, 0.25);
        }

        .hero-title {
            font-size: clamp(2.3rem, 3vw, 2.8rem);
            line-height: 1.1;
            font-weight: 700;
            letter-spacing: -0.04em;
            margin-bottom: 16px;
        }

        .hero-title span.accent {
            background: linear-gradient(90deg, #22e6ff, #ff3b9a);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            position: relative;
        }

        .hero-subtitle {
            color: var(--text-secondary);
            max-width: 480px;
            font-size: 14px;
        }

        .hero-terminal {
            flex: 1 1 320px;
            background: var(--bg-card);
            border-radius: 24px;
            box-shadow: var(--shadow-card);
            overflow: hidden;
            border: 1px solid rgba(148, 163, 184, 0.35);
        }

        .terminal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 16px;
            background: linear-gradient(90deg, #111827, #020617);
            font-size: 11px;
            letter-spacing: 0.08em;
            text-transform: lowercase;
            color: #9ca3af;
        }

        .traffic-lights {
            display: flex;
            gap: 6px;
        }

        .traffic-lights span {
            width: 9px;
            height: 9px;
            border-radius: 999px;
            background: #4b5563;
        }

        .traffic-lights span:nth-child(1) {
            background: #f97373;
        }

        .traffic-lights span:nth-child(2) {
            background: #facc15;
        }

        .traffic-lights span:nth-child(3) {
            background: #22c55e;
        }

        .terminal-body {
            padding: 14px 18px 16px;
            background: radial-gradient(circle at top left, #1a1037 0, #020617 50%);
            font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
                Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 12px;
            line-height: 1.5;
            color: #e5e7eb;
            min-height: 180px;
            white-space: pre;
            overflow-x: auto;
        }

        .terminal-line.info {
            color: #60a5fa;
        }

        .terminal-line.warn {
            color: #facc15;
        }

        .terminal-line.vuln {
            color: #fb7185;
        }

        .terminal-line.success {
            color: #4ade80;
        }

        .layout {
            display: grid;
            grid-template-columns: minmax(0, 1.3fr) minmax(0, 1fr);
            gap: 20px;
            margin-top: 8px;
        }

        .panel {
            background: linear-gradient(145deg, #0b1020, #050816);
            border-radius: var(--radius-lg);
            padding: 18px 18px 20px;
            border: 1px solid var(--border-subtle);
            box-shadow: var(--shadow-card);
        }

        .panel+.panel {
            margin-top: 14px;
        }

        .panel-title {
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 10px;
        }

        .panel-title span.pill {
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 999px;
            background: rgba(148, 163, 184, 0.18);
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .panel p {
            font-size: 13px;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }

        ul {
            list-style: none;
            margin: 8px 0 0;
            padding-left: 0;
        }

        ul li {
            font-size: 13px;
            color: var(--text-secondary);
            padding-left: 18px;
            position: relative;
            margin-bottom: 4px;
        }

        ul li::before {
            content: "▹";
            position: absolute;
            left: 0;
            top: 0;
            color: var(--accent-cyan);
            font-size: 12px;
        }

        pre {
            margin-top: 8px;
            background: var(--code-bg);
            border-radius: 12px;
            padding: 10px 11px;
            font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
                Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 12px;
            color: #e5e7eb;
            border: 1px solid rgba(31, 41, 55, 0.8);
            overflow-x: auto;
        }

        pre code {
            background: transparent;
            padding: 0;
            border-radius: 0;
            color: inherit;
        }

        code {
            font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco,
                Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 12px;
            background: rgba(15, 23, 42, 0.85);
            padding: 1px 5px;
            border-radius: 6px;
            border: 1px solid rgba(148, 163, 184, 0.35);
            color: #e5e7eb;
        }

        .steps {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 12px;
            margin-top: 6px;
        }

        .step-card {
            background: radial-gradient(circle at top left, #1c153f 0, #050816 55%);
            border-radius: 12px;
            padding: 10px 11px;
            border: 1px solid rgba(55, 65, 81, 0.85);
        }

        .step-label {
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.12em;
            color: var(--accent-cyan);
            margin-bottom: 4px;
        }

        .step-title {
            font-size: 13px;
            font-weight: 500;
            margin-bottom: 4px;
        }

        .step-card p {
            font-size: 12px;
            margin-bottom: 6px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 8px;
            font-size: 12px;
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid rgba(55, 65, 81, 0.9);
            background: #020617;
        }

        th,
        td {
            padding: 6px 8px;
            text-align: left;
            border-bottom: 1px solid rgba(31, 41, 55, 0.9);
        }

        th {
            background: linear-gradient(90deg, #111827, #020617);
            font-weight: 500;
            color: #e5e7eb;
        }

        tr:last-child td {
            border-bottom: none;
        }

        tr:nth-child(even) td {
            background: rgba(15, 23, 42, 0.7);
        }

        .sev-info {
            color: #7390f9;
            font-weight: 600;
        }

        .sev-critical {
            color: #f97373;
            font-weight: 600;
        }

        .sev-high {
            color: #fb923c;
            font-weight: 600;
        }

        .sev-medium {
            color: #facc15;
            font-weight: 600;
        }

        .sev-low {
            color: #4ade80;
            font-weight: 600;
        }

        .pill-level {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            font-size: 11px;
            padding: 2px 7px;
            border-radius: 999px;
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(55, 65, 81, 0.9);
        }

        .pill-level span.dot {
            width: 7px;
            height: 7px;
            border-radius: 999px;
            background: currentColor;
        }

        .section-heading {
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.14em;
            color: var(--text-secondary);
            margin: 22px 0 6px;
        }

        a.link-inline {
            color: var(--accent-cyan);
            text-decoration: none;
        }

        a.link-inline:hover {
            text-decoration: underline;
        }

        /* Mobile tweaks */
        @media (max-width: 900px) {
            body {
                padding: 18px 10px 32px;
            }

            header.hero {
                flex-direction: column;
                align-items: flex-start;
            }

            .hero-terminal {
                width: 100%;
            }

            .layout {
                grid-template-columns: minmax(0, 1fr);
            }

            .panel {
                padding: 14px 14px 16px;
            }

            .steps {
                grid-template-columns: minmax(0, 1fr);
            }
        }

        @media (max-width: 640px) {
            .hero-title {
                font-size: 1.9rem;
            }

            .hero-subtitle {
                font-size: 13px;
            }
        }
      `}</style>
      <div>
        <div className="shell">
          <header className="hero">
            <div className="hero-text">
              <div className="badge">
                <span className="badge-dot"></span>
                <span>Documentation</span>
              </div>
              <h1 className="hero-title">
                Chaos Kitten <span className="accent">Developer Hub</span>
              </h1>
              <p className="hero-subtitle">
                Learn how to contribute, extend, and understand the internal architecture of Chaos Kitten.
                Get started with our guides below.
              </p>
            </div>
          </header>

          <div className="layout">
            <div>
              <div className="panel">
                <div className="panel-title">
                  Architecture Overview
                  <span className="pill">Internal Design</span>
                </div>
                <p>Chaos Kitten is built on a modular architecture to allow easy extension of attacks and scanners.</p>
                <ul>
                  <li><strong>The Brain</strong>: Parses OpenAPI specs and plans attacks using LLM or heuristics.</li>
                  <li><strong>The Paws</strong>: Executes HTTP requests against the target API with various adapters.</li>
                  <li><strong>The Litterbox</strong>: Generates reports in multiple formats (HTML, SARIF, JSON).</li>
                  <li><strong>Scanner</strong>: The core engine that orchestrates the entire process.</li>
                </ul>
              </div>

              <div className="panel">
                 <div className="panel-title">
                    Contributing
                    <span className="pill">Join Us</span>
                 </div>
                 <p>We welcome contributions! To get started with development:</p>
                 <pre><code>git clone https://github.com/mdhaarishussain/chaos-kitten.git
cd chaos-kitten
pip install -e '.[dev]'
pytest</code></pre>
                 <p>See <a href="https://github.com/mdhaarishussain/chaos-kitten/blob/main/CONTRIBUTING.md" className="link-inline">CONTRIBUTING.md</a> for more details.</p>
              </div>
            </div>

            <div>
               <div className="panel">
                  <div className="panel-title">
                     Project Structure
                     <span className="pill">File Tree</span>
                  </div>
                  <ul>
                    <li><code>chaos_kitten/brain/</code>: Planning logic & strategies</li>
                    <li><code>chaos_kitten/paws/</code>: Network execution</li>
                    <li><code>chaos_kitten/litterbox/</code>: Reporting modules</li>
                    <li><code>website/</code>: This documentation site</li>
                    <li><code>tests/</code>: Comprehensive test suite</li>
                  </ul>
               </div>

               <div className="panel">
                  <div className="panel-title">
                     Resources
                  </div>
                  <ul>
                    <li><Link href="/quickstart" className="link-inline">Getting Started / Quickstart</Link></li>
                    <li><a href="https://github.com/mdhaarishussain/chaos-kitten" className="link-inline">GitHub Repository</a></li>
                    <li><a href="https://github.com/mdhaarishussain/chaos-kitten/issues" className="link-inline">Report an Issue</a></li>
                  </ul>
               </div>
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </>
  );
}
