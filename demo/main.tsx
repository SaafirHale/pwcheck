import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/archivo/500.css";
import "@fontsource/archivo/600.css";
import "@fontsource/archivo/700.css";
import "@fontsource/geist-mono/400.css";
import "@fontsource/geist-mono/500.css";
import "../src/react/styles.css";
import "./demo.css";
import { PasswordChecker } from "../src/react/index.js";

type Theme = "dark" | "light";

function App() {
  // Held in memory only: the tool promises no browser storage, and that includes the demo shell.
  const [theme, setTheme] = useState<Theme>("dark");
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  return (
    <div className="sh-shell">
      <div className="sh-wrap">
        <header className="demo-header">
          <span className="demo-name">Saafir Hale</span>
          <nav className="demo-crumbs">
            <span className="muted">tools</span> / password
          </nav>
          <button type="button" className="demo-theme" onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}>
            {theme === "dark" ? "light" : "dark"}
          </button>
        </header>

        <main id="main">
          <section className="demo-hero">
            <div className="muted demo-eyebrow">Tool · runs in your browser</div>
            <h1 className="sh-h1">Password check</h1>
            <p className="sh-lede demo-lede">
              How a password would actually be guessed, how long that takes under four kinds of attack, and whether it already sits in
              breach data. Your password never leaves the page. The optional breach check sends the first five characters of its SHA-1
              hash, and nothing else about it.
            </p>
          </section>

          <PasswordChecker userInputs={["saafir", "hale", "saafirhale", "pwcheck"]} />
        </main>

        <footer className="demo-footer">
          <span>
            Strength by{" "}
            <a className="sh-link-muted" href="https://github.com/zxcvbn-ts/zxcvbn" target="_blank" rel="noreferrer noopener">
              zxcvbn-ts
            </a>{" "}
            (MIT). Breach data from{" "}
            <a className="sh-link-muted" href="https://haveibeenpwned.com/Passwords" target="_blank" rel="noreferrer noopener">
              Have I Been Pwned
            </a>
            .
          </span>
          <span>saafirhale.com/tools/password</span>
        </footer>
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
