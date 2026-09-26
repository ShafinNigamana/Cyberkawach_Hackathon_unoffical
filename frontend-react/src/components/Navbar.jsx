import './Navbar.css';

/**
 * Minimal navbar: brand name left, nothing else.
 * History removed per user instructions (backend not implemented).
 */
export default function Navbar() {
  return (
    <nav className="navbar" role="navigation" aria-label="Main navigation">
      <div className="navbar-inner">
        <a href="/" className="navbar-brand" aria-label="Cyber Fraud Guardian home">
          Cyber Fraud Guardian
        </a>
      </div>
    </nav>
  );
}
