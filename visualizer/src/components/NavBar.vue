<template>
  <nav class="navbar-container">
    <!-- Top Banner -->
    <div class="banner-bar">
      <div class="banner-content">
        <a 
          href="https://cytix.io/virtual-event-micro-pen-testing" 
          target="_blank" 
          rel="noopener noreferrer"
          class="banner-link"
        >
          VIRTUAL EVENT: Micro Pen Testing in the SDLC: Closing the Gap Between Dev and Security - Watch Here
        </a>
      </div>
    </div>

    <!-- Main Navigation -->
    <div class="navbar-main">
      <!-- Logo -->
      <div class="navbar-logo">
        <a href="/" class="logo-link">
          <img 
            src="https://cdn.builder.io/api/v1/image/assets%2F0ae2d7cfe4b54f369c000b904ffc735e%2F2c22103cea5b47c8941084370846936c?format=webp&width=400" 
            alt="Cytix Logo" 
            class="logo-image"
          />
        </a>
      </div>

      <!-- Primary Menu -->
      <div class="navbar-menu">
      </div>

      <!-- Right Side Actions -->
      <div class="navbar-actions">
        <!-- Sign In Link -->
        <a href="https://portal.cytix.io" target="_blank" rel="noopener noreferrer" class="sign-in-link">
          <button class="sign-in-button">
            Sign In
          </button>
        </a>

        <!-- Start a Conversation CTA -->
        <a href="https://cytix.io/book-a-demo" target="_blank" rel="noopener noreferrer" class="cta-link">
          <button class="cta-button">
            Start a Conversation
          </button>
        </a>
      </div>

      <!-- Mobile Menu Toggle -->
      <button 
        class="mobile-menu-toggle"
        @click="isMobileMenuOpen = !isMobileMenuOpen"
        :aria-expanded="isMobileMenuOpen"
        aria-label="Open main menu"
      >
        <svg 
          class="menu-icon" 
          viewBox="0 0 24 24" 
          fill="none" 
          stroke="currentColor" 
          stroke-width="2"
        >
          <path d="M3 12h18M3 6h18M3 18h18"></path>
        </svg>
      </button>
    </div>

    <!-- Mobile Menu -->
    <div v-if="isMobileMenuOpen" class="mobile-menu">
      <a href="https://portal.cytix.io" target="_blank" rel="noopener noreferrer" class="mobile-nav-link">
        Sign In
      </a>
      <a href="https://cytix.io/book-a-demo" target="_blank" rel="noopener noreferrer" class="mobile-nav-link mobile-cta">
        Start a Conversation
      </a>
    </div>
  </nav>
</template>

<script setup lang="ts">
import { ref } from 'vue'

const isMobileMenuOpen = ref(false)
</script>

<style scoped>
.navbar-container {
  position: sticky;
  top: 0;
  z-index: 50;
  background-color: #ffffff;
  border-bottom: 1px solid #e5e7eb;
  box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
  backdrop-filter: blur(4px);
}

/* Banner Bar */
.banner-bar {
  background: linear-gradient(90deg, #020E1E 0%, #1a1a2e 100%);
  padding: 0.75rem 0;
  text-align: center;
  border-bottom: 1px solid #333;
}

.banner-content {
  max-width: 1400px;
  margin: 0 auto;
  padding: 0 1.5rem;
}

.banner-link {
  color: #ffffff;
  font-size: 0.875rem;
  font-weight: 500;
  text-decoration: none;
  transition: opacity 0.2s ease;
  display: inline-block;
}

.banner-link:hover {
  opacity: 0.8;
}

/* Main Navbar */
.navbar-main {
  display: flex;
  align-items: center;
  justify-content: space-between;
  max-width: 1400px;
  margin: 0 auto;
  padding: 0 1.5rem;
  height: 5rem;
  gap: 2rem;
}

/* Logo */
.navbar-logo {
  flex-shrink: 0;
}

.logo-link {
  display: inline-flex;
  align-items: center;
  text-decoration: none;
}

.logo-image {
  height: 2.5rem;
  width: auto;
  object-fit: contain;
}

/* Menu Items */
.navbar-menu {
  display: none;
  align-items: center;
  gap: 2rem;
  flex: 1;
}

@media (min-width: 768px) {
  .navbar-menu {
    display: flex;
  }
}

/* Actions */
.navbar-actions {
  display: none;
  align-items: center;
  gap: 1rem;
  flex-shrink: 0;
}

@media (min-width: 768px) {
  .navbar-actions {
    display: flex;
  }
}

.sign-in-link,
.cta-link {
  text-decoration: none;
}

.sign-in-button,
.cta-button {
  border: none;
  cursor: pointer;
  font-family: inherit;
  font-weight: 600;
  border-radius: 0.375rem;
  transition: all 0.2s ease;
  padding: 0.5rem 1rem;
  font-size: 0.875rem;
}

.sign-in-button {
  background-color: transparent;
  color: #374151;
}

.sign-in-button:hover {
  color: #FF822E;
}

.sign-in-button:focus-visible {
  outline: 2px solid #FF822E;
  outline-offset: 2px;
}

.cta-button {
  background-color: #FF822E;
  color: #ffffff;
  border-radius: 9999px;
  padding: 0.625rem 1.5rem;
  font-weight: 700;
}

.cta-button:hover {
  background-color: #DA4100;
}

.cta-button:focus-visible {
  outline: 2px solid #FF822E;
  outline-offset: 2px;
}

/* Mobile Menu Toggle */
.mobile-menu-toggle {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 2.5rem;
  height: 2.5rem;
  padding: 0;
  background: none;
  border: none;
  color: #374151;
  cursor: pointer;
  transition: color 0.2s ease;
}

@media (min-width: 768px) {
  .mobile-menu-toggle {
    display: none;
  }
}

.mobile-menu-toggle:hover {
  color: #FF822E;
}

.menu-icon {
  width: 1.5rem;
  height: 1.5rem;
}

/* Mobile Menu */
.mobile-menu {
  display: flex;
  flex-direction: column;
  gap: 0;
  border-top: 1px solid #e5e7eb;
  background-color: #ffffff;
  padding: 1rem 1.5rem;
}

@media (min-width: 768px) {
  .mobile-menu {
    display: none;
  }
}

.mobile-nav-link {
  padding: 0.75rem 0;
  color: #374151;
  text-decoration: none;
  font-size: 1rem;
  font-weight: 500;
  transition: color 0.2s ease;
  border: none;
  background: none;
  cursor: pointer;
  text-align: left;
  font-family: inherit;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.mobile-nav-link:hover {
  color: #FF822E;
}

.mobile-dropdown-trigger {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
}

.mobile-chevron {
  width: 1rem;
  height: 1rem;
  transition: transform 0.2s ease;
}

.mobile-chevron.chevron-open {
  transform: rotate(180deg);
}

.mobile-dropdown-menu {
  display: flex;
  flex-direction: column;
  gap: 0;
  background-color: #f9fafb;
  border-radius: 0.375rem;
  padding: 0.5rem 0;
  margin-top: 0.5rem;
  border-left: 4px solid #FF822E;
}

.mobile-dropdown-item {
  padding: 0.75rem 1rem;
  color: #374151;
  text-decoration: none;
  font-size: 0.875rem;
  transition: color 0.2s ease;
}

.mobile-dropdown-item:hover {
  color: #FF822E;
}

.mobile-cta {
  color: #ffffff;
  background-color: #FF822E;
  padding: 0.75rem;
  border-radius: 0.375rem;
  text-align: center;
  font-weight: 700;
  margin-top: 0.5rem;
}

.mobile-cta:hover {
  background-color: #DA4100;
}

/* Responsive adjustments */
@media (max-width: 640px) {
  .navbar-main {
    height: 4rem;
    padding: 0 1rem;
    gap: 1rem;
  }

  .logo-image {
    height: 2rem;
  }

  .banner-link {
    font-size: 0.8125rem;
  }
}
</style>
