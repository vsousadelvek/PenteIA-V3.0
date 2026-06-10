/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: {
          900: '#0f0f0f',
          800: '#1a1a1a',
          700: '#2d2d2d',
          600: '#3d3d3d'
        },
        neon: {
          red: '#ff4444',
          green: '#44ff44',
          blue: '#4444ff',
          cyan: '#44ffff'
        }
      }
    },
  },
  plugins: [],
}
