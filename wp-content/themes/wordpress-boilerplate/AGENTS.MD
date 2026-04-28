# Project Build

This theme uses Laravel Mix to compile the front-end assets defined in `webpack.mix.js`.

## Install Dependencies

Run this once before building:

```bash
npm install
```

## Build JS and CSS

Run the production build from the theme root:

```bash
npm run build
```

The build compiles:

- `assets/styles/style.scss` to `style.css`
- `assets/scripts/scripts.js` to `js/scripts.min.js`
