/** @type {import("next").NextConfig} */
module.exports = {
  webpack(config) {
    // Workspace packages must share the app renderer's React installation.
    config.resolve.alias = {
      ...config.resolve.alias,
      react$: require.resolve("react"),
      "react/jsx-runtime$": require.resolve("react/jsx-runtime"),
      "react/jsx-dev-runtime$": require.resolve("react/jsx-dev-runtime"),
      "react-dom$": require.resolve("react-dom"),
    }
    config.experiments = { ...config.experiments, topLevelAwait: true }
    return config
  },
  typescript: { ignoreBuildErrors: true },
}
