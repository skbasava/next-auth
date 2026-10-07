// Tests must explicitly opt into dedicated local integration services.
// Never copy an ambient DATABASE_URL or Redis URL into test configuration.
process.env.TZ = "UTC"
