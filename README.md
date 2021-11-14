# Suricata Eve Kafka Output Plugin for Suricata 6.0.x

This plugin provides a Suricata Eve output for Kafka. Base on suricata-redis-output: https://github.com/jasonish/suricata-redis-output/tree/6.0

## Building

```
git clone https://github.com/Center-Sun/suricata-kafka-output.git
cd suricata-kafka-output
cargo build --release
```

## Installing

As there is no standard way (yet) to install Suricata plugins we'll install the
plugin to `/usr/local/lib/suricata/plugins`.

```
mkdir -p /usr/local/lib/suricata/plugins
cp target/release/libkafka_output.so /usr/local/lib/suricata/plugins/
```

Add a section to your `suricata.yaml` that looks like:

```
plugins:
  - /usr/local/lib/suricata/plugins/libkafka_output.so
```

Then set the `filetype` in your `eve` configuration section to
`kafka`.

## Configuration

Add a section to your `suricata.yaml` that looks like:

```
kafka:
  brokers: "kafka1:9092,kafka2:9092"
  topic: suricata
  buffer-size: 1024
```