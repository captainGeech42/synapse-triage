# synapse-triage
Synapse Rapid Power-Up for [Hatching Triage](https://tria.ge/)

## Install

To install the latest release, run the following Storm command

```
storm> pkg.load --raw https://github.com/captainGeech42/synapse-triage/releases/latest/download/synapse_triage.json
```

You can also clone this repo, and install via the telepath API:

```
$ python -m synapse.tools.genpkg --push core00 synapse-triage.yaml
```

## Usage

First, configure your API key (globally, or per user with `--self`):

```
storm> zw.triage.setup.apikey <api key here>
```

Then, you can push samples to the sandbox:

```
storm> file:bytes | limit 1 | zw.triage.submit
```

Samples will automatically have their report ingested once execution finishes. You can also manually ingest a report:

```
storm> file:bytes | limit 1 | zw.triage.ingest
```

Both commands have a `--force` option to re-submit/re-model if it's already been done.

You can also manually ingest a report from Triage using the sample ID:

```
storm> zw.triage.ingest.id 220221-wa3sgsbgbj
```

For more details, please run `help zw.triage`.

## Running the test suite

_Warning: `sample.zip` is extracted in memory and contains a live malware sample used for testing this functionality._

You must have a Tria.ge public cloud API key to run the tests. Please put the key in `$SYNAPSE_TRIAGE_APIKEY` when running the tests:

```
$ pip install -r requirements.txt
$ SYNAPSE_TRIAGE_APIKEY=asdf python -m pytest test_synapse_triage.py
```

## TODO

URL submissions: https://tria.ge/220221-qyb2saadb6