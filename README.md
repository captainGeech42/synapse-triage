# synapse-triage
Synapse Rapid Power-Up for Hatching Triage

## Install

TBD

## Test

_Warning: `sample.zip` is extracted in memory and contains a live malware sample used for testing this functionality._

You must have a Tria.ge public cloud API key to run the tests. Please put the key in `$SYNAPSE_TRIAGE_APIKEY` when running the tests:

```
$ SYNAPSE_TRIAGE_APIKEY=asdf python -m pytest test_synapse_triage.py
```