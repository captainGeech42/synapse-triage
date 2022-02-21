# synapse-triage
Synapse Rapid Power-Up for Hatching Triage

## Install

TBD

## Test

_Warning: `sample.zip` is extracted in memory and contains a live malware sample used for testing this functionality._

You must have a Tria.ge public cloud API key to run the tests. You can put the key in `$SYNAPSE_TRIAGE_APIKEY` for the test suite, or pass it to stdin when prompted.

```
$ SYNAPSE_TRIAGE_APIKEY=asdf python -m pytest test_synapse_triage.py
```