import binascii
import hashlib
import os
import logging
import zipfile

import synapse.common as s_common
import synapse.tests.utils as s_test
import synapse.tools.genpkg as s_genpkg

logger = logging.getLogger(__name__)

dirname = os.path.dirname(__file__)
pkgproto = s_common.genpath(dirname, "synapse-triage.yaml")

def get_mal_bytes():
    with zipfile.ZipFile("sample.zip") as zf:
        with zf.open("sample", "r", b"infected") as f:
            return f.read()

def get_api_key():
    key = os.getenv("SYNAPSE_TRIAGE_APIKEY")
    if key is not None:
        return key

class SynapseTriageTest(s_test.SynTest):

    async def test_synapse_triage(self):
        # this test suite requires internet access
        self.skipIfNoInternet()

        # get API key
        api_key = get_api_key()
        self.assertIsNotNone(api_key, "You must provide an API key in $SYNAPSE_TRIAGE_APIKEY to run the test suite")

        async with self.getTestCore() as core:
            # upload malware sample to test axon
            mal_bytes = get_mal_bytes()
            mal_sha256 = hashlib.sha256(mal_bytes).hexdigest()

            async with await core.axon.upload() as fd:
                await fd.write(mal_bytes)
                _, axon_sha256 = await fd.save()
                self.eq(binascii.hexlify(axon_sha256).decode(), mal_sha256)

            # create file:bytes node in the cortex
            nodes = await core.nodes("[ file:bytes=$hash :name=$name ]", opts={"vars": {"hash": mal_sha256, "name": "raccon_test_boi"}})
            self.len(1, nodes)
            
            # install package
            await s_genpkg.main((pkgproto, "--push", f"cell://{core.dirn}"))

            # set the api key
            msgs = await core.stormlist("triage.setup.apikey --self $key", opts={"vars": {"key": api_key}})
            self.stormIsInPrint("for the current user", msgs)
            
            msgs = await core.stormlist("triage.setup.apikey $key", opts={"vars": {"key": api_key}})
            self.stormIsInPrint("for all users", msgs)

            # submit the sample to triage
            msgs = await core.stormlist("file:bytes:sha256=$hash | triage.submit", opts={"vars": {"hash": mal_sha256}})
            self.stormIsInPrint("Hatching Triage (sample ID: ", msgs)







            return

            # some test APIs to simplify async generators and such...
            msgs = await core.stormlist("acme.hello.print --show-prefix --prefix VISI \"hello world!\"")
            self.stormIsInPrint("VISI hello world!", msgs)

            nodes = await core.nodes("[ inet:email=visi@vertex.link ] | acme.hello.autotag")
            self.len(1, nodes)
            self.true(nodes[0].tags.get("acme.hello") is not None)

            # check that the meta source node got created and linked...
            nodes = await core.nodes("meta:source:name=\"ACME Hello World\" -(seen)> *")
            self.len(1, nodes)
            self.eq(nodes[0].ndef, ("inet:email", "visi@vertex.link"))

            # check that the description is in the auto generated `--help` output
            msgs = await core.stormlist("acme.hello.print --help")
            self.stormIsInPrint("Print some text", msgs)
