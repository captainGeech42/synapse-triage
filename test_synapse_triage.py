import binascii
import hashlib
import os
import logging
import zipfile

import synapse.common as s_common
import synapse.cortex as s_cortex
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

    def has_tag(self, node, tag):
        self.true(node.tags.get(tag) is not None)

    # Upload the sample used for testing
    async def _t_upload_sample(self, core: s_cortex.Cortex) -> str:
        # upload malware sample to test axon
        mal_bytes = get_mal_bytes()
        mal_sha256 = hashlib.sha256(mal_bytes).hexdigest()

        async with await core.axon.upload() as fd:
            await fd.write(mal_bytes)
            _, axon_sha256 = await fd.save()
            self.eq(binascii.hexlify(axon_sha256).decode(), mal_sha256)

        # create file:bytes node in the cortex
        nodes = await core.nodes("[ file:bytes=$hash :name=$name ]", opts={"vars": {"hash": mal_sha256, "name": "raccoon_test_boi"}})
        self.len(1, nodes)
            
        # TODO: add support for hash forms and test for them

        return mal_sha256

    # Tests for installing/configuring the package
    async def _t_install_pkg(self, core: s_cortex.Cortex):
        # get API key
        api_key = get_api_key()
        self.assertIsNotNone(api_key, "You must provide an API key in $SYNAPSE_TRIAGE_APIKEY to run the test suite")

        # install package
        await s_genpkg.main((pkgproto, "--push", f"cell://{core.dirn}"))

        # set the api key
        msgs = await core.stormlist("zw.triage.setup.apikey --self $key", opts={"vars": {"key": api_key}})
        self.stormIsInPrint("for the current user", msgs)
            
        msgs = await core.stormlist("zw.triage.setup.apikey $key", opts={"vars": {"key": api_key}})
        self.stormIsInPrint("for all users", msgs)

    # Tests for sample submission
    async def _t_submit(self, core: s_cortex.Cortex, mal_sha256: str):
        # try to submit the sample to triage
        # it already exists, should flag and not submit
        msgs = await core.stormlist("file:bytes:sha256=$hash | zw.triage.submit", opts={"vars": {"hash": mal_sha256}})
        self.stormIsInWarn("Report(s) already exist for ", msgs)
        self.stormNotInPrint("Hatching Triage (sample ID: ", msgs)

        # now force submit it
        # TODO: add --no-ingest in test and in lib to skip adding the cron job to auto ingest
        msgs = await core.stormlist("file:bytes:sha256=$hash | zw.triage.submit --force", opts={"vars": {"hash": mal_sha256}})
        self.stormIsInPrint("Hatching Triage (sample ID: ", msgs)
    
    # Tests for report ingestion
    async def _t_ingest(self, core: s_cortex.Cortex, mal_sha256: str):
        # reports already exist for the test sample, so we don't need to wait to ingest it
        # TODO: add --config and --noconfig along with something in triage.setup to model configs
        # TODO: also customizable tag prefixes like other rapid power-ups
        msgs = await core.stormlist("file:bytes:sha256=$hash | zw.triage.ingest", opts={"vars": {"hash": mal_sha256}})
        self.stormIsInPrint("Ingested latest execution report for ", msgs)

        # check the meta:source edge
        nodes = await core.nodes("meta:source:name=$name -(seen)> file:bytes:sha256=$hash", opts={"vars": {"name": "hatching triage public cloud", "hash": mal_sha256}})
        self.len(1, nodes)

        # check that its tagged properly

        nodes = await core.nodes("file:bytes:sha256=$hash", opts={"vars": {"hash": mal_sha256}})
        self.len(1, nodes)
        n = nodes[0]
        self.eq(n.ndef, ("file:bytes", "sha256:af0bc0b2149df1769de0128984f8178620fae9de69e5bb4e0a3d661ae8cd18eb"))

        # aka?
        self.has_tag(n, "rep.triage.raccoon")

        # tags?
        self.has_tag(n, "rep.triage.stealer")
        self.has_tag(n, "rep.triage.suricata")

        # config?
        self.has_tag(n, "desc.config.raccoon.botnet.e50c949ecf0380ef03a3368f13619264294662b6")

        # check the passwd edges
        nodes = await core.nodes("file:bytes:sha256=$hash -(refs)> inet:passwd +#rep.triage.raccoon", opts={"vars": {"hash": mal_sha256}})
        self.len(2, nodes)

        # check the inet:http:requests
        #nodes = await core.nodes("file:bytes:sha256=$hash -> inet:dns:request +#rep.triage.raccoon", opts={"vars": {"hash": mal_sha256}})
        #self.len(6, nodes)

        # try to re-ingest it, should fail without --force
        msgs = await core.stormlist("file:bytes:sha256=$hash | zw.triage.ingest", opts={"vars": {"hash": mal_sha256}})
        self.stormNotInPrint("Ingested latest execution report for ", msgs)
        self.stormIsInWarn(" is already modeled, use --force ", msgs)

        # now ingest it with --force
        msgs = await core.stormlist("file:bytes:sha256=$hash | zw.triage.ingest --force", opts={"vars": {"hash": mal_sha256}})
        self.stormIsInPrint("Ingested latest execution report for ", msgs)

    async def _t_ingest_id_1(self, core: s_cortex.Cortex):
        # Vidar sample
        # https://tria.ge/220221-wa3sgsbgbj
        sample_id = "220221-wa3sgsbgbj"
        hash = "31fabfbe61fdc161c12c62ec848d558cce743de39b58cf634910bd6fb305f22d"
    
        msgs = await core.stormlist("zw.triage.ingest.id $id", opts={"vars": {"id": sample_id}})
        self.stormIsInPrint(f"Ingested {sample_id} from Hatching Triage", msgs)

        nodes = await core.nodes("file:bytes:sha256=$hash", opts={"vars": {"hash": hash}})
        self.len(1, nodes)
        n = nodes[0]
        self.eq(n.ndef, ("file:bytes", "sha256:31fabfbe61fdc161c12c62ec848d558cce743de39b58cf634910bd6fb305f22d"))

        # aka?
        self.has_tag(n, "rep.triage.vidar")

        # config?
        self.has_tag(n, "desc.config.vidar.version.50_3")
        self.has_tag(n, "desc.config.vidar.botnet.565")

        # c2s?
        # check the digraph edge
        nodes = await core.nodes("file:bytes=$hash -> inet:http:request:exe +#rep.triage.vidar", opts={"vars": {"hash": hash}})
        self.len(2, nodes)
        # check the url node
        nodes = await core.nodes("file:bytes=$hash -> inet:http:request:exe +#rep.triage.vidar :url -> inet:url +#rep.triage.vidar", opts={"vars": {"hash": hash}})
        self.len(2, nodes)

    async def test_synapse_triage(self):
        # this test suite requires internet access
        self.skipIfNoInternet()

        async with self.getTestCore() as core:
            await self._t_install_pkg(core)

            mal_sha256 = await self._t_upload_sample(core)

            await self._t_submit(core, mal_sha256) 

            await self._t_ingest(core, mal_sha256)

            await self._t_ingest_id_1(core)