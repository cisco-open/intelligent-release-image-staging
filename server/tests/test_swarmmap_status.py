# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exercise live map state changes without a browser or network."""
from pathlib import Path
import shutil
import subprocess

import pytest

import auth
import telemetry


MAP = Path(__file__).resolve().parents[1] / "swarmmap.html"
HARNESS = r"""
const assert = require('node:assert/strict');
const nodes = {};
class Element {
  constructor(id='') { this.id=id; this.dataset={}; this.children=[]; this.attrs={};
    this._html=''; this.textContent=''; this.listeners={}; this.disabled=false;
    const names=new Set(); this.classList={add:x=>names.add(x),remove:x=>names.delete(x),contains:x=>names.has(x)}; }
  set innerHTML(value) { this._html=value;
    for(const m of value.matchAll(/id="([^"]+)"/g)) nodes[m[1]]=new Element(m[1]);
    for(const id of ['peer-details','hub-details']) {
      const m=new RegExp('id="'+id+'">([\\s\\S]*?)</div>').exec(value);
      if(m) nodes[id]._html=m[1];
    }
  }
  get innerHTML() { return this._html; }
  append(...values) { this.children.push(...values); }
  replaceChildren(...values) { this.children=values; }
  setAttribute(k,v) { this.attrs[k]=v; }
  removeAttribute(k) { delete this.attrs[k]; }
  getAttribute(k) { return this.attrs[k]; }
  addEventListener(k,fn) { this.listeners[k]=fn; }
  querySelector(s) { return nodes[s.slice(1)] || null; }
  focus() { document.activeElement=this; }
}
for(const id of ['svg','drawer','empty','state','wrap','imgsel','tbody']) nodes[id]=new Element(id);
const document={getElementById:id=>nodes[id]||null,createElement:()=>new Element(),
  createElementNS:()=>new Element(),querySelector:()=>nodes.tbody,activeElement:new Element('initial')};
const window={};
const Option=function(label,value) { return {label,value}; };
let fetch=async()=>{throw Error('No network in this harness');};
const setTimeout=()=>0, clearTimeout=()=>{};
function peer(id,state='staging') { return {device_id:id,ip:id,port:6881,_hash:'hash-os',_img:'os.iso',_image_id:'os',
  tracker:{principal_type:'device',principal_id:id,role:state==='ready'?'seeder':'leecher',left:state==='ready'?0:50,progress:state==='ready'?1:.5},
  device_observation:{obs_state:'observed',stale:false},current_image_id:'os',stage_state:state,
  staged_image_ids:state==='ready'?['os']:[],errored_image_ids:[]}; }
function snapshot(peers) { return {now:100,images:[{image:'os.iso',image_id:'os',info_hash:'hash-os',peers}]}; }
"""


def run_map(scenario):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for map behavior tests")
    source = MAP.read_text().split("<script>", 1)[1].split("</script>", 1)[0]
    source = source.split('document.getElementById("imgsel").addEventListener', 1)[0]
    result = subprocess.run([node], input=HARNESS + source + "\n(async()=>{\n" + scenario
                            + "\n})().catch(e=>{console.error(e);process.exitCode=1;});\n",
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("stage", ["staging", "verifying", "transferring_to_ios", "flash_full"])
def test_torrent_completion_does_not_claim_device_staging_complete(stage):
    run_map("""
      const p=peer('device', %r); p.tracker.left=0; p.tracker.progress=1;
      p.device_observation={obs_state:'not_due',stale:true};
      assert.doesNotMatch(peerStatus(p), /staging complete/);
    """ % stage)


def test_finished_and_new_device_keep_independent_staging_status():
    run_map("""
      const finished=peer('xr-one','ready'), starting=peer('xr-two');
      assert.match(peerStatus(finished), /ready/);
      assert.match(peerStatus(starting), /staging/);
      assert.doesNotMatch(peerStatus(starting), /ready/);
      starting.staged_image_ids=['os']; starting.errored_image_ids=['os'];
      assert.match(imageRows(starting), /error/);
      assert.doesNotMatch(imageRows(starting), />ready</);
      assert.match(peerStatus(starting), /error|failed/);
    """)


def test_open_drawer_refreshes_same_participant_when_another_joins_first():
    run_map("""
      DATA=snapshot([peer('xr-one')]); render(); openPeer(allPeers()[0]);
      const focus=document.activeElement, gen=drawerGen;
      DATA=snapshot([peer('xr-two'),peer('xr-one','ready')]); render();
      const detail=document.getElementById('peer-details');
      assert.ok(detail,'drawer needs a refreshable details region');
      assert.match(detail.innerHTML, /xr-one/); assert.match(detail.innerHTML, />ready</);
      assert.doesNotMatch(detail.innerHTML, /xr-two/);
      assert.equal(document.activeElement,focus,'poll stole focus');
      assert.equal(drawerGen,gen,'poll restarted report requests');
    """)


def test_closing_or_switching_to_origin_invalidates_peer_report_request():
    run_map("""
      openPeer(peer('xr-one')); const first=drawerGen; closeDrawer();
      assert.equal(selected,null); assert.ok(drawerGen>first);
      openPeer(peer('xr-one')); const second=drawerGen; openHub();
      assert.ok(drawerGen>second); assert.notEqual(selected?.device_id,'xr-one');
    """)


def test_image_bound_observation_does_not_describe_another_image():
    run_map("""
      const p=peer('xr-one'); p.device_observation={image_id:'other',obs_state:'observed',receive_bps:123456,valid:true};
      p.latest_report={image_id:'other',schema:'v2',content_sha256_state:'verified-other'};
      openPeer(p); const html=drawer.innerHTML;
      assert.doesNotMatch(html,/verified-other/);
      assert.match(html,/another image/);
    """)


def test_unstaged_image_is_pending_when_device_reports_another_ready_image():
    run_map("""
      const p=peer('xe-one','ready'); p._image_id='other';
      assert.match(peerStatus(p), /pending/); assert.doesNotMatch(peerStatus(p), /ready/);
    """)


@pytest.mark.parametrize("state", ["error", "copy_failed", "transferring_to_ios", "ready"])
def test_legacy_single_image_keeps_its_exact_reported_state(state):
    run_map("""
      const p=peer('legacy'); delete p.staged_image_ids; delete p.errored_image_ids;
      p.stage_state=%r; assert.equal(imageState(p,'os'), %r);
    """ % (state, state))


def test_missing_participant_clears_old_details_and_recovers_without_switching():
    run_map("""
      DATA=snapshot([peer('xr-one')]); render(); openPeer(allPeers()[0]);
      DATA=snapshot([peer('xr-two')]); render();
      assert.match(nodes['peer-details'].innerHTML,/no longer present/);
      DATA=snapshot([peer('xr-two'),peer('xr-one','ready')]); render();
      assert.match(nodes['peer-details'].innerHTML,/xr-one/);
      assert.match(nodes['peer-details'].innerHTML,/>ready</);
    """)


def test_late_failed_poll_cannot_clear_a_newer_successful_snapshot():
    run_map("""
      let failOld; fetch=()=>new Promise((resolve,reject)=>{failOld=reject});
      const old=poll();
      fetch=async()=>({ok:true,json:async()=>snapshot([peer('xr-two')])});
      await poll(); failOld(Error('older request failed')); await old;
      assert.equal(DATA.images[0].peers[0].device_id,'xr-two');
    """)


def test_swarm_preserves_image_identity_and_separates_devices():
    devices = {"one": {"current_image_id": "os", "stage_state": "ready", "staged_image_ids": ["os"]},
               "two": {"current_image_id": "os", "stage_state": "staging", "staged_image_ids": []}}
    observation = {"schema": "v2", "image_id": "other", "obs_state": "observed",
                   "observed_received_at": 95, "valid": True, "aria": {"receive_bps": 123}}
    report = {"v": 2, "image_id": "other", "event": "staging-complete"}
    hub = telemetry.Telemetry(device_info=lambda: devices,
        images_info=lambda: {"os": {"info_hash_hex": "abc", "filename": "os.iso"}},
        live_info=lambda: {"samples": {"one": observation}},
        reports_info=lambda: {"one": [report]})
    for name in devices:
        hub.registry.announce("abc", name, "192.0.2.1", 6881, left=0, now=100,
                              principal=auth.Principal("device", name))
    image = hub.swarm_snapshot(now=100)["images"][0]
    assert image["image_id"] == "os"
    peers = {p["device_id"]: p for p in image["peers"]}
    assert peers["one"]["stage_state"] == "ready"
    assert peers["two"]["stage_state"] == "staging"
    assert peers["one"]["device_observation"]["image_id"] == "other"
    assert peers["one"]["latest_report"]["image_id"] == "other"
    assert "device_observation" not in peers["two"]


def test_shared_nat_ip_does_not_duplicate_one_devices_measured_send_rate():
    hub = telemetry.Telemetry()
    for name, port in (("one", 6881), ("two", 6882)):
        hub.registry.announce("abc", name, "192.0.2.1", port, left=100, now=100,
                              principal=auth.Principal("device", name))
    hub._torrent_observed_at = 100
    hub._peer_up = {"abc": {("192.0.2.1", 50000): 123}}
    peers = hub.swarm_snapshot(now=100)["images"][0]["peers"]
    assert all("server_observation" not in p for p in peers)
    # The origin connected to an unambiguous advertised listen endpoint.
    hub._peer_up = {"abc": {("192.0.2.1", 6882): 321}}
    peers = {p["device_id"]: p for p in hub.swarm_snapshot(now=100)["images"][0]["peers"]}
    assert "server_observation" not in peers["one"]
    assert peers["two"]["server_observation"]["peer"]["send_bps"] == 321


def test_shared_exact_endpoint_also_requires_unique_participant():
    hub = telemetry.Telemetry()
    for name in ("one", "two"):
        hub.registry.announce("abc", name, "192.0.2.1", 6881, left=100, now=100,
                              principal=auth.Principal("device", name))
    hub._torrent_observed_at = 100
    hub._peer_up = {"abc": {("192.0.2.1", 6881): 123}}
    assert all("server_observation" not in p
               for p in hub.swarm_snapshot(now=100)["images"][0]["peers"])


def test_two_aria_clients_on_one_device_do_not_duplicate_address_rate():
    hub = telemetry.Telemetry()
    for peer, port in (("aria-old", 6881), ("aria-new", 6882)):
        hub.registry.announce("abc", peer, "192.0.2.1", port, left=100, now=100,
                              principal=auth.Principal("device", "one"))
    hub._torrent_observed_at = 100
    hub._peer_up = {"abc": {("192.0.2.1", 50000): 123}}
    assert all("server_observation" not in p
               for p in hub.swarm_snapshot(now=100)["images"][0]["peers"])
