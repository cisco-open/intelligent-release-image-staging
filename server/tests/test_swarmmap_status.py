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
function peer(id,state='staging') { return {device_id:id,ip:id,port:6881,_hash:'a'.repeat(40),_img:'os.iso',_image_id:'os',
  tracker:{principal_type:'device',principal_id:id,role:state==='ready'?'seeder':'leecher',left:state==='ready'?0:50,progress:state==='ready'?1:.5},
  device_observation:{obs_state:'observed',stale:false},current_image_id:'os',stage_state:state,
  staged_image_ids:state==='ready'?['os']:[],errored_image_ids:[]}; }
function snapshot(peers) { return {now:100,images:[{image:'os.iso',image_id:'os',info_hash:'a'.repeat(40),peers}]}; }
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


CONTROL_SETUP = r'''
  const p=peer('d1'); DATA=snapshot([p]); selected=p;drawerGen=1;drawer.classList.add('open');
  for(const id of ['save-peer-interval','peer-interval-status','peer-interval','review-peer-interval','pullbtn','pullstatus','review-pull','repbox'])nodes[id]=new Element(id);
  nodes['peer-interval'].value='10';CSRF='fixture-only';
  const response=(body,status=200)=>({status,ok:status>=200&&status<300,json:async()=>body});
  const reply=(dry_run,over={})=>({ok:true,device_id:'d1',requested_interval_s:10,revision:8,candidate_revision:8,dry_run,requires_confirmation:false,confirm_token:null,...over});
'''


@pytest.mark.parametrize("bad", ["{device_id:'other'}", "{requested_interval_s:60}",
                                  "{revision:7}", "{dry_run:false}", "{ok:false}"])
def test_interval_mismatched_preview_never_commits(bad):
    run_map(CONTROL_SETUP + f'''
      let writes=0;fetch=async(url)=>{{if(url.endsWith('peer-policy'))return response({{revision:7}});writes++;return response(reply(true,{bad}));}};
      await savePeerInterval(p,1);
      assert.equal(writes,1);assert.equal(intervalActions.get('d1').unknown,true);
      assert.doesNotMatch(nodes['peer-interval-status'].textContent,/^Saved/);
    ''')


@pytest.mark.parametrize("bad", ["{device_id:'other'}", "{requested_interval_s:60}",
                                  "{revision:7}", "{dry_run:true}", "{ok:false}"])
def test_interval_mismatched_commit_requires_explicit_review(bad):
    run_map(CONTROL_SETUP + f'''
      let writes=0;fetch=async(url)=>{{if(url.endsWith('effective-qos'))return response({{revision:8,device_id:'d1',degraded:false,fail_closed:false,qos:{{peer_telemetry_interval_s:{{value:10}}}}}});if(url.endsWith('peer-policy'))return response({{revision:7}});writes++;return response(reply(url.includes('?'),url.includes('?')?{{}}:{bad}));}};
      await savePeerInterval(p,1);await savePeerInterval(p,1);
      assert.equal(writes,2);assert.equal(intervalActions.get('d1').unknown,true);
      await reviewPeerInterval(p,1);assert.equal(intervalActions.get('d1').unknown,false);
      assert.match(nodes['peer-interval-status'].textContent,/Current requested interval: 10/);
    ''')


@pytest.mark.parametrize("hide", ["document.hidden=true", "hostPaused=true;stopMapReads()", "paused=true;stopMapReads()", "DATA=snapshot([])", "++drawerGen"])
def test_interval_hidden_or_gone_preflight_never_commits(hide):
    run_map(CONTROL_SETUP + f'''
      let writes=0;fetch=async(url)=>{{if(url.endsWith('peer-policy'))return response({{revision:7}});writes++;{hide};return response(reply(true));}};
      await savePeerInterval(p,1);assert.equal(writes,1);assert.equal(intervalActions.get('d1').busy,false);
    ''')


def test_interval_pending_lock_survives_reopened_drawer_and_finishes_once():
    run_map(CONTROL_SETUP + '''
      let release,writes=0;fetch=async(url)=>{if(url.endsWith('peer-policy'))return response({revision:7});writes++;if(url.includes('?'))return response(reply(true));return new Promise(resolve=>release=()=>resolve(response(reply(false))));};
      const first=savePeerInterval(p,1);while(!release)await Promise.resolve();
      ++drawerGen;await savePeerInterval(p,2);assert.equal(writes,2);
      release();await first;assert.equal(intervalActions.get('d1').busy,false);
      assert.match(intervalActions.get('d1').message,/^Saved/);
    ''')


@pytest.mark.parametrize("accept", [True, False])
def test_interval_required_confirmation_is_bound_to_reviewed_intent(accept):
    run_map(CONTROL_SETUP + f'''
      let writes=0,prompts=[];window.confirm=message=>{{prompts.push(message);return {str(accept).lower()};}};
      fetch=async(url)=>{{if(url.endsWith('peer-policy'))return response({{revision:7}});writes++;return response(reply(url.includes('?'),{{requires_confirmation:true,confirm_token:'reviewed-intent'}}));}};
      await savePeerInterval(p,1);assert.equal(prompts.length,1);
      assert.match(prompts[0],/d1 to 10 seconds/);assert.match(prompts[0],/revision 7 will become 8/);
      assert.equal(writes,{2 if accept else 1});assert.equal(intervalActions.get('d1').busy,false);
      assert.equal(intervalActions.get('d1').unknown,false);
      assert.match(intervalActions.get('d1').message,/{'^Saved' if accept else 'cancelled'}/);
    ''')


@pytest.mark.parametrize("changed", ["hostPaused=true;stopMapReads()", "document.hidden=true", "++drawerGen", "DATA=snapshot([])"])
def test_interval_confirmation_rechecks_visibility_and_identity_before_commit(changed):
    run_map(CONTROL_SETUP + f'''
      let writes=0;window.confirm=()=>{{{changed};return true;}};
      fetch=async(url)=>{{if(url.endsWith('peer-policy'))return response({{revision:7}});writes++;return response(reply(true,{{requires_confirmation:true,confirm_token:'reviewed-intent'}}));}};
      await savePeerInterval(p,1);assert.equal(writes,1);assert.equal(intervalActions.get('d1').busy,false);
      assert.doesNotMatch(intervalActions.get('d1').message,/^Saved/);
    ''')


def test_pull_matches_request_identity_not_clock_or_unrelated_completion():
    run_map(CONTROL_SETUP + '''
      const request={request_id:'a'.repeat(32),requested_at:100,expires_at:700};
      const action=actionState(pullActions,'d1');action.request=request;
      let reports=[{schema:'v2',event:'staging-complete',report_id:'b'.repeat(32),report_request_id:null,received_at:9999999999}];
      let pending=request;fetch=async()=>response({device_id:'d1',observed_at:102,pending_request:pending,reports});
      assert.equal(await readPull(p,1,controlEpoch,action,false),false);assert.equal(action.request.request_id,request.request_id);
      reports.push({schema:'v2',event:'pull',report_id:'c'.repeat(32),report_request_id:'d'.repeat(32),received_at:103});
      assert.equal(await readPull(p,1,controlEpoch,action,false),false);
      reports.push({schema:'v2',event:'pull',report_id:'e'.repeat(32),report_request_id:request.request_id,received_at:100});
      pending=null;
      assert.equal(await readPull(p,1,controlEpoch,action,false),true);assert.equal(action.request,null);
      assert.match(action.message,/Matching report received/);
    ''')


def test_pull_completed_request_preserves_a_newer_pending_directive():
    run_map(CONTROL_SETUP + '''
      const action=actionState(pullActions,'d1');action.request={request_id:'a'.repeat(32),requested_at:100,expires_at:700};
      const next={request_id:'b'.repeat(32),requested_at:101,expires_at:701};
      fetch=async()=>response({device_id:'d1',observed_at:102,pending_request:next,reports:[
        {schema:'v2',event:'pull',report_id:'c'.repeat(32),report_request_id:'a'.repeat(32)}]});
      assert.equal(await readPull(p,1,controlEpoch,action,false),true);refreshControlState();
      assert.equal(action.request.request_id,next.request_id);assert.equal(nodes.pullbtn.disabled,true);
      assert.match(action.message,/still pending/);
    ''')


def test_pull_identity_fields_reject_regex_coercion():
    run_map(CONTROL_SETUP + '''
      assert.equal(validDirective({request_id:['a'.repeat(32)],requested_at:100,expires_at:700}),false);
      const action=actionState(pullActions,'d1');action.request={request_id:'a'.repeat(32),requested_at:100,expires_at:700};
      fetch=async()=>response({device_id:'d1',observed_at:102,pending_request:null,reports:[
        {schema:'v2',event:'pull',report_id:['c'.repeat(32)],report_request_id:'a'.repeat(32)}]});
      assert.equal(await readPull(p,1,controlEpoch,action,false),false);
    ''')


@pytest.mark.parametrize("body", ["{ok:false}", "{ok:true,device_id:'other',request_id:'a'.repeat(32),requested_at:100,expires_at:700}", "{ok:true,device_id:'d1',request_id:'bad',requested_at:100,expires_at:700}"])
def test_pull_malformed_acceptance_is_not_replayed(body):
    run_map(CONTROL_SETUP + f'''
      let writes=0;fetch=async()=>{{writes++;return response({body});}};
      await requestPull(p,1);await requestPull(p,1);assert.equal(writes,1);
      assert.equal(pullActions.get('d1').unknown,true);
      fetch=async()=>response({{device_id:'d1',observed_at:100,pending_request:null,reports:[]}});
      await reviewPull(p,1);assert.equal(pullActions.get('d1').unknown,false);
      assert.doesNotMatch(pullActions.get('d1').message,/Matching report received/);
    ''')


def test_peer_arrows_have_direction_provenance_and_image_scope():
    run_map("""
      DATA=snapshot([peer('xr-one'),peer('xr-two')]);
      DATA.images[0].peer_edges=[{source_device_id:'xr-one',target_device_id:'xr-two',
        reporter_device_id:'xr-two',rate_field:'receive_bps',bytes_per_second:123,
        identity_basis:'unique_tracker_address',received_at:95,valid_for_s:120}];
      render();
      assert.equal(freshPeerEdges().length,1);
      assert.match(peerConnectionDetails(allPeers()[0]),/xr-one → xr-two/);
      assert.match(peerConnectionDetails(allPeers()[0]),/reported by xr-two/);
      const scene=svg.children[1],paths=scene.children.filter(x=>x.attrs.class==='edge peer-transfer');
      assert.equal(paths.length,1); assert.equal(paths[0].attrs['marker-end'],'url(#peer-arrow)');
      assert.match(paths[0].attrs['aria-label'],/xr-one → xr-two/);
      curHash='another'; assert.equal(freshPeerEdges().length,0);
      curHash='all'; query='xr-one';render();
      assert.equal(svg.children[1].children.filter(x=>x.attrs.class==='edge peer-transfer').length,0);
      query='';DATA.now=216;render();assert.equal(freshPeerEdges().length,0);
    """)


def test_cached_peer_arrows_age_while_map_polling_is_paused():
    run_map("""
      DATA=snapshot([peer('xr-one'),peer('xr-two')]);
      DATA.images[0].peer_edges=[{source_device_id:'xr-one',target_device_id:'xr-two',
        bytes_per_second:1,received_at:100,valid_for_s:120}];
      lastUpdated=Date.now()/1000-121;paused=true;
      assert.equal(freshPeerEdges().length,0);
    """)


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


@pytest.mark.parametrize("bad", ["{}", "{now:100,images:{}}", "{now:100,images:[null]}",
    "{...snapshot([]),now:null}", "snapshot([{}])", "snapshot([{tracker:{principal_type:'unknown'}}])",
    "snapshot([{...peer('d1'),staged_image_ids:{}}])",
    "snapshot([{...peer('d1'),device_observation:{obs_state:7}}])",
    "{...snapshot([]),peers_offset:1}"])
def test_malformed_map_snapshot_is_unavailable_then_recovers(bad):
    run_map(f'''
      fetch=async()=>({{ok:true,json:async()=>({bad})}});await poll();
      assert.equal(DATA,null);assert.equal(loadFailed,true);
      assert.match(empty.textContent,/unavailable/);
      fetch=async()=>({{ok:true,json:async()=>snapshot([peer('d1')])}});await poll();
      assert.equal(DATA.images[0].peers[0].device_id,'d1');assert.equal(loadFailed,false);
    ''')


def test_historical_report_read_cannot_overwrite_newer_review():
    run_map(CONTROL_SETUP + '''
      let release;fetch=async()=>new Promise(resolve=>release=()=>resolve(response({device_id:'d1',reports:[{image_id:'old',peers:[]}]})));
      const old=refreshDrawerReport(p,1);while(!release)await Promise.resolve();
      fetch=async()=>response({device_id:'d1',observed_at:100,pending_request:null,reports:[{image_id:'new',peers:[]}]});
      await reviewPull(p,1);release();await old;
      assert.match(nodes.repbox.innerHTML,/new/);assert.doesNotMatch(nodes.repbox.innerHTML,/old/);
    ''')


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


def test_node_caption_carries_the_reported_model_and_never_repeats_an_ip_identity():
    """An IOS-XR router is onboarded by IP, announces from that same IP (the
    appmgr container uses host networking) and, like every platform, reports
    a model but no hostname in its heartbeat. The node caption is therefore
    the device id plus the reported model; the table row repeats the announce
    IP only when it differs from the id; a legacy peer gets neither."""
    run_map("""
      const xr=peer('100.90.170.81','ready'); xr.model='8000';
      const c8k=peer('Iris-c8kv-104','ready'); c8k.ip='100.90.171.14'; c8k.model='C8000V';
      const legacy={ip:'198.51.100.7',port:6881,_hash:'hash-os',_img:'os.iso',_image_id:'os',device_id:null,
        model:'leaked',tracker:{principal_type:'legacy',participant_class:'legacy_unattributed',role:'leecher'}};
      DATA=snapshot([xr,c8k,legacy]); render();
      const scene=nodes.svg.children.find(c=>c.attrs.id==='scene');
      const captions=Object.fromEntries(scene.children.filter(c=>c.attrs.class==='node')
        .map(g=>[g.attrs['aria-label'],g.children.filter(t=>t.attrs.class==='small').map(t=>t.textContent)]));
      assert.deepEqual(captions['Open 100.90.170.81 (8000) details'],['100.90.170.81','8000']);
      assert.deepEqual(captions['Open Iris-c8kv-104 (C8000V) details'],['Iris-c8kv-104','C8000V']);
      assert.deepEqual(captions['Open Legacy unattributed peer details'],['Legacy unattributed peer']);
      const rows=nodes.tbody.children.map(tr=>tr.children[0].children[0].textContent).sort();
      assert.deepEqual(rows,['100.90.170.81','Iris-c8kv-104 — 100.90.171.14','Legacy unattributed peer — 198.51.100.7']);
      assert.match(peerDetails(xr),/<h2>100\\.90\\.170\\.81<\\/h2><p class="sub">Model: 8000<\\/p><p class="sub">Announce IP: 100\\.90\\.170\\.81<\\/p>/);
      assert.doesNotMatch(peerDetails(legacy),/Model:/);
    """)


def test_image_labels_are_the_catalog_filename_once_for_every_platform():
    """An IOS-XR image id is its whole filename (publish.derive_id strips only
    .SPA.bin/.bin), an XE id is the stem: the selector and the table show the
    catalog filename once either way -- never an info hash, never an empty
    label, never the id repeated behind the name."""
    run_map("""
      DATA={now:100,images:[
        {image:'8000-x64-26.2.1.iso',image_id:'8000-x64-26.2.1.iso',info_hash:'253b',peers:[peer('100.90.170.81','ready')]},
        {image:'cat9k_iosxe.26.01.01.SPA.bin',image_id:'cat9k_iosxe.26.01.01',info_hash:'c9fd',peers:[peer('100.92.9.129','ready')]}]};
      render();
      assert.deepEqual(nodes.imgsel.children.map(o=>o.label),['All images','8000-x64-26.2.1.iso','cat9k_iosxe.26.01.01.SPA.bin']);
      const byName=Object.fromEntries(nodes.tbody.children.map(tr=>[tr.children[0].children[0].textContent,tr.children[1].textContent]));
      assert.deepEqual(byName,{'100.90.170.81':'8000-x64-26.2.1.iso','100.92.9.129':'cat9k_iosxe.26.01.01.SPA.bin'});
      for(const p of allPeers()) assert.match(peerDetails(p),new RegExp('<dt>Image</dt><dd>'+p._img+'</dd>'));
    """)
