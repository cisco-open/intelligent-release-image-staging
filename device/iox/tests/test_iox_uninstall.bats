#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  export DEVICE_IP=192.0.2.10 DEVICE_USER=u DEVICE_PASS=p VLAN=666
  UNINSTALL="${IOX_RECIPE_ROOT:-$BATS_TEST_DIRNAME/..}/uninstall.sh"
}
@test "dry-run exits 0" {
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "stale NETWORK_ATTACHMENT without MANAGEMENT_TYPE aborts; a normal env is unaffected" {
  run env -u MANAGEMENT_TYPE NETWORK_ATTACHMENT=inband bash "$UNINSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE"* ]] || return 1
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "dry-run tears the app down stop -> deactivate -> uninstall" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"app-hosting stop appid iris"* ]] && \
  [[ "$output" == *"app-hosting deactivate appid iris"* ]] && \
  [[ "$output" == *"app-hosting uninstall appid iris"* ]]
}

@test "dry-run removes the app-hosting appid config" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no app-hosting appid iris"* ]]
}

@test "dry-run removes the IRIS VLAN and SVI" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no interface Vlan666"* ]] && [[ "$output" == *"no vlan 666"* ]]
}

@test "dry-run removes any runtime EEM applets (no-op if absent)" {
  # the shared agent may leave IRIS-COPYROOT and the on-demand low-space
  # reclaim applets (IRIS-RECLAIM / IRIS-RECLAIM-BUNDLE) in running-config
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no event manager applet IRIS-COPYROOT"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-AGENT"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-RECLAIM"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-RECLAIM-BUNDLE"* ]]
}

@test "dry-run removes the PKI trustpoint with its yes confirm" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no ip http client secure-trustpoint IRIS"* ]] && \
  [[ "$output" == *$'no crypto pki trustpoint IRIS\nyes'* ]]
}

@test "dry-run deletes the staged app package and runtime certificate source" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"delete /force flash:iris-arm64.tar"* ]] && \
  [[ "$output" == *"delete /force flash:iris-catalog.pem"* ]]
}

@test "dry-run leaves generic config and the sdflash image in place" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"no iox"* ]] && \
  [[ "$output" != *"no ip scp server"* ]] && \
  [[ "$output" != *"delete /force sdflash:"* ]]
}

@test "dry-run persists successful IOx cleanup" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"copy running-config startup-config"* ]]
}

@test "force dry-run never claims or emits a configuration save" {
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"copy running-config startup-config"* ]]
  [[ "$output" != *"verify cleanup and save"* ]]
}

@test "dry-run rejects newline injection in rendered cleanup paths" {
  local name
  for name in PKG PKG_FS TARGET_FS SHARE_IOS_PATH; do
    run env "$name=safe
reload" bash "$UNINSTALL" --dry-run
    [ "$status" -ne 0 ] || { echo "$name unexpectedly accepted"; return 1; }
    [[ "$output" != *$'\nreload\n'* ]]
  done
}

@test "custom VLAN and PKG_FS flow into the removal" {
  VLAN=42 PKG_FS=sdflash: run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no interface Vlan42"* ]] && \
  [[ "$output" == *"delete /force sdflash:iris-arm64.tar"* ]]
}

@test "inband dry-run removes only the app footprint" {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"no app-hosting appid iris"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-COPYROOT"* ]]
}

@test "inband dry-run keeps the existing VLAN/SVI but clears IRIS-named config" {
  # "Operator-owned" is the VLAN and its SVI -- network IRIS merely configured,
  # which no deployment record proves it created. The IRISQ discriminator and
  # the IRIS PKI trustpoint carry IRIS's own name, so a teardown clears them
  # in every mode: leaving them behind is what made a "clean" device refuse
  # the next onboard on an artifact we put there ourselves.
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"no vlan "* ]] || return 1
  [[ "$output" != *"no interface Vlan"* ]] || return 1
  [[ "$output" == *"no crypto pki trustpoint IRIS"* ]] || return 1
  [[ "$output" == *"no logging discriminator IRISQ"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "dry-run with SHARE_IOS_PATH removes only iris-prefixed share files" {
  SHARE_IOS_PATH=usbflash1:iox_host_data_share run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"delete /force usbflash1:iox_host_data_share/iris-staged.bin"* ]] && \
  [[ "$output" == *"delete /force usbflash1:iox_host_data_share/iris-probe.txt"* ]] && \
  [[ "$output" == *"delete /force /recursive usbflash1:iox_host_data_share/iris"* ]] && \
  [[ "$output" != *"delete /force /recursive usbflash1:iox_host_data_share
"* ]]
}

@test "dry-run without SHARE_IOS_PATH never touches the CAF share" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"iox_host_data_share"* ]]
}

@test "dry-run removes the scp-push staging dir under guest-share" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"delete /force /recursive sdflash:guest-share/iris"* ]]
}

@test "dry-run honors TARGET_FS for the staging dir" {
  TARGET_FS=flash: run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"delete /force /recursive flash:guest-share/iris"* ]]
}

@test "dry-run never deletes the guest-share root itself" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"delete /force /recursive sdflash:guest-share"$'\n'* ]] && \
  [[ "$output" != *"delete /force sdflash:guest-share"$'\n'* ]]
}

@test "dry-run verification mentions the staging dir" {
  run bash "$UNINSTALL" --dry-run
  [[ "$output" == *"guest-share/iris"* ]]
}

@test "force dry-run keeps the operator VLAN but clears IRIS-named config" {
  # "Operator-owned" is the VLAN and its SVI -- network IRIS merely configured,
  # which no deployment record proves it created. The IRISQ discriminator and
  # the IRIS PKI trustpoint carry IRIS's own name, so a teardown clears them
  # in every mode: leaving them behind is what made a "clean" device refuse
  # the next onboard on an artifact we put there ourselves.
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [[ "$output" != *"no interface Vlan"* ]] || return 1
  [[ "$output" != *"no vlan 666"* ]] || return 1
  [[ "$output" == *"no crypto pki trustpoint IRIS"* ]] || return 1
  [[ "$output" == *"no logging discriminator IRISQ"* ]] || return 1
  [ "$status" -eq 0 ]
}

@test "non-force dry-run DOES emit the operator-owned teardown commands" {
  # proves the gate actually gates: without IRIS_FORCE_AGENT_ONLY, the same
  # routed default undeploy still removes the VLAN/SVI and trustpoint
  run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"no interface Vlan666"* ]] && \
  [[ "$output" == *"no vlan 666"* ]] && \
  [[ "$output" == *"no crypto pki trustpoint IRIS"* ]]
}

@test "force dry-run still removes the full IRIS agent footprint" {
  IRIS_FORCE_AGENT_ONLY=1 run bash "$UNINSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"app-hosting stop appid iris"* ]] && \
  [[ "$output" == *"app-hosting deactivate appid iris"* ]] && \
  [[ "$output" == *"app-hosting uninstall appid iris"* ]] && \
  [[ "$output" == *"no app-hosting appid iris"* ]] && \
  [[ "$output" == *"no event manager applet IRIS-COPYROOT"* ]] && \
  [[ "$output" == *"delete /force flash:iris-arm64.tar"* ]] && \
  [[ "$output" == *"delete /force /recursive sdflash:guest-share/iris"* ]]
}

# The controller peer is inline and uses a fresh private socketpair for each
# invocation. Direct device tools are refusal sentinels, never success stubs.
# The fixture validates every v1 key, binding, sequence and closed operation.
# Live identity discovery belongs to the Python controller suite. The two
# identity-refusal scenarios here prove that a recipe lacking a ready frame
# cannot fall back to direct device commands or environment authority.
_iox_fixture_setup() {
  STUBDIR="$BATS_TEST_TMPDIR/private-controller"
  mkdir -p "$STUBDIR/device/iox" "$STUBDIR/lab" "$STUBDIR/bin" \
    "$STUBDIR/artifacts" "$STUBDIR/home" "$STUBDIR/authority"
  chmod 700 "$STUBDIR" "$STUBDIR/home" "$STUBDIR/authority"
  export IOX_DIRECT_LOG="$STUBDIR/direct-transport.log"
  export IOX_REQUEST_LOG="$STUBDIR/requests.jsonl"
  : > "$IOX_DIRECT_LOG"
  : > "$IOX_REQUEST_LOG"
  cat > "$STUBDIR/lab/device-run.sh" <<'GUARD'
#!/usr/bin/env bash
printf '%s\n' 'forbidden direct device transport' >> "$IOX_DIRECT_LOG"
exit 96
GUARD
  chmod 700 "$STUBDIR/lab/device-run.sh"
  for binary in ssh scp sshpass; do
    cp "$STUBDIR/lab/device-run.sh" "$STUBDIR/bin/$binary"
  done
  cat > "$STUBDIR/lab/iris-ssh-policy.sh" <<'GUARD'
iris_ssh_policy() { printf '%s\n' 'forbidden recipe SSH policy' >> "$IOX_DIRECT_LOG"; return 96; }
iris_ssh_cleanup() { :; }
GUARD
  ln -s "${IOX_RECIPE_ROOT:-$BATS_TEST_DIRNAME/..}/install.sh" "$STUBDIR/device/iox/install.sh"
  ln -s "${IOX_RECIPE_ROOT:-$BATS_TEST_DIRNAME/..}/uninstall.sh" "$STUBDIR/device/iox/uninstall.sh"
  ln -s "$BATS_TEST_DIRNAME/../../../server" "$STUBDIR/server"
  python3 - "$STUBDIR/artifacts/iris-arm64.tar" <<'TAR'
import io,sys,tarfile
with tarfile.open(sys.argv[1], 'w', format=tarfile.USTAR_FORMAT) as archive:
    member=tarfile.TarInfo('package.yaml')
    data=b'descriptor-schema-version: "2.7"\n'
    member.size=len(data)
    archive.addfile(member,io.BytesIO(data))
TAR
  export IRIS_CRT_FILE="$STUBDIR/artifacts/iris-catalog.pem"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$STUBDIR/catalog.key" -out "$IRIS_CRT_FILE" \
    -days 1 -subj '/CN=private-test-fixture' >/dev/null 2>&1
  printf '%s\n' 'authority-owner-data' > "$STUBDIR/authority/owner"
  export PATH="$STUBDIR/bin:$PATH" HOME="$STUBDIR/home" TMPDIR="$STUBDIR"
  export IRIS_ARTIFACTS_DIR="$STUBDIR/artifacts" IRIS_STATE="$STUBDIR/authority"
  export DEVICE_IP=192.0.2.10 DEVICE_USER=fixture-user DEVICE_PASS=fixture-login-secret
  export DEVICE_ENABLE=fixture-enable-secret DEVICE_SSH_PASS=fixture-self-secret
  export CATALOG_TOKEN=fixture-catalog-secret DEVICE_ID=fixture-device STAGE_HOST=192.0.2.2
  export VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10
  export MODEL=IE-3400-8T2S EXPECTED_DEVICE_IDENTITY=ENVIRONMENT-MUST-NOT-AUTHORIZE
  export INSTALL_TIMEOUT=2 ACTIVATE_TIMEOUT=2 START_TIMEOUT=2 STATE_POLL=1
}

_iox_controller_run() {
  local action="$1" scenario="${2:-success}" mode="${3:-recorded}"
  python3 - "$STUBDIR/device/iox/$action.sh" "$action" "$scenario" "$mode" <<'CONTROLLER'
import base64,ctypes,fcntl,hashlib,json,os,selectors,signal,socket,struct,subprocess,sys,time
script,action,scenario,mode=sys.argv[1:]
mode='none' if action=='install' else mode
attempt='a'*32
board='CONTROLLER-LIVE-BOARD'
record='controller-record' if mode!='force_agent_only' else None
transaction='b'*32 if action=='install' else None
revision=0 if action=='install' else None
phase='observed' if action=='install' else None
wrapper=hashlib.sha256(open(os.path.join(os.environ['IRIS_ARTIFACTS_DIR'],'iris-arm64.tar'),'rb').read()).hexdigest() if action=='install' else None
trace=open(os.environ['IOX_REQUEST_LOG'],'a')
control,recipe=socket.socketpair()
control.setblocking(False)
selector=selectors.DefaultSelector()
selector.register(control,selectors.EVENT_READ,'control')
env=dict(os.environ)
env['IRIS_IOX_CONTROL_FD']=str(recipe.fileno())
env['IRIS_IOX_RECORD_ID']='environment-forged-record'
env['IRIS_IOX_TRANSACTION_ID']='e'*32
env['IRIS_IOX_REVISION']='999'
env['IRIS_IOX_BOARD_IDENTITY']='ENVIRONMENT-FORGED-BOARD'
if mode=='force_agent_only':
    env['IRIS_FORCE_AGENT_ONLY']='1'
    env.pop('VLAN',None)
    env.pop('INBAND_VLAN',None)
if scenario=='missing_environment_identity':
    env.pop('EXPECTED_DEVICE_IDENTITY',None)
# The fixture itself is a subreaper, and never leaves shell/helper descendants.
libc=ctypes.CDLL(None,use_errno=True)
assert libc.prctl(36,1,0,0,0)==0
child=subprocess.Popen(['/bin/bash',script],env=env,pass_fds=(recipe.fileno(),),
    stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
recipe.close()
fcntl.fcntl(child.stdout.fileno(),fcntl.F_SETFL,fcntl.fcntl(child.stdout.fileno(),fcntl.F_GETFL)|os.O_NONBLOCK)
selector.register(child.stdout,selectors.EVENT_READ,'output')
deadline=time.monotonic()+6
wire=bytearray()
output=bytearray()
sequence=1
finished=False
expected_exit=None
protocol_error=None
signal_sent=False
signal_case=scenario.split('_') if scenario.startswith(('group_', 'direct_')) else []
uploaded=False
remote_wrapper=False
remote_certificate=False
admitted=False
resolved=False
certificate=False
state='RUNNING' if scenario in ('routing_missing','preserve_existing') else ''
counts={}
last_ready=None


def frame(value):
    payload=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')
    assert 1<=len(payload)<=65536
    return struct.pack('!I',len(payload))+payload


def send(value):
    data=frame(value)
    control.setblocking(True)
    control.settimeout(max(0.01,deadline-time.monotonic()))
    control.sendall(data)
    control.setblocking(False)


def ready():
    global last_ready
    last_ready=dict(version=1,type='ready',next_sequence=sequence,attempt_id=attempt,
        action=action,teardown_mode=mode,record_id=record,transaction_id=transaction,
        expected_revision=revision,board_identity=board,wrapper_sha256=wrapper)
    outgoing=dict(last_ready)
    if scenario=='malformed_ready_key' and sequence==1:
        outgoing['unexpected']='fixture-login-secret'
    if scenario=='malformed_ready_tuple' and sequence==1:
        outgoing['transaction_id']='e'*32 if action=='uninstall' else None
    if scenario=='malformed_ready_revision' and sequence==2:
        outgoing['expected_revision']+=1
    send(outgoing)


def unique(pairs):
    result={}
    for key,value in pairs:
        assert key not in result,'duplicate JSON key'
        result[key]=value
    return result


def command_names():
    return set('iox_status app_list routing_prereq storage_prereq clock prepare_iox_scp configure_network mkdir_share app_stop app_deactivate app_uninstall remove_app_config configure_app app_install app_activate copy_certificate app_start save remove_wrapper remove_certificate cleanup_config cleanup_files cleanup_config_probe cleanup_stage_probe'.split())


def request(value):
    global sequence,finished,expected_exit,uploaded,admitted,resolved,certificate,state,revision,phase
    global signal_sent,remote_wrapper,remote_certificate
    keys=set('version sequence attempt_id action teardown_mode record_id transaction_id expected_revision board_identity wrapper_sha256 operation arguments'.split())
    assert set(value)==keys,'request is not the exact closed schema'
    assert type(value['sequence']) is int and value['sequence']==sequence
    assert type(value['version']) is int and value['version']==1
    for key in keys-set(('sequence','operation','arguments')):
        assert type(value[key]) is type(last_ready[key]) and value[key]==last_ready[key],'request replaced controller '+key
    operation=value['operation']
    arguments=value['arguments']
    assert type(arguments) is dict
    assert operation in ('command','upload_wrapper','upload_certificate','begin_install','deployed','cleanup','finish')
    name=operation
    if operation=='command':
        assert set(arguments)=={'name'} and arguments['name'] in command_names()
        name=arguments['name']
    elif operation=='cleanup':
        assert set(arguments)=={'reason','exit_intent'}
        assert arguments['reason'] in ('success','error','term','int','hup','cancel')
        assert arguments['exit_intent'] is None or type(arguments['exit_intent']) is int and 0<=arguments['exit_intent']<=255
    elif operation=='finish':
        assert set(arguments)=={'exit_intent'} and type(arguments['exit_intent']) is int and 0<=arguments['exit_intent']<=255
    else:
        assert arguments=={}
    if action=='uninstall':
        assert operation not in ('upload_wrapper','upload_certificate','begin_install','deployed')
        assert name not in ('app_install','app_activate','configure_app','configure_network','copy_certificate','app_start')
    trace.write(json.dumps(dict(event='request',request=value),sort_keys=True)+'\n')
    trace.flush()
    counts[name]=counts.get(name,0)+1
    assert sum(counts.values())<=128,'unbounded recipe requests'
    if scenario in ('signal_during_ipc','second_signal_during_cleanup') and not signal_sent:
        os.kill(child.pid,signal.SIGTERM)
        signal_sent=True
        time.sleep(0.05)
    elif scenario=='second_signal_during_cleanup' and operation=='cleanup':
        os.kill(child.pid,signal.SIGTERM)
        time.sleep(0.05)
    if signal_case:
        sender=os.killpg if signal_case[0]=='group' else os.kill
        number={'term':signal.SIGTERM,'int':signal.SIGINT,'hup':signal.SIGHUP}[signal_case[1]]
        if not signal_sent:
            sender(child.pid,number)
            signal_sent=True
            time.sleep(0.05)
        elif operation in ('cleanup','finish'):
            # Different later signals must not replace the first exit intent.
            sender(child.pid,signal.SIGHUP if number!=signal.SIGHUP else signal.SIGINT)
            time.sleep(0.05)
    code=0
    category=None
    detail=''
    stdout=''
    stderr=''
    returncode=0 if operation in ('command','upload_wrapper','upload_certificate') else None
    framing=True
    timed_out=False
    if scenario=='certificate_invalid' and sum(counts.values())==1:
        code,category,detail=2,None,'not a valid PEM certificate'
        returncode=None
    elif name=='routing_prereq':
        if scenario=='device_down':
            code,category,detail=4,'connection','PREREQ: could not verify ip routing'
            returncode=255
            framing=False
        elif scenario in ('routing_missing','preserve_existing'):
            stdout='show running-config | include no ip routing\nno ip routing\nDefault gateway is not set\n'
        else:
            stdout='show running-config | include no ip routing\nGateway of last resort is 192.0.2.1 to network 0.0.0.0\n'
    elif name=='storage_prereq':
        stdout='Filesystem: sdflash: (no IOx partition present)\n' if scenario=='no_partition' else 'IOx Partition Exists\n'
    elif name=='clock':
        stdout='% Clock is not set\n' if scenario=='unknown_clock' else '14:23:07.512 UTC Thu Aug 20 '+('2018' if scenario=='old_clock' else '2026')+'\n'
    elif name=='iox_status':
        stdout='IOx service (CAF) : Running\nDockerd : Running\n'
        if scenario=='caf_missing': stdout='Dockerd : Running\n'
        if scenario=='dockerd_missing': stdout='IOx service (CAF) : Running\n'
        if scenario in ('caf_missing','dockerd_missing') and counts[name]>=2:
            code,category,detail=4,'timeout','waiting for IOx services exceeded the controller deadline'
            timed_out=True
            framing=False
            returncode=None
    elif name=='app_list':
        stdout='App id State\n---------------------\n'+('iris '+state+'\n' if state else 'No App found\n')
        if scenario=='activation_timeout' and counts.get('app_activate') and counts[name]>=4:
            code,category,detail=4,'timeout','did not reach ACTIVATED within 2 seconds; Last observed state: DEPLOYED; Activation may still be running; retry onboarding'
            stderr='% Error: activation is still loading the app image\n'
            timed_out=True
            framing=False
            returncode=None
        if scenario in ('install_timeout','install_timeout_cleanup_rejected') and counts.get('app_install') and counts[name]>=4:
            code,category,detail=4,'timeout','did not reach DEPLOYED within 2 seconds'
            timed_out=True
            framing=False
            returncode=None
    elif name=='upload_wrapper':
        uploaded=True
        remote_wrapper=True
        if scenario=='upload_wrapper_failure':
            code,category,detail=4,'transport','fixture upload failed after creating remote file'
            returncode=1
    elif name=='upload_certificate': remote_certificate=True
    elif name=='begin_install':
        assert uploaded,'begin_install preceded bound upload'
        admitted=True
        revision+=1
        phase='unchanged' if scenario=='marker_present' else 'disabled_confirmed'
    elif name in ('app_stop','app_deactivate','app_uninstall','remove_app_config','configure_network','configure_app','app_install'):
        assert action=='uninstall' or admitted,'application mutation preceded begin_install'
        if name=='app_stop': state='STOPPED'
        if name=='app_deactivate': state='DEPLOYED'
        if name=='remove_app_config' and counts[name]>1 and scenario=='install_timeout_cleanup_rejected':
            code,category,detail=2,'rejected','repeated app configuration removal rejected by controller order'
            returncode=None
        elif name in ('app_uninstall','remove_app_config'): state=''
        if name=='app_install':
            state='INSTALLING' if scenario in ('install_timeout','install_timeout_cleanup_rejected') else 'DEPLOYED'
            stdout="Installing package for 'iris'.\n%IOX: application installation accepted\n"
    elif name=='deployed':
        assert state=='DEPLOYED' and admitted
        resolved=True
        revision+=1
        phase=('relinquished' if scenario=='deployed_relinquished' else 'restored') if phase!='unchanged' else phase
    elif name=='app_activate':
        assert admitted and resolved,'activation preceded restoration acknowledgement'
        if scenario!='activation_timeout': state='ACTIVATED'
        stdout='Application activation requested\n' if scenario=='activation_timeout' else 'Application activated\n'
    elif name=='copy_certificate':
        assert state=='ACTIVATED','certificate copied before activation'
        if scenario in ('certificate_copy_failure','copy_failure_cleanup_failure'):
            code,category,detail=4,'rejected','application data copy failed'
            stdout='% Error: application data unavailable\n'
        else:
            certificate=True
            stdout='Successfully copied file /flash/iris-catalog.pem to iris as iris-catalog.pem\n'
    elif name=='app_start':
        assert certificate and state=='ACTIVATED'
        state='RUNNING'
    elif name=='save': stdout='[OK]\n'
    elif name=='remove_wrapper': remote_wrapper=False
    elif name=='remove_certificate': remote_certificate=False
    elif name=='cleanup_config_probe':
        residues={
            'residue_log_bare':'logging discriminator IRISQ\n',
            'residue_log_buffered':'logging buffered discriminator IRISQ\n',
            'residue_log_console':'logging console discriminator IRISQ\n',
            'residue_log_monitor':'logging monitor discriminator IRISQ\n',
            'residue_app_row':'iris RUNNING\n',
            'residue_vlan':'interface Vlan666\n',
            'residue_l2_vlan':'vlan 666\n',
        }
        stdout=residues.get(scenario,'')
    elif name=='cleanup_stage_probe':
        residues={
            'residue_stage':'Directory of sdflash:/guest-share/iris\n',
            'residue_staged_file':'  12 -rw- 100 Sep 8 2026 iris-staged.bin\n',
            'residue_staged_part':'  13 -rw- 100 Sep 8 2026 iris-staged.bin.part\n',
            'residue_probe_file':'  14 -rw- 10 Sep 8 2026 iris-probe.txt\n',
            'residue_arm_wrapper':'  15 -rw- 100 Sep 8 2026 iris-arm64.tar\n',
            'residue_amd_wrapper':'  20 -rw- 100 Sep 8 2026 iris-amd64.tar\n',
            'residue_custom_wrapper':'  21 -rw- 100 Sep 8 2026 Custom.IOx_wrapper-1.2\n',
            'residue_short_wrapper':'  22 -rw- 100 Sep 8 2026 Z\n',
            'residue_max_wrapper':'  23 -rw- 100 Sep 8 2026 '+('a'*128)+'\n',
            'nonresidue_probe_output':'dir flash: | include iris-amd64.tar\n0 bytes available (1000 bytes used)\n',
            'nonresidue_overlong_wrapper':'  24 -rw- 100 Sep 8 2026 '+('a'*129)+'\n',
            'nonresidue_invalid_wrapper':'  25 -rw- 100 Sep 8 2026 bad;name.tar\n',
            'residue_ca_file':'  16 -rw- 100 Sep 8 2026 iris-ca.pem\n',
            'residue_catalog_file':'  17 -rw- 100 Sep 8 2026 iris-catalog.pem\n',
            'residue_transaction_wrapper':'  18 -rw- 100 Sep 8 2026 iris-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tar\n',
            'residue_share_directory':'Directory of usbflash1:iox_host_data_share/iris\n',
            'residue_share_entry':'  19 drwx 4096 Sep 8 2026 iris\n',
        }
        stdout=residues.get(scenario,'')
    elif name=='cleanup':
        if action=='install' and admitted and phase=='disabled_confirmed':
            revision+=1
            phase='restored'
            resolved=True
        if scenario in ('copy_failure_cleanup_failure','cleanup_failure'):
            code,category,detail=5,'journal_durability','fixture cleanup durability failure'
        if scenario=='completion_order': stdout='fixture cleanup acknowledged\n'
    elif name=='finish':
        if action=='install' and admitted and phase=='disabled_confirmed':
            revision+=1
            phase='restored'
            resolved=True
        if scenario in ('finish_failure','copy_failure_cleanup_failure'):
            code,category,detail=5,'journal_durability','fixture finish durability failure'
        if action=='install' and code==0:
            remote_wrapper=False
            remote_certificate=False
            trace.write(json.dumps(dict(event='artifact_cleanup',wrapper=False,certificate=False))+'\n')
            trace.flush()
        if scenario=='completion_order': stdout='fixture finish acknowledged\n'
        finished=True
    for stream,data in (('stdout',stdout),('stderr',stderr)):
        raw=data.encode('utf-8')
        assert len(raw)<=32768
        for index,start in enumerate(range(0,len(raw),4096)):
            send(dict(version=1,type='output',sequence=sequence,stream=stream,index=index,
                data_b64=base64.b64encode(raw[start:start+4096]).decode('ascii')))
    result=dict(version=1,type='result',sequence=sequence,ok=code==0,operation_code=code,
        revision=revision,phase=phase,returncode=returncode,timed_out=timed_out,
        stdout_truncated=False,stderr_truncated=False,framing_complete=framing,
        error_category=category,detail=detail,transcript_ref=None,
        recipe_returncode=None,recovery_code=None)
    if sum(counts.values())==1:
        if scenario=='malformed_success_timed_out': result['timed_out']=True
        if scenario=='malformed_success_framing': result['framing_complete']=False
        if scenario=='malformed_success_returncode': result['returncode']=7
        if scenario=='malformed_install_journal_none':
            result['revision']=None
            result['phase']=None
        if scenario=='malformed_install_phase': result['phase']='restored'
        if scenario=='malformed_uninstall_journal_half': result['revision']=0
    if signal_case and len(signal_case)==3 and signal_case[2]=='malformed':
        result['unexpected']='fixture-login-secret'
    if scenario=='malformed_response_key': result['unexpected']='fixture-login-secret'
    if scenario=='malformed_response_status': result['recipe_returncode']=0
    send(result)
    if scenario.endswith('_malformed') or scenario.startswith(('malformed_response','malformed_success','malformed_install_','malformed_uninstall_')):
        control.shutdown(socket.SHUT_WR)
        return
    if finished:
        expected_exit=arguments['exit_intent'] or code
        trace.write(json.dumps(dict(event='finish',exit_intent=arguments['exit_intent'],
            operation_code=code,expected_exit=arguments['exit_intent'] or code,state=state))+'\n')
        trace.flush()
    else:
        sequence+=1
        ready()

try:
    if scenario in ('identity_refused','identity_unknown'):
        control.shutdown(socket.SHUT_WR)
    else:
        ready()
    while time.monotonic()<deadline:
        for key,unused in selector.select(min(0.1,max(0,deadline-time.monotonic()))):
            if key.data=='output':
                data=os.read(child.stdout.fileno(),4096)
                if data:
                    output.extend(data)
                    assert len(output)<=65536,'unbounded recipe diagnostic output'
                else: selector.unregister(child.stdout)
            else:
                data=control.recv(4096)
                if not data:
                    selector.unregister(control)
                else:
                    assert not finished,'request after acknowledged finish'
                    wire.extend(data)
                    while len(wire)>=4:
                        length=struct.unpack('!I',wire[:4])[0]
                        assert 1<=length<=65536,'invalid frame length'
                        if len(wire)<4+length: break
                        payload=bytes(wire[4:4+length])
                        del wire[:4+length]
                        value=json.loads(payload.decode('utf-8'),object_pairs_hook=unique,
                            parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite JSON')))
                        request(value)
        if child.poll() is not None and not selector.get_map(): break
    else:
        raise AssertionError('bounded controller fixture deadline expired')
    assert not wire,'partial final request frame'
    if finished: assert child.returncode==expected_exit,'recipe exit differs from acknowledged finish'
    assert finished or scenario in ('identity_refused','identity_unknown') or scenario.startswith('malformed_') or scenario.endswith('_malformed'),'recipe exited without acknowledged finish'
except (AssertionError,ValueError,TypeError,OSError) as error:
    protocol_error=str(error)
finally:
    try: os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError: pass
    child.wait(timeout=1)
    reap_deadline=time.monotonic()+0.5
    while True:
        try:
            pid,unused=os.waitpid(-1,os.WNOHANG)
            if not pid:
                if time.monotonic()>=reap_deadline:
                    protocol_error='fixture descendant could not be reaped'
                    break
                time.sleep(0.005)
        except ChildProcessError: break
    control.close()
    selector.close()
    trace.close()
sys.stdout.write(output.decode('utf-8','replace'))
if protocol_error:
    sys.stdout.write('\ncontroller fixture: '+protocol_error+'\n')
    sys.exit(97)
sys.exit(child.returncode if child.returncode>=0 else 128-child.returncode)
CONTROLLER
}

_iox_assert_trace() {
  # A broken peer is a fixture failure, never the expected recipe refusal.
  [ "$status" -ne 97 ] || return 1
  [ "$status" -ne 124 ] || return 1
  python3 - "$IOX_REQUEST_LOG" "$@" <<'ASSERTIONS' || return 1
import json,sys
records=[json.loads(line) for line in open(sys.argv[1])]
requests=[row['request'] for row in records if row['event']=='request']
names=[row['arguments']['name'] if row['operation']=='command' else row['operation'] for row in requests]
check=sys.argv[2]
if check=='none':
    assert requests==[],names
elif check=='absent':
    assert not set(sys.argv[3:]).intersection(names),names
else:
    assert requests,'recipe did not use its controller channel'
    assert all(row['board_identity']=='CONTROLLER-LIVE-BOARD' for row in requests)
    assert [row['sequence'] for row in requests]==list(range(1,len(requests)+1))
    if check=='ordered':
        indices=[names.index(name) for name in sys.argv[3:]]
        assert indices==sorted(indices),(names,indices)
    elif check=='first_only':
        assert len(requests)==1,names
    elif check=='count':
        assert names.count(sys.argv[3])==int(sys.argv[4]),names
    elif check=='finish':
        finishes=[row for row in records if row['event']=='finish']
        assert len(finishes)==1 and names[-1]=='finish'
        assert finishes[0]['state']==sys.argv[3],finishes
    elif check=='mode':
        mode=sys.argv[3]
        assert all(row['teardown_mode']==mode for row in requests)
        for row in requests:
            assert row['transaction_id'] is None and row['wrapper_sha256'] is None and row['expected_revision'] is None
            assert row['record_id']==(None if mode=='force_agent_only' else 'controller-record')
    elif check=='preserve_primary':
        finish=[row for row in records if row['event']=='finish'][0]
        assert finish['exit_intent']!=0 and finish['expected_exit']==finish['exit_intent']
    elif check=='signal':
        expected=int(sys.argv[3])
        reason=sys.argv[4]
        assert names[-2:]==['cleanup','finish'],names
        assert names.count('cleanup')==names.count('finish')==1,names
        assert requests[-2]['arguments']=={'reason':reason,'exit_intent':expected},requests[-2]
        assert requests[-1]['arguments']=={'exit_intent':expected},requests[-1]
    elif check=='artifact_clean':
        clean=[row for row in records if row['event']=='artifact_cleanup']
        assert clean and clean[-1]['wrapper'] is False and clean[-1]['certificate'] is False,records
ASSERTIONS
  [ ! -s "$IOX_DIRECT_LOG" ]
}

@test "standalone dry-run needs no credentials controller authority or transport" {
  _iox_fixture_setup
  run env -u DEVICE_USER -u DEVICE_PASS -u DEVICE_SSH_PASS -u DEVICE_ENABLE \
    -u CATALOG_TOKEN -u ENABLE_SECRET -u SSHPASS -u IRIS_IOX_CONTROL_FD \
    -u EXPECTED_DEVICE_IDENTITY -u IRIS_FORCE_AGENT_ONLY \
    IRIS_STATE="$STUBDIR/authority/owner" \
    bash "$STUBDIR/device/iox/uninstall.sh" --dry-run
  [ "$status" -eq 0 ]
  [ ! -s "$IOX_DIRECT_LOG" ]
  [ ! -s "$IOX_REQUEST_LOG" ]
  [ "$(cat "$STUBDIR/authority/owner")" = authority-owner-data ]
  [ "$(find "$STUBDIR/authority" -mindepth 1 | wc -l)" -eq 1 ]
}

@test "environment authority cannot start the real uninstall recipe" {
  _iox_fixture_setup
  run env -u IRIS_IOX_CONTROL_FD IRIS_FORCE_AGENT_ONLY=1 \
    IRIS_IOX_RECORD_ID=environment-record \
    IRIS_IOX_TRANSACTION_ID=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
    IRIS_IOX_REVISION=999 timeout 6 bash "$STUBDIR/device/iox/uninstall.sh"
  [ "$status" -eq 2 ]
  [ ! -s "$IOX_DIRECT_LOG" ]
  [ ! -s "$IOX_REQUEST_LOG" ]
  [[ "$output" != *'fixture-login-secret'* ]]
}

@test "controller recorded teardown uses its bound board and record through finish" {
  _iox_fixture_setup
  run _iox_controller_run uninstall success recorded
  [ "$status" -eq 0 ]
  _iox_assert_trace mode recorded
  _iox_assert_trace ordered app_stop app_deactivate app_uninstall cleanup_config cleanup_files save finish
  _iox_assert_trace finish ''
}

@test "controller forced teardown needs no VLAN and still has a live board binding" {
  _iox_fixture_setup
  run _iox_controller_run uninstall success force_agent_only
  [ "$status" -eq 0 ]
  [[ "$output" != *'VLAN not set'* ]]
  _iox_assert_trace mode force_agent_only
  _iox_assert_trace ordered app_stop app_deactivate app_uninstall cleanup_config cleanup_files finish
  _iox_assert_trace absent upload_wrapper upload_certificate begin_install deployed app_install app_activate
}

@test "controller recorded teardown remains board-bound without EXPECTED_DEVICE_IDENTITY" {
  _iox_fixture_setup
  run _iox_controller_run uninstall missing_environment_identity recorded
  [ "$status" -eq 0 ]
  _iox_assert_trace mode recorded
  _iox_assert_trace ordered app_stop app_uninstall finish
}

@test "controller force authority ignores a forged environment identity and record" {
  _iox_fixture_setup
  run _iox_controller_run uninstall success force_agent_only
  [ "$status" -eq 0 ]
  _iox_assert_trace mode force_agent_only
  _iox_assert_trace finish ''
}

@test "controller identity mismatch refusal supplies no handoff or teardown authority" {
  _iox_fixture_setup
  run _iox_controller_run uninstall identity_refused recorded
  [ "$status" -ne 0 ]
  _iox_assert_trace none
}

@test "controller unreadable live identity also refuses forced teardown handoff" {
  _iox_fixture_setup
  run _iox_controller_run uninstall identity_unknown force_agent_only
  [ "$status" -ne 0 ]
  _iox_assert_trace none
}

@test "controller finish failure cannot be reported as successful uninstall" {
  _iox_fixture_setup
  run _iox_controller_run uninstall finish_failure recorded
  [ "$status" -eq 5 ]
  [[ "$output" != *'undeploy complete:'* ]]
  _iox_assert_trace finish ''
}

_assert_uninstall_residue_refused() {
  _iox_fixture_setup
  run _iox_controller_run uninstall "$1" recorded
  [ "$status" -ne 0 ]
  [ "$status" -ne 97 ]
  _iox_assert_trace absent save
  _iox_assert_trace count cleanup 1
  _iox_assert_trace count finish 1
}

@test "cleanup proof rejects a bare IRIS logging discriminator" {
  _assert_uninstall_residue_refused residue_log_bare
}

@test "cleanup proof rejects the buffered IRIS logging discriminator" {
  _assert_uninstall_residue_refused residue_log_buffered
}

@test "cleanup proof rejects the console IRIS logging discriminator" {
  _assert_uninstall_residue_refused residue_log_console
}

@test "cleanup proof rejects the monitor IRIS logging discriminator" {
  _assert_uninstall_residue_refused residue_log_monitor
}

@test "cleanup proof rejects a remaining iris application row" {
  _assert_uninstall_residue_refused residue_app_row
}

@test "cleanup proof rejects a remaining IRIS SVI" {
  _assert_uninstall_residue_refused residue_vlan
}

@test "cleanup proof rejects a remaining bound L2 VLAN" {
  _assert_uninstall_residue_refused residue_l2_vlan
}

@test "stage proof rejects a remaining guest-share iris directory" {
  _assert_uninstall_residue_refused residue_stage
}

@test "stage proof rejects iris-staged.bin" {
  _assert_uninstall_residue_refused residue_staged_file
}

@test "stage proof rejects iris-staged.bin.part" {
  _assert_uninstall_residue_refused residue_staged_part
}

@test "stage proof rejects iris-probe.txt" {
  _assert_uninstall_residue_refused residue_probe_file
}

@test "stage proof rejects iris-arm64.tar" {
  _assert_uninstall_residue_refused residue_arm_wrapper
}

@test "stage proof rejects iris-ca.pem" {
  _assert_uninstall_residue_refused residue_ca_file
}

@test "stage proof rejects legacy iris-catalog.pem" {
  _assert_uninstall_residue_refused residue_catalog_file
}

@test "stage proof rejects a transaction-bound wrapper" {
  _assert_uninstall_residue_refused residue_transaction_wrapper
}

@test "stage proof rejects the share iris directory header" {
  _assert_uninstall_residue_refused residue_share_directory
}

@test "stage proof rejects a bare iris share directory entry" {
  _assert_uninstall_residue_refused residue_share_entry
}

@test "handled TERM during uninstall IPC commits its ready binding before cleanup and finish" {
  _iox_fixture_setup
  run _iox_controller_run uninstall signal_during_ipc recorded
  [ "$status" -eq 143 ]
  _iox_assert_trace ordered app_stop cleanup finish
}

@test "a second TERM during uninstall cleanup cannot interrupt the mandatory finish" {
  _iox_fixture_setup
  run _iox_controller_run uninstall second_signal_during_cleanup recorded
  [ "$status" -eq 143 ]
  _iox_assert_trace ordered app_stop cleanup finish
}

@test "uninstall rejects inconsistent successful results before a second request" {
  for scenario in malformed_success_timed_out malformed_success_framing malformed_success_returncode \
      malformed_uninstall_journal_half; do
    _iox_fixture_setup
    run _iox_controller_run uninstall "$scenario" recorded
    [ "$status" -ne 0 ]
    [ "$status" -ne 97 ]
    _iox_assert_trace first_only
    rm -rf "$STUBDIR"
  done
}

@test "malformed controller ready and response frames close the recipe before another operation" {
  for scenario in malformed_ready_key malformed_ready_tuple malformed_response_key malformed_response_status; do
    _iox_fixture_setup
    run _iox_controller_run uninstall "$scenario"
    [ "$status" -ne 0 ]
    [ "$status" -ne 97 ]
    [[ "$output" != *'fixture-login-secret'* ]]
    if [[ "$scenario" == malformed_ready* ]]; then
      _iox_assert_trace none
    else
      _iox_assert_trace first_only
    fi
    rm -rf "$STUBDIR"
  done
}

_assert_signal_finalization() {
  local scope="$1" reason="$2" expected="$3"
  _iox_fixture_setup
  run _iox_controller_run uninstall "${scope}_${reason}"
  [ "$status" -eq "$expected" ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace signal "$expected" "$reason"
  [[ "$output" != *'complete:'* ]]
}

@test "uninstall group TERM preserves first signal through cleanup and finish" {
  _assert_signal_finalization group term 143
}

@test "uninstall group INT preserves first signal through cleanup and finish" {
  _assert_signal_finalization group int 130
}

@test "uninstall group HUP preserves first signal through cleanup and finish" {
  _assert_signal_finalization group hup 129
}

@test "uninstall direct TERM preserves first signal through cleanup and finish" {
  _assert_signal_finalization direct term 143
}

@test "uninstall direct INT preserves first signal through cleanup and finish" {
  _assert_signal_finalization direct int 130
}

@test "uninstall direct HUP preserves first signal through cleanup and finish" {
  _assert_signal_finalization direct hup 129
}

@test "uninstall pending TERM survives rejection of the current response" {
  _iox_fixture_setup
  run _iox_controller_run uninstall group_term_malformed
  [ "$status" -eq 143 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace first_only
  [[ "$output" != *'complete:'* ]]
}

@test "uninstall pending INT survives rejection of the current response" {
  _iox_fixture_setup
  run _iox_controller_run uninstall group_int_malformed
  [ "$status" -eq 130 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace first_only
  [[ "$output" != *'complete:'* ]]
}

@test "uninstall pending HUP survives rejection of the current response" {
  _iox_fixture_setup
  run _iox_controller_run uninstall group_hup_malformed
  [ "$status" -eq 129 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace first_only
  [[ "$output" != *'complete:'* ]]
}

@test "uninstall completion follows acknowledged cleanup and finish" {
  _iox_fixture_setup
  run _iox_controller_run uninstall completion_order
  [ "$status" -eq 0 ]
  [[ "$output" == *'fixture cleanup acknowledged'*'fixture finish acknowledged'*'undeploy complete:'* ]]
  _iox_assert_trace count cleanup 1
  _iox_assert_trace count finish 1
}

@test "uninstall never announces completion after cleanup or finish failure" {
  local scenario
  for scenario in cleanup_failure finish_failure; do
    _iox_fixture_setup
    run _iox_controller_run uninstall "$scenario"
    [ "$status" -eq 5 ]
    [[ "$output" != *'undeploy complete:'* ]] || { printf '%s\n' "$output"; return 1; }
    _iox_assert_trace count cleanup 1
    _iox_assert_trace count finish 1
    rm -rf "$STUBDIR"
  done
}

@test "stage proof rejects iris-amd64.tar" {
  _assert_uninstall_residue_refused residue_amd_wrapper
}

@test "stage proof rejects custom validated PKG basenames" {
  _assert_uninstall_residue_refused residue_custom_wrapper
}

@test "stage proof rejects a one-character PKG basename" {
  _assert_uninstall_residue_refused residue_short_wrapper
}

@test "stage proof rejects a maximum-length PKG basename" {
  _assert_uninstall_residue_refused residue_max_wrapper
}

@test "stage proof filename grammar excludes echoes invalid and overlong basenames" {
  local scenario
  for scenario in nonresidue_probe_output nonresidue_overlong_wrapper nonresidue_invalid_wrapper; do
    _iox_fixture_setup
    run _iox_controller_run uninstall "$scenario"
    [ "$status" -eq 0 ]
    _iox_assert_trace count save 1
    _iox_assert_trace count finish 1
    rm -rf "$STUBDIR"
  done
}
