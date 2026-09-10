#!/usr/bin/env bats

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

setup() {
  export DEVICE_IP=192.0.2.10 CATALOG_TOKEN=t DEVICE_ID=e1 STAGE_HOST=192.0.2.2 DEVICE_SSH_PASS=x
  INSTALL="${IOX_RECIPE_ROOT:-$BATS_TEST_DIRNAME/..}/install.sh"
}
@test "stale NETWORK_ATTACHMENT without MANAGEMENT_TYPE aborts; a normal env is unaffected" {
  NETWORK_ATTACHMENT=inband run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] || return 1
  [[ "$output" == *"NETWORK_ATTACHMENT was renamed to MANAGEMENT_TYPE"* ]] || return 1
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
}

@test "inband dry-run creates no VLAN/SVI and never replaces the AppGig allowed list" {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *$'\nvlan '* ]] && \
  [[ "$output" != *"interface Vlan"* ]] && \
  ! grep -Eq 'switchport trunk allowed vlan [0-9]' <<<"$output" && \
  [[ "$output" != *"ip address 192.0.2"* ]]
}

@test "inband dry-run trunks the AppGig additively (allowed vlan add)" {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [[ "$output" == *"interface AppGigabitEthernet1/1"* ]] && \
  [[ "$output" == *"switchport mode trunk"* ]] && \
  [[ "$output" == *"switchport trunk allowed vlan add 120"* ]]
}

@test "inband dry-run points the app SSH-to-IOS at the existing management SVI" {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [[ "$output" == *"IRIS_DEVICE_SSH_HOST=192.0.2.1"* ]] && \
  [[ "$output" == *"vlan 120 guest-interface 0"* ]]
}

@test "routed dry-run still creates the IRIS VLAN and SVI" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [[ "$output" == *"vlan 666"* ]] && [[ "$output" == *"interface Vlan666"* ]]
}

@test "dry-run preserves run-opt structure without printing credentials" {
  CATALOG_TOKEN=literal-catalog-secret DEVICE_SSH_PASS=literal-device-secret \
    VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'IRIS_CATALOG_TOKEN=<redacted>'* ]]
  [[ "$output" == *'IRIS_DEVICE_SSH_PASS=<redacted>'* ]]
  [[ "$output" != *'literal-catalog-secret'* ]]
  [[ "$output" != *'literal-device-secret'* ]]
}

@test "package destination values are validated before use" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    PKG='../escape.tar' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"PKG must be a safe basename"* ]]
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    PKG_FS='flash:;reload' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"PKG_FS must be an IOS filesystem prefix"* ]]
}

@test "dry-run rejects a newline in every rendered package name before output" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    PKG=$'safe\nreload' run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" != *$'\nreload\n'* ]]
}

@test "share dry-run renders the bind mount and its matching container/IOS paths" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iox_host_data_share \
    SHARE_IOS_PATH=usbflash1:iox_host_data_share \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'-v /vol/usb1/iox_host_data_share:/mnt/share'* ]] && \
  [[ "$output" == *'-e IRIS_SHARE_DIR=/mnt/share'* ]] && \
  [[ "$output" == *'-e IRIS_SHARE_IOS_PATH=usbflash1:iox_host_data_share'* ]] && \
  [[ "$output" == *"mkdir usbflash1:iox_host_data_share"* ]]
}

@test "share dry-run preserves a validated alternate host/IOS path pair" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb2/iris-alt \
    SHARE_IOS_PATH=usbflash2:iris-alt \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *'run-opts 12 "-e IRIS_SHARE_DIR=/mnt/share"'* ]]
  [[ "$output" == *'run-opts 13 "-e IRIS_SHARE_IOS_PATH=usbflash2:iris-alt"'* ]]
  [[ "$output" == *'run-opts 14 "-v /vol/usb2/iris-alt:/mnt/share"'* ]]
  [[ "$output" == *'mkdir usbflash2:iris-alt'* ]]
}

@test "share run-opts render INSIDE the app-hosting docker block (before end)" {
  # app-hosting silently ignores run-opts rendered after the block's `end`,
  # so the mount would vanish while every substring gate still passed —
  # assert the line that immediately follows run-opts 14 (the last one,
  # after the unified selector and target override were added ahead of
  # the SHARE block) is `end`.
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iox_host_data_share \
    SHARE_IOS_PATH=usbflash1:iox_host_data_share \
    run bash "$INSTALL" --dry-run
  after="$(printf '%s\n' "$output" | grep -A1 'run-opts 14' | tail -1)"
  [ "$after" = "end" ]
}

@test "without SHARE env no bind-mount is rendered (IE-3x00 default unchanged)" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [[ "$output" != *'-v /vol/'* ]] && \
  [[ "$output" != *'IRIS_SHARE_DIR'* ]]
}

@test "SHARE env is all-or-nothing" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iox_host_data_share \
    run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ] && [[ "$output" == *"SHARE_IOS_PATH"* ]]
}

@test "alternate share paths reject traversal and IOS command separators" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/../escape SHARE_IOS_PATH=usbflash1:escape \
    run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"SHARE_HOST_PATH must be a safe absolute path"* ]]
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iris SHARE_IOS_PATH='usbflash1:iris;reload' \
    run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"SHARE_IOS_PATH must be a safe IOS filesystem path"* ]]
}

@test "dry-run rejects CLI and config injection across IOx supplied fields" {
  local name value
  while IFS='|' read -r name value; do
    run env VLAN=666 SVI_IP=192.0.2.9 \
      SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 "$name=$value" \
      bash "$INSTALL" --dry-run
    [ "$status" -ne 0 ] || { echo "$name unexpectedly accepted"; return 1; }
    [[ "$output" != *$'\nreload\n'* ]] || return 1
  done <<'EOF'
APP_INTF|AppGigabitEthernet1/1;reload
VLAN|666;reload
SVI_IP|192.0.2.9;reload
SVI_MASK|255.0.255.0
GUEST_IP|192.0.2.10;reload
GW_IP|192.0.2.9;reload
CPU|400;reload
MEM|768;reload
DISK|2048;reload
IOS_SSH_HOST|192.0.2.9;reload
IRIS_TELEMETRY|on;reload
IRIS_TELEMETRY_STREAM|off;reload
SHARE_HOST_PATH|/vol/usb1/../escape
EOF
}

@test "dry-run rejects CR/LF before rendering supplied secrets" {
  CATALOG_TOKEN=$'literal-secret\r\nend' \
    VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" != *'literal-secret'* ]]
  [[ "$output" != *$'\nend\n'* ]]
}

@test "dry-run rejects catalog URL userinfo without printing it" {
  CATALOG_URL=https://user:literal-secret@192.0.2.20:8443 \
    VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"without credentials"* ]]
  [[ "$output" != *"literal-secret"* ]]
}

@test "a non-numeric lifecycle budget is refused before the device is touched" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    ACTIVATE_TIMEOUT=abc run bash "$INSTALL" --dry-run
  [ "$status" -eq 2 ]
  [[ "$output" == *"ACTIVATE_TIMEOUT must be an integer from 1 to 86400"* ]]
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    STATE_POLL=0 run bash "$INSTALL" --dry-run
  [ "$status" -eq 2 ]
  [[ "$output" == *"STATE_POLL must be an integer from 1 to 86400"* ]]
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
remote_instructions=False
admitted=False
resolved=False
certificate=False
instructions=False
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
    global sequence,finished,expected_exit,uploaded,admitted,resolved,certificate,instructions,state,revision,phase
    global signal_sent,remote_wrapper,remote_certificate,remote_instructions
    keys=set('version sequence attempt_id action teardown_mode record_id transaction_id expected_revision board_identity wrapper_sha256 operation arguments'.split())
    assert set(value)==keys,'request is not the exact closed schema'
    assert type(value['sequence']) is int and value['sequence']==sequence
    assert type(value['version']) is int and value['version']==1
    for key in keys-set(('sequence','operation','arguments')):
        assert type(value[key]) is type(last_ready[key]) and value[key]==last_ready[key],'request replaced controller '+key
    operation=value['operation']
    arguments=value['arguments']
    assert type(arguments) is dict
    assert operation in ('command','fetch_wrapper','fetch_certificate','begin_install','deployed','stage_instructions','cleanup','finish')
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
        assert operation not in ('fetch_wrapper','fetch_certificate','begin_install','deployed','stage_instructions')
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
        if not signal_sent and (len(signal_case)<3 or signal_case[2]!='poll' or name=='app_list'):
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
    returncode=0 if operation in ('command','fetch_wrapper','fetch_certificate') else None
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
        # A Catalyst 8000V runs the app under Libvirtd, not Dockerd; CAF plus
        # Libvirtd Running is ready (must NOT time out).
        if scenario=='c8000v_libvirtd': stdout='IOx service (CAF) : Running\nLibvirtd 5.5.0 : Running\n'
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
    elif name=='fetch_wrapper':
        uploaded=True
        remote_wrapper=True
        if scenario=='fetch_wrapper_failure':
            code,category,detail=4,'transport','fixture upload failed after creating remote file'
            returncode=1
    elif name=='fetch_certificate': remote_certificate=True
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
            state='INSTALLING' if scenario in ('install_timeout','install_timeout_cleanup_rejected','install_poll_exhaustion') else 'DEPLOYED'
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
    elif name=='stage_instructions':
        assert state=='ACTIVATED','instructions staged before activation'
        remote_instructions=True
        if scenario=='instruction_stage_failure':
            code,category,detail=4,'transport','instruction staging failed'
        else:
            instructions=True
            revision+=2
        remote_instructions=False
    elif name=='copy_certificate':
        assert state=='ACTIVATED','certificate copied before activation'
        if scenario in ('certificate_copy_failure','copy_failure_cleanup_failure'):
            code,category,detail=4,'rejected','application data copy failed'
            stdout='% Error: application data unavailable\n'
        else:
            certificate=True
            stdout='Successfully copied file /flash/iris-catalog.pem to iris as iris-catalog.pem\n'
    elif name=='app_start':
        assert certificate and instructions and state=='ACTIVATED'
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
        }
        stdout=residues.get(scenario,'')
    elif name=='cleanup_stage_probe':
        if scenario=='residue_stage': stdout='Directory of sdflash:/guest-share/iris\n'
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
            remote_instructions=False
            trace.write(json.dumps(dict(event='artifact_cleanup',wrapper=False,certificate=False,instructions=False))+'\n')
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
    malformed_app_list=scenario=='malformed_app_list' and name=='app_list' and counts[name]==1
    if malformed_app_list: result['unexpected']='fixture-login-secret'
    if scenario=='malformed_response_key': result['unexpected']='fixture-login-secret'
    if scenario=='malformed_response_status': result['recipe_returncode']=0
    send(result)
    if malformed_app_list or scenario.endswith('_malformed') or scenario.startswith(('malformed_response','malformed_success','malformed_install_','malformed_uninstall_')):
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
    -u EXPECTED_DEVICE_IDENTITY IRIS_STATE="$STUBDIR/authority/owner" \
    bash "$STUBDIR/device/iox/install.sh" --dry-run
  [ "$status" -eq 0 ]
  [ ! -s "$IOX_DIRECT_LOG" ]
  [ ! -s "$IOX_REQUEST_LOG" ]
  [ "$(cat "$STUBDIR/authority/owner")" = authority-owner-data ]
  [ "$(find "$STUBDIR/authority" -mindepth 1 | wc -l)" -eq 1 ]
  [[ "$output" != *'fixture-login-secret'* ]]
}

@test "environment authority cannot start the real install recipe" {
  _iox_fixture_setup
  run env -u IRIS_IOX_CONTROL_FD IRIS_IOX_RECORD_ID=environment-record \
    IRIS_IOX_TRANSACTION_ID=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
    IRIS_IOX_REVISION=999 timeout 6 bash "$STUBDIR/device/iox/install.sh"
  [ "$status" -eq 2 ]
  [ ! -s "$IOX_DIRECT_LOG" ]
  [ ! -s "$IOX_REQUEST_LOG" ]
  [[ "$output" != *'fixture-login-secret'* ]]
}

@test "controller recipe preserves successful lifecycle and certificate ordering" {
  _iox_fixture_setup
  run _iox_controller_run install success
  [ "$status" -eq 0 ]
  [[ "$output" == *'onboard complete: 192.0.2.10'* ]]
  # The job log is the recipe's step headers and poll outcomes, in order;
  # the device session the controller drove stays in its transcript.
  [[ "$output" == *'[1/8] fetch package and certificate'*'[2/8] check prerequisites'*'IOx services ready (poll 1/24)'*'[3/8] remove any existing app'*'[4/8] configure networking and app'*'[5/8] install app'*'app is DEPLOYED (poll 1/24)'*'[6/8] activate app'*'app is ACTIVATED (poll 1/24)'*'[7/8] stage instructions'*'app is RUNNING (poll 1/24)'*'[8/8] save configuration'*'onboard complete:'* ]]
  [[ "$output" != *'Installing package'* ]]
  [[ "$output" != *'%IOX: application installation accepted'* ]]
  [[ "$output" != *'Application activated'* ]]
  [[ "$output" != *'[OK]'* ]]
  _iox_assert_trace ordered fetch_wrapper begin_install app_install deployed app_activate stage_instructions copy_certificate app_start save finish
  _iox_assert_trace finish RUNNING
}

@test "the job's IRIS_LOG opt-in echoes the device session into the recipe output" {
  _iox_fixture_setup
  IRIS_LOG=on run _iox_controller_run install success
  [ "$status" -eq 0 ]
  [[ "$output" == *'[5/8] install app'*'Installing package'*'%IOX: application installation accepted'*'app is DEPLOYED (poll 1/24)'* ]]
  [[ "$output" == *'Application activated'* ]]
  [[ "$output" == *'[OK]'*'onboard complete: 192.0.2.10'* ]]
  _iox_assert_trace finish RUNNING
}

@test "controller signing admission is opaque to the recipe and precedes application mutation" {
  _iox_fixture_setup
  run _iox_controller_run install marker_present
  [ "$status" -eq 0 ]
  _iox_assert_trace ordered fetch_wrapper begin_install app_stop app_install deployed app_activate stage_instructions
  _iox_assert_trace absent verification_enable verification_disable
}

@test "controller rejection of the catalog certificate precedes application teardown" {
  _iox_fixture_setup
  run _iox_controller_run install certificate_invalid
  [ "$status" -ne 0 ]
  [[ "$output" == *'not a valid PEM certificate'* ]]
  _iox_assert_trace absent app_stop app_deactivate app_uninstall app_install
}

@test "controller certificate-copy failure leaves the activated IRIS app unstarted" {
  _iox_fixture_setup
  run _iox_controller_run install certificate_copy_failure
  [ "$status" -ne 0 ]
  # A failed step quotes the device's own '%' verdict and the controller's
  # detail, without the rest of the session.
  [[ "$output" == *'% Error: application data unavailable'* ]]
  [[ "$output" == *'application data copy failed'* ]]
  [[ "$output" != *'Application activated'* ]]
  _iox_assert_trace ordered app_activate copy_certificate finish
  _iox_assert_trace absent app_start
  _iox_assert_trace finish ACTIVATED
}

@test "instruction staging is one opaque empty recipe operation after activation" {
  _iox_fixture_setup
  run _iox_controller_run install success
  [ "$status" -eq 0 ] || return 1
  python3 - "$IOX_REQUEST_LOG" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1])]
requests = [row["request"] for row in rows if row.get("event") == "request"]
stage = [row for row in requests if row["operation"] == "stage_instructions"]
assert len(stage) == 1
assert stage[0]["arguments"] == {}
following = requests[requests.index(stage[0]) + 1]
assert following["operation"] == "command"
assert following["arguments"] == {"name": "copy_certificate"}
assert following["expected_revision"] == stage[0]["expected_revision"] + 2
serialized = json.dumps(stage[0], sort_keys=True)
for forbidden in ("envelope", "bootstrap", "ciphertext", "/tmp/", "instruction key"):
    assert forbidden not in serialized
PY
  _iox_assert_trace ordered app_activate stage_instructions copy_certificate app_start
}

@test "instruction staging failure leaves the activated app unstarted" {
  _iox_fixture_setup
  run _iox_controller_run install instruction_stage_failure
  [ "$status" -ne 0 ]
  _iox_assert_trace ordered app_activate stage_instructions finish
  _iox_assert_trace absent copy_certificate app_start
  _iox_assert_trace finish ACTIVATED
}

@test "controller routing prerequisite failure reports routing and preserves the existing app" {
  _iox_fixture_setup
  run _iox_controller_run install routing_missing
  [ "$status" -ne 0 ]
  [[ "$output" == *'PREREQ: ip routing is disabled'* ]]
  _iox_assert_trace absent app_stop app_deactivate app_uninstall remove_app_config
  _iox_assert_trace finish RUNNING
}

@test "controller dead session reports transport rather than disabled routing" {
  _iox_fixture_setup
  run _iox_controller_run install device_down
  [ "$status" -ne 0 ]
  [[ "$output" == *'PREREQ: could not verify ip routing'* ]]
  [[ "$output" != *'PREREQ: ip routing is disabled'* ]]
  _iox_assert_trace absent app_stop app_uninstall
}

@test "controller routing prerequisite success permits later network configuration" {
  _iox_fixture_setup
  run _iox_controller_run install success
  [ "$status" -eq 0 ]
  [[ "$output" != *'PREREQ: ip routing is disabled'* ]]
  _iox_assert_trace ordered routing_prereq begin_install configure_network
}

@test "controller storage prerequisite failure preserves the existing application" {
  _iox_fixture_setup
  run _iox_controller_run install no_partition
  [ "$status" -ne 0 ]
  [[ "$output" == *'PREREQ: no IOx partition on the SD card'* ]]
  _iox_assert_trace absent app_stop app_deactivate app_uninstall app_install
}

@test "controller old-clock diagnostic warns and permits later configuration" {
  _iox_fixture_setup
  run _iox_controller_run install old_clock
  [ "$status" -eq 0 ]
  [[ "$output" == *'PREREQ WARNING: device clock is 2018'* ]]
  _iox_assert_trace ordered clock configure_network app_start finish
}

@test "controller unparseable optional clock does not abort installation" {
  _iox_fixture_setup
  run _iox_controller_run install unknown_clock
  [ "$status" -eq 0 ]
  [[ "$output" != *'PREREQ WARNING'* ]]
  _iox_assert_trace ordered clock configure_network app_start finish
}

@test "controller identity refusal provides no handoff and admits no recipe mutation" {
  _iox_fixture_setup
  run _iox_controller_run install identity_refused
  [ "$status" -ne 0 ]
  _iox_assert_trace none
}

@test "controller activation timeout keeps the app and exposes the unfiltered diagnostic" {
  _iox_fixture_setup
  run _iox_controller_run install activation_timeout
  [ "$status" -ne 0 ]
  [[ "$output" == *'did not reach ACTIVATED within 2 seconds'* ]]
  [[ "$output" == *'activation is still loading the app image'* ]]
  [[ "$output" == *'Last observed state: DEPLOYED'* ]]
  [[ "$output" == *'retry onboarding'* ]]
  _iox_assert_trace count remove_app_config 1
  _iox_assert_trace absent app_start
  _iox_assert_trace finish DEPLOYED
}

# Controller ordering allows remove_app_config only before configure_app.
# A failed DEPLOYED poll must retain its failure and enter mandatory cleanup.
@test "controller install timeout enters cleanup without repeating app configuration removal" {
  _iox_fixture_setup
  run _iox_controller_run install install_timeout
  [ "$status" -eq 4 ]
  _iox_assert_trace count remove_app_config 1
  [[ "$output" == *'did not reach DEPLOYED within 2 seconds'* ]]
  [[ "$output" == *'onboarding aborted.'* ]]
  [[ "$output" != *'Partial app configuration removed'* ]]
  _iox_assert_trace absent app_activate app_start
  _iox_assert_trace finish INSTALLING
}

@test "controller IOx readiness reads both required fields in one observation" {
  _iox_fixture_setup
  run _iox_controller_run install success
  [ "$status" -eq 0 ]
  _iox_assert_trace count iox_status 1
}

@test "controller IOx readiness refuses either missing service field" {
  for scenario in caf_missing dockerd_missing; do
    _iox_fixture_setup
    run _iox_controller_run install "$scenario"
    [ "$status" -ne 0 ]
    _iox_assert_trace absent begin_install app_install
    rm -rf "$STUBDIR"
  done
}

@test "controller IOx readiness accepts a Catalyst 8000V running Libvirtd, not Dockerd" {
  # A C8000V has no Dockerd; its app runtime is Libvirtd. CAF + Libvirtd
  # Running is ready and the install must proceed, not hang to the deadline.
  _iox_fixture_setup
  run _iox_controller_run install c8000v_libvirtd
  [ "$status" -eq 0 ]
  _iox_assert_trace count iox_status 1
}

@test "controller finish failure sets a previously successful recipe exit" {
  _iox_fixture_setup
  run _iox_controller_run install finish_failure
  [ "$status" -eq 5 ]
  [[ "$output" != *'onboard complete:'* ]]
  _iox_assert_trace finish RUNNING
}

@test "controller cleanup failure preserves the original nonzero recipe exit intent" {
  _iox_fixture_setup
  run _iox_controller_run install copy_failure_cleanup_failure
  [ "$status" -ne 0 ]
  [ "$status" -ne 5 ]
  _iox_assert_trace preserve_primary
  _iox_assert_trace finish ACTIVATED
}

@test "controller cleanup removes admitted uploads after upload prerequisite and lifecycle failure" {
  for scenario in fetch_wrapper_failure routing_missing certificate_copy_failure; do
    _iox_fixture_setup
    run _iox_controller_run install "$scenario"
    [ "$status" -ne 0 ]
    _iox_assert_trace ordered cleanup finish
    _iox_assert_trace artifact_clean
    rm -rf "$STUBDIR"
  done
}

@test "handled TERM during an IPC request commits its ready binding before cleanup and finish" {
  _iox_fixture_setup
  run _iox_controller_run install signal_during_ipc
  [ "$status" -eq 143 ]
  _iox_assert_trace ordered fetch_wrapper cleanup finish
  _iox_assert_trace artifact_clean
}

@test "a second TERM during cleanup cannot interrupt the mandatory finish" {
  _iox_fixture_setup
  run _iox_controller_run install second_signal_during_cleanup
  [ "$status" -eq 143 ]
  _iox_assert_trace ordered fetch_wrapper cleanup finish
  _iox_assert_trace artifact_clean
}

@test "inconsistent successful results are rejected before a second request" {
  for scenario in malformed_success_timed_out malformed_success_framing \
      malformed_success_returncode malformed_install_journal_none malformed_install_phase; do
    _iox_fixture_setup
    run _iox_controller_run install "$scenario"
    [ "$status" -ne 0 ]
    [ "$status" -ne 97 ]
    _iox_assert_trace first_only
    rm -rf "$STUBDIR"
  done
}

@test "next ready must retain the acknowledged install journal revision" {
  _iox_fixture_setup
  run _iox_controller_run install malformed_ready_revision
  [ "$status" -ne 0 ]
  [ "$status" -ne 97 ]
  _iox_assert_trace first_only
}

@test "deployed recovery may relinquish ownership after an enabled probe" {
  _iox_fixture_setup
  run _iox_controller_run install deployed_relinquished
  [ "$status" -eq 0 ]
  _iox_assert_trace ordered deployed app_activate app_start finish
}

@test "inband dry-run validates the IOS management host before rendering" {
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 run env -u IOS_SSH_HOST bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *'IOS_SSH_HOST'* ]]
}

@test "malformed controller ready and response frames close the recipe before another operation" {
  for scenario in malformed_ready_key malformed_ready_tuple malformed_response_key malformed_response_status; do
    _iox_fixture_setup
    run _iox_controller_run install "$scenario"
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

@test "dry-run explains that wrapper marker presence does not establish cryptographic validity" {
  _iox_fixture_setup
  run bash "$STUBDIR/device/iox/install.sh" --dry-run
  [ "$status" -eq 0 ]
  local lower="${output,,}"
  [[ "$lower" == *'package.sign'* && "$lower" == *'package.cert'* ]]
  [[ "$lower" == *'presence does not establish'*'validity'* ]]
  [ ! -s "$IOX_DIRECT_LOG" ]
}

_assert_signal_finalization() {
  local scope="$1" reason="$2" expected="$3"
  _iox_fixture_setup
  run _iox_controller_run install "${scope}_${reason}"
  [ "$status" -eq "$expected" ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace signal "$expected" "$reason"
  [[ "$output" != *'complete:'* ]]
}

@test "install group TERM preserves first signal through cleanup and finish" {
  _assert_signal_finalization group term 143
}

@test "install group INT preserves first signal through cleanup and finish" {
  _assert_signal_finalization group int 130
}

@test "install group HUP preserves first signal through cleanup and finish" {
  _assert_signal_finalization group hup 129
}

@test "install direct TERM preserves first signal through cleanup and finish" {
  _assert_signal_finalization direct term 143
}

@test "install direct INT preserves first signal through cleanup and finish" {
  _assert_signal_finalization direct int 130
}

@test "install direct HUP preserves first signal through cleanup and finish" {
  _assert_signal_finalization direct hup 129
}

@test "install pending TERM survives rejection of the current response" {
  _iox_fixture_setup
  run _iox_controller_run install group_term_malformed
  [ "$status" -eq 143 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace first_only
  [[ "$output" != *'complete:'* ]]
}

@test "install pending INT survives rejection of the current response" {
  _iox_fixture_setup
  run _iox_controller_run install group_int_malformed
  [ "$status" -eq 130 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace first_only
  [[ "$output" != *'complete:'* ]]
}

@test "install pending HUP survives rejection of the current response" {
  _iox_fixture_setup
  run _iox_controller_run install group_hup_malformed
  [ "$status" -eq 129 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace first_only
  [[ "$output" != *'complete:'* ]]
}

@test "install completion follows acknowledged cleanup and finish" {
  _iox_fixture_setup
  # The fixture's acknowledgements are device-session output, which only
  # the IRIS_LOG opt-in echoes; the ordering proof needs them visible.
  IRIS_LOG=on run _iox_controller_run install completion_order
  [ "$status" -eq 0 ]
  [[ "$output" == *'fixture cleanup acknowledged'*'fixture finish acknowledged'*'onboard complete:'* ]]
  _iox_assert_trace count cleanup 1
  _iox_assert_trace count finish 1
}

@test "install never announces completion after cleanup or finish failure" {
  local scenario
  for scenario in cleanup_failure finish_failure; do
    _iox_fixture_setup
    run _iox_controller_run install "$scenario"
    [ "$status" -eq 5 ]
    [[ "$output" != *'onboard complete:'* ]] || { printf '%s\n' "$output"; return 1; }
    _iox_assert_trace count cleanup 1
    _iox_assert_trace count finish 1
    rm -rf "$STUBDIR"
  done
}

@test "install timeout never sends or claims the forbidden repeated app configuration removal" {
  _iox_fixture_setup
  run _iox_controller_run install install_timeout_cleanup_rejected
  [ "$status" -eq 4 ]
  _iox_assert_trace count remove_app_config 1
  [[ "$output" == *'did not reach DEPLOYED within 2 seconds'* ]]
  [[ "$output" == *'onboarding aborted.'* ]]
  [[ "$output" != *'repeated app configuration removal rejected'* ]]
  [[ "$output" != *'Partial app configuration removed'* ]]
  [[ "$output" != *'onboard complete:'* ]]
  _iox_assert_trace count cleanup 1
  _iox_assert_trace count finish 1
  _iox_assert_trace absent app_activate app_start
  _iox_assert_trace finish INSTALLING
}

@test "install group TERM during polling proceeds directly to finalization" {
  _iox_fixture_setup
  run _iox_controller_run install group_term_poll
  [ "$status" -eq 143 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace signal 143 term
  _iox_assert_trace count remove_app_config 1
  _iox_assert_trace absent deployed app_activate app_start
  [[ "$output" != *'Partial app configuration removed'* ]]
}

@test "install group INT during polling proceeds directly to finalization" {
  _iox_fixture_setup
  run _iox_controller_run install group_int_poll
  [ "$status" -eq 130 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace signal 130 int
  _iox_assert_trace count remove_app_config 1
  _iox_assert_trace absent deployed app_activate app_start
  [[ "$output" != *'Partial app configuration removed'* ]]
}

@test "install group HUP during polling proceeds directly to finalization" {
  _iox_fixture_setup
  run _iox_controller_run install group_hup_poll
  [ "$status" -eq 129 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace signal 129 hup
  _iox_assert_trace count remove_app_config 1
  _iox_assert_trace absent deployed app_activate app_start
  [[ "$output" != *'Partial app configuration removed'* ]]
}

@test "install direct TERM during polling proceeds directly to finalization" {
  _iox_fixture_setup
  run _iox_controller_run install direct_term_poll
  [ "$status" -eq 143 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace signal 143 term
  _iox_assert_trace count remove_app_config 1
  _iox_assert_trace absent deployed app_activate app_start
  [[ "$output" != *'Partial app configuration removed'* ]]
}

@test "install direct INT during polling proceeds directly to finalization" {
  _iox_fixture_setup
  run _iox_controller_run install direct_int_poll
  [ "$status" -eq 130 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace signal 130 int
  _iox_assert_trace count remove_app_config 1
  _iox_assert_trace absent deployed app_activate app_start
  [[ "$output" != *'Partial app configuration removed'* ]]
}

@test "install direct HUP during polling proceeds directly to finalization" {
  _iox_fixture_setup
  run _iox_controller_run install direct_hup_poll
  [ "$status" -eq 129 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace signal 129 hup
  _iox_assert_trace count remove_app_config 1
  _iox_assert_trace absent deployed app_activate app_start
  [[ "$output" != *'Partial app configuration removed'* ]]
}

@test "install poll exhaustion enters cleanup without repeating app configuration removal" {
  _iox_fixture_setup
  run _iox_controller_run install install_poll_exhaustion
  [ "$status" -eq 4 ]
  _iox_assert_trace count remove_app_config 1
  [[ "$output" == *'onboarding aborted.'* ]]
  [[ "$output" != *'Partial app configuration removed'* ]]
  [[ "$output" != *'onboard complete:'* ]]
  _iox_assert_trace count app_list 24
  _iox_assert_trace count cleanup 1
  _iox_assert_trace count finish 1
  _iox_assert_trace absent app_activate app_start
  _iox_assert_trace finish INSTALLING
}

@test "malformed first app-list response preserves protocol failure without promising cleanup" {
  _iox_fixture_setup
  run _iox_controller_run install malformed_app_list
  [ "$status" -eq 200 ] || { printf '%s\n' "$output"; return 1; }
  _iox_assert_trace count app_list 1
  _iox_assert_trace count remove_app_config 1
  _iox_assert_trace count cleanup 0
  _iox_assert_trace count finish 0
  _iox_assert_trace absent deployed app_activate app_start
  [[ "$output" == *'invalid private IOx controller protocol'* ]]
  [[ "$output" != *'controller cleanup follows'* ]] || { printf '%s\n' "$output"; return 1; }
  [[ "$output" == *'Application deployment did not complete; onboarding aborted.'* ]]
  [[ "$output" != *'onboard complete:'* ]]
}


@test "router-routed dry-run attaches the app to the VirtualPortGroup, never a VLAN or AppGig" {
  MANAGEMENT_TYPE=router-routed VPG_NUMBER=0 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 PKG=iris-amd64.tar PKG_FS=bootflash: TARGET_FS=bootflash: \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" == *"interface VirtualPortGroup0"* ]] && \
  [[ "$output" == *"ip address 192.0.2.1 255.255.255.0"* ]] && \
  [[ "$output" == *"app-vnic gateway0 virtualportgroup 0 guest-interface 0"* ]] && \
  [[ "$output" == *"guest-ipaddress 192.0.2.21 netmask 255.255.255.0"* ]] && \
  [[ "$output" == *"app-default-gateway 192.0.2.1 guest-interface 0"* ]] && \
  [[ "$output" == *"IRIS_DEVICE_SSH_HOST=192.0.2.1"* ]] && \
  [[ "$output" == *"IRIS_TARGET_FS=bootflash:"* ]] && \
  [[ "$output" != *"AppGigabitEthernet"* ]] && \
  [[ "$output" != *"interface Vlan"* ]] && \
  [[ "$output" != *"ip nat"* ]]
}

@test "router-nat dry-run adds the NAT footprint device/router-install.sh would" {
  MANAGEMENT_TYPE=router-nat VPG_NUMBER=2 APP_IP=10.0.2.5 APP_MASK=255.255.255.0 \
    APP_GATEWAY=10.0.2.1 NAT_INTERFACE=GigabitEthernet1 PKG=iris-amd64.tar \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ] || { echo "$output"; return 1; }
  [[ "$output" == *" ip nat inside"* ]] && \
  [[ "$output" == *"interface GigabitEthernet1"* ]] && \
  [[ "$output" == *"ip access-list standard IRIS-NAT-2"* ]] && \
  [[ "$output" == *"permit 10.0.2.0 0.0.0.255"* ]] && \
  [[ "$output" == *"ip nat inside source list IRIS-NAT-2 interface GigabitEthernet1 overload"* ]] && \
  [[ "$output" == *"ip nat inside source static tcp 10.0.2.5 6881 interface GigabitEthernet1 6881"* ]] && \
  [[ "$output" == *"app-vnic gateway0 virtualportgroup 2 guest-interface 0"* ]]
}

@test "a router type refuses an out-of-range VirtualPortGroup" {
  MANAGEMENT_TYPE=router-routed VPG_NUMBER=32 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 run bash "$INSTALL" --dry-run
  [ "$status" -ne 0 ]
  [[ "$output" == *"VPG_NUMBER must be between 0 and 31"* ]]
}


@test "dry-run installs the catalog trustpoint before any copy, as device-install.sh does" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *$'no crypto pki trustpoint IRIS\n'* ]]
  [[ "$output" == *$'crypto pki trustpoint IRIS\n enrollment terminal\n revocation-check none\nexit\ncrypto pki authenticate IRIS\n'* ]]
  [[ "$output" == *$'quit\n'* ]]
  [[ "$output" == *"ip http client secure-trustpoint IRIS"* ]]
  trust="$(printf '%s\n' "$output" | grep -n 'crypto pki authenticate IRIS' | head -1 | cut -d: -f1)"
  first_copy="$(printf '%s\n' "$output" | grep -n '^copy https://' | head -1 | cut -d: -f1)"
  [ "$trust" -lt "$first_copy" ]
}

@test "dry-run pastes the real certificate when IRIS_CRT_FILE is readable" {
  printf -- '-----BEGIN CERTIFICATE-----\nZml4dHVyZQ==\n-----END CERTIFICATE-----\n' > "$BATS_TEST_TMPDIR/crt.pem"
  IRIS_CRT_FILE="$BATS_TEST_TMPDIR/crt.pem" \
    VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *$'crypto pki authenticate IRIS\n-----BEGIN CERTIFICATE-----\nZml4dHVyZQ==\n-----END CERTIFICATE-----\nquit\n'* ]]
}

@test "dry-run has the DEVICE fetch the package, certificate and envelope over verified https" {
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"copy https://192.0.2.2:8000/v1/devices/e1/artifacts/iris-arm64.tar flash:iris-<transaction>.tar"* ]]
  [[ "$output" == *'dir flash: | include iris-<transaction>\.tar'* ]]
  [[ "$output" == *"copy https://192.0.2.2:8000/v1/devices/e1/artifacts/iris-catalog.pem flash:iris-ca.pem"* ]]
  [[ "$output" == *"copy https://192.0.2.2:8000/v1/devices/e1/artifacts/staging/e1/iris-instructions-<transaction>.envelope flash:iris-instructions-<transaction>.envelope"* ]]
  [[ "$output" != *"scp -O"* ]]
  [[ "$output" != *'${DEVICE_USER}'* ]]
}

@test "dry-run brackets every copy with the device's own fetch credentials and never prints the token" {
  CATALOG_TOKEN=literal-catalog-secret \
    VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"literal-catalog-secret"* ]]
  [ "$(printf '%s\n' "$output" | grep -c '^ip http client username e1$')" -eq 3 ]
  [ "$(printf '%s\n' "$output" | grep -c '^ip http client password 0 <redacted>$')" -eq 3 ]
  [ "$(printf '%s\n' "$output" | grep -c '^no ip http client username$')" -eq 3 ]
  [ "$(printf '%s\n' "$output" | grep -c '^no ip http client password$')" -eq 3 ]
  # set -> copy -> clear, in that order, for the package copy
  set_at="$(printf '%s\n' "$output" | grep -n '^ip http client password 0 <redacted>$' | head -1 | cut -d: -f1)"
  copy_at="$(printf '%s\n' "$output" | grep -n '^copy https://' | head -1 | cut -d: -f1)"
  clear_at="$(printf '%s\n' "$output" | grep -n '^no ip http client password$' | head -1 | cut -d: -f1)"
  [ "$set_at" -lt "$copy_at" ] && [ "$copy_at" -lt "$clear_at" ]
}

@test "dry-run keeps the SCP server line only where there is no share (IE-3x00)" {
  # Issue #228. Onboarding pushes nothing over SCP on any platform; the
  # device's SCP server exists for the agent's runtime guest-share hand-off,
  # and only a platform that cannot bind-mount its staging filesystem into
  # the app needs it. `file prompt quiet` is not part of that decision -- the
  # device-side `copy https:` fetch needs it everywhere.
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"ip scp server enable"* ]]
  [[ "$output" == *"file prompt quiet"* ]]
  MANAGEMENT_TYPE=inband INBAND_VLAN=120 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
    APP_GATEWAY=192.0.2.1 IOS_SSH_HOST=192.0.2.1 \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" == *"ip scp server enable"* ]]
  # A C9300 job carries the SSD share, so the same switch template drops it.
  VLAN=666 SVI_IP=192.0.2.9 SVI_MASK=255.255.255.252 GUEST_IP=192.0.2.10 \
    SHARE_HOST_PATH=/vol/usb1/iox_host_data_share \
    SHARE_IOS_PATH=usbflash1:iox_host_data_share \
    run bash "$INSTALL" --dry-run
  [ "$status" -eq 0 ]
  [[ "$output" != *"ip scp server enable"* ]]
  [[ "$output" == *"file prompt quiet"* ]]
}

@test "dry-run stages a Catalyst 8000 through the bootflash share, never over scp" {
  # The share pair is gui_onboard._C8K_IOX_ENV's; the installer only renders
  # what it is given. With it the router bind-mounts the share, creates it,
  # and leaves the device's SCP server alone (issue #228).
  for mode in router-routed router-nat; do
    MANAGEMENT_TYPE=$mode VPG_NUMBER=0 APP_IP=192.0.2.21 APP_MASK=255.255.255.0 \
      APP_GATEWAY=192.0.2.1 NAT_INTERFACE=GigabitEthernet1 \
      SHARE_HOST_PATH=/bootflash/iox_host_data_share \
      SHARE_IOS_PATH=bootflash:iox_host_data_share \
      run bash "$INSTALL" --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" != *"ip scp server enable"* ]]
    [[ "$output" == *"file prompt quiet"* ]]
    [[ "$output" == *'run-opts 12 "-e IRIS_SHARE_DIR=/mnt/share"'* ]]
    [[ "$output" == *'run-opts 13 "-e IRIS_SHARE_IOS_PATH=bootflash:iox_host_data_share"'* ]]
    [[ "$output" == *'run-opts 14 "-v /bootflash/iox_host_data_share:/mnt/share"'* ]]
    [[ "$output" == *"mkdir bootflash:iox_host_data_share"* ]]
    [[ "$output" == *"copy https://192.0.2.2:8000/v1/devices/e1/artifacts/iris-amd64.tar bootflash:iris-<transaction>.tar"* ]]
  done
}
