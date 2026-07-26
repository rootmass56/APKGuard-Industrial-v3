from app.dynamic_analysis.events import dynamic_views, parse_frida_events, parse_logcat_events, risk_score


def test_frida_event_becomes_timestamped_runtime_observation():
    text = (
        'APKGuardEvent:{"category":"COMMAND","event_type":"runtime_exec",'
        '"title":"Runtime command execution observed","description":"Runtime.exec invoked",'
        '"severity":"HIGH","timestamp_ms":1700000000000,'
        '"payload":{"api":"java.lang.Runtime.exec","args":["id"]}}'
    )
    events = parse_frida_events(text, session_id="session-1", package_name="com.example.app")
    assert len(events) == 1
    event = events[0]
    assert event.source == "frida-java-agent"
    assert event.evidence_digest
    assert event.session_id == "session-1"
    views = dynamic_views(events)
    assert views["api_calls_intercepted"][0]["api"] == "java.lang.Runtime.exec"
    assert risk_score(events) >= 18


def test_logcat_parser_only_promotes_runtime_signals():
    text = "\n".join(
        [
            "1700000000.125 123 123 I ActivityTaskManager: START u0 cmp=com.example.app/.MainActivity",
            "1700000001.125 123 123 E AndroidRuntime: FATAL EXCEPTION: main com.example.app",
            "1700000002.125 555 555 I Unrelated: harmless message",
        ]
    )
    events = parse_logcat_events(text, session_id="session-2", package_name="com.example.app")
    assert len(events) == 2
    assert {event.event_type for event in events} == {"application_launch", "application_crash"}
    assert all(event.evidence_digest for event in events)


def test_package_and_process_state_become_observed_events():
    from app.dynamic_analysis.events import parse_granted_permissions, parse_process_presence

    permissions = parse_granted_permissions(
        "android.permission.CAMERA: granted=true\nandroid.permission.RECORD_AUDIO: granted=false",
        session_id="session-3",
        package_name="com.example.app",
    )
    processes = parse_process_presence(
        "USER PID PPID NAME\nu0_a123 321 1 com.example.app",
        session_id="session-3",
        package_name="com.example.app",
        start_sequence=2,
    )
    assert [event.payload["permission"] for event in permissions] == ["android.permission.CAMERA"]
    assert processes[0].process_id == 321
    assert processes[0].event_type == "application_process_observed"
