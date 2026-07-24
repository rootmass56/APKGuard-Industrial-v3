import React, { useState, useCallback, useRef } from "react";
import { CircularProgressbar, buildStyles } from "react-circular-progressbar";
import "react-circular-progressbar/dist/styles.css";
import {
  Shield, Upload, AlertTriangle, AlertOctagon, CheckCircle, Info,
  Download, ChevronDown, ChevronRight, Terminal, Cpu, Lock, Wifi,
  Database, Eye, FileText, Zap, Activity, Search, Globe, Package, BarChart2, Clock,
} from "lucide-react";
import "./index.css";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1";
const sev = (s) => { s = (s||"").toUpperCase(); const m = { CRITICAL:{color:"var(--c-critical)",icon:AlertOctagon,label:"CRITICAL"}, HIGH:{color:"var(--c-high)",icon:AlertTriangle,label:"HIGH"}, MEDIUM:{color:"var(--c-medium)",icon:Info,label:"MEDIUM"}, LOW:{color:"var(--c-low)",icon:CheckCircle,label:"LOW"}, INFO:{color:"var(--c-info)",icon:Info,label:"INFO"} }; return m[s]||m.INFO; };
const mitreColor=(t)=>({"Initial Access":"#ef4444","Execution":"#f97316","Persistence":"#f59e0b","Privilege Escalation":"#eab308","Defense Evasion":"#84cc16","Credential Access":"#22c55e","Discovery":"#06b6d4","Lateral Movement":"#3b82f6","Collection":"#8b5cf6","Exfiltration":"#ec4899","Command and Control":"#dc2626","Impact":"#991b1b"})[t]||"#6b7280";
const gaugeColor=(s)=>s>=80?"#ef4444":s>=60?"#f97316":s>=40?"#f59e0b":s>=20?"#84cc16":"#22c55e";
const gaugeLabel=(s)=>s>=80?"CRITICAL":s>=60?"HIGH":s>=40?"MEDIUM":s>=20?"LOW":"SAFE";
const STAGES=[{icon:Package,label:"Uploading APK"},{icon:Search,label:"Server analysis running"},{icon:Lock,label:"Evidence review"},{icon:BarChart2,label:"Finalizing result"}];
const DANGEROUS=["CAMERA","RECORD_AUDIO","READ_CONTACTS","ACCESS_FINE_LOCATION","READ_SMS","PROCESS_OUTGOING_CALLS","SEND_SMS","READ_CALL_LOG","READ_PHONE_STATE","REQUEST_INSTALL_PACKAGES"];

function UploadPage({onResults}){
  const [dragging,setDragging]=useState(false);
  const [file,setFile]=useState(null);
  const [status,setStatus]=useState("idle");
  const [errMsg,setErrMsg]=useState("");
  const [stageIdx,setStageIdx]=useState(0);
  const [progress,setProgress]=useState(0);
  const inputRef=useRef();
  const handleFile=(f)=>{if(!f)return;if(!f.name.endsWith(".apk")){setErrMsg("Only .apk files accepted.");setStatus("error");return;}setFile(f);setStatus("idle");setErrMsg("");};
  const onDrop=useCallback((e)=>{e.preventDefault();setDragging(false);handleFile(e.dataTransfer.files[0]);},[]);
  const analyze=async()=>{
    if(!file)return;
    setStatus("scanning");setStageIdx(0);setProgress(10);
    const form=new FormData();form.append("file",file);
    try{
      setStageIdx(1);setProgress(35);
      const res=await fetch(`${API}/analyze`,{method:"POST",body:form});
      setStageIdx(2);setProgress(75);
      if(!res.ok){const e=await res.json().catch(()=>({detail:"Analysis failed"}));throw new Error(e.detail||"Analysis failed");}
      const data=await res.json();
      setStageIdx(3);setProgress(100);
      setTimeout(()=>onResults(data),250);
    }catch(e){setStatus("error");setErrMsg(e.message);}
  };
  const FEATURES=[[Search,"Static Analysis","DEX, manifest, resources"],[Cpu,"Optional AI Summary","Disabled unless configured"],[Eye,"MITRE ATT&CK","Evidence-based mapping"],[Globe,"Hash Reputation","No file upload by default"],[Lock,"Permission Audit","Dangerous perm detection"],[BarChart2,"Risk Scoring","Explainable weighted score"]];
  const STATS=[["Evidence","Based"],["Hash-only","VT Mode"],["AI","Optional"],["Open","Source"]];
  return(
    <div className="upload-root">
      <div className="grid-bg" aria-hidden/><div className="scanline" aria-hidden/>
      <div className="orb orb-1" aria-hidden/><div className="orb orb-2" aria-hidden/>
      <div className="upload-center">
        <div className="logo-wrap">
          <div className="logo-hex"><Shield size={36} strokeWidth={1.5}/></div>
          <div><h1 className="logo-title">APKGuard <span className="logo-ai">AI</span></h1><p className="logo-sub">Android Package Security Intelligence Platform</p></div>
        </div>
        <div className="stats-row">{STATS.map(([val,label])=><div key={label} className="stat-pill"><span className="stat-pill-val">{val}</span><span className="stat-pill-lbl">{label}</span></div>)}</div>
        {status!=="scanning"?(
          <div className={`dropzone ${dragging?"dragging":""} ${status==="error"?"errored":""}`} onDragOver={(e)=>{e.preventDefault();setDragging(true);}} onDragLeave={()=>setDragging(false)} onDrop={onDrop} onClick={()=>inputRef.current?.click()} role="button" tabIndex={0} aria-label="Upload APK" onKeyDown={(e)=>e.key==="Enter"&&inputRef.current?.click()}>
            <input ref={inputRef} type="file" accept=".apk" className="hidden-input" onChange={(e)=>handleFile(e.target.files[0])}/>
            <div className="drop-content">
              <div className="drop-icon-wrap"><Upload size={40} strokeWidth={1.2}/></div>
              {file?(<><p className="drop-filename">{file.name}</p><p className="drop-size">{(file.size/1048576).toFixed(2)} MB Ready to scan</p></>):(<><p className="drop-headline">Drop your APK here</p><p className="drop-hint">or click to browse</p><div className="drop-formats"><span>Supports standard .apk files up to 100MB</span></div></>)}
            </div>
          </div>
        ):(
          <div className="scan-box">
            <div className="scan-radar"><div className="radar-ring r1"/><div className="radar-ring r2"/><div className="radar-ring r3"/><div className="radar-sweep"/><div className="radar-icon-wrap"><Shield size={26} strokeWidth={1.5}/></div></div>
            <div className="scan-stages">{STAGES.map((s,i)=>{const Icon=s.icon;const done=i<stageIdx,active=i===stageIdx;return(<div key={i} className={`scan-stage ${done?"done":""} ${active?"active":""}`}><div className="stage-dot">{done?<CheckCircle size={12}/>:active?<div className="dot-pulse"/>:<div className="dot-idle"/>}</div><Icon size={13}/><span>{s.label}</span>{done&&<CheckCircle size={11} className="stage-check"/>}</div>);})}</div>
            <div className="scan-progress-wrap"><div className="scan-progress-fill" style={{width:`${progress}%`}}/></div>
            <div className="scan-pct">{progress}% {STAGES[Math.min(stageIdx,STAGES.length-1)]?.label}</div>
          </div>
        )}
        {status==="error"&&<div className="upload-err"><AlertTriangle size={14}/> {errMsg}</div>}
        {file&&status==="idle"&&<button className="analyze-btn" onClick={analyze}><Zap size={16}/>Run Security Analysis</button>}
        <div className="features-grid">{FEATURES.map(([Icon,title,desc])=><div key={title} className="feature-card"><div className="feature-icon"><Icon size={16}/></div><div><div className="feature-title">{title}</div><div className="feature-desc">{desc}</div></div></div>)}</div>
        <p className="upload-footer">Local static analysis by default | External lookups are configurable | Results may be cached locally</p>
      </div>
    </div>
  );
}

function VTBadge({vt, score}){
  if(!vt)return null;
  const detected=vt.detected??0,total=vt.total??0;
  const unavailable=!vt.available || vt.status==="disabled" || vt.status==="error";
  const pending=vt.pending;
  const notFound=vt.not_found&&total===0;
  const highInternalNoDetections = detected === 0 && total > 0 && !pending && !notFound && !unavailable && score >= 60;
  const color = unavailable || pending || notFound ? "var(--fg-dim)" : highInternalNoDetections ? "var(--c-high)" : detected === 0 ? "var(--c-low)" : detected <= 5 ? "var(--c-medium)" : detected <= 20 ? "var(--c-high)" : "var(--c-critical)";
  const label = unavailable ? `VT ${vt.status||"unavailable"}` : pending ? "Analysis pending..." : notFound ? "Hash not found — file not uploaded" : highInternalNoDetections ? `0/${total} — High internal risk` : detected === 0 ? `0/${total} detections` : `${detected}/${total} engines detected`;
  return(<div className="vt-badge" style={{borderColor:`${color}44`,background:`${color}11`}}>
    <Globe size={14} color={color}/>
    <span style={{color,fontSize:11,fontWeight:700}} title={vt.reason||""}>{label}</span>
    {vt.sha256&&!pending&&vt.available&&<a href={`https://www.virustotal.com/gui/file/${vt.sha256}`} target="_blank" rel="noreferrer" className="vt-link">View</a>}
  </div>);
}

function RiskGauge({score}){const color=gaugeColor(score);return(<div className="gauge-wrap"><div className="gauge-ring-outer" style={{"--gc":color}}><CircularProgressbar value={score} text={`${score}`} styles={buildStyles({rotation:0.625,strokeLinecap:"round",pathColor:color,textColor:color,trailColor:"rgba(255,255,255,0.06)",textSize:"22px"})} circleRatio={0.75}/></div><div className="gauge-label" style={{color}}>{gaugeLabel(score)}</div><div className="gauge-sub">Risk Score / 100</div></div>);}

function StatBar({counts}){return(<div className="stat-bar">{[["critical","Critical","var(--c-critical)"],["high","High","var(--c-high)"],["medium","Medium","var(--c-medium)"],["low","Low","var(--c-low)"]].map(([k,l,c])=><div key={k} className="stat-cell"><span className="stat-num" style={{color:c}}>{counts[k]??0}</span><span className="stat-lbl">{l}</span></div>)}</div>);}

function FindingCard({finding}){const [open,setOpen]=useState(false);const {color,icon:SevIcon,label}=sev(finding.severity);const title=finding.title||finding.name||finding.type||"Finding";return(<div className="finding-card" style={{"--sev-color":color}}><div className="finding-header" onClick={()=>setOpen(!open)} role="button" tabIndex={0} onKeyDown={(e)=>e.key==="Enter"&&setOpen(!open)}><div className="finding-left"><SevIcon size={15} color={color}/><span className="finding-title">{title}</span></div><div className="finding-right"><span className="sev-badge" style={{background:`${color}22`,color,borderColor:`${color}55`}}>{label}</span>{open?<ChevronDown size={14}/>:<ChevronRight size={14}/>}</div></div>{open&&(<div className="finding-body">{(finding.explanation||finding.description||finding.detail||"")&&<p className="finding-desc">{finding.explanation||finding.description||finding.detail||""}</p>}{finding.recommendation&&<div className="finding-rec"><span className="rec-label">Recommendation</span><p>{finding.recommendation}</p></div>}{finding.location&&<div className="finding-meta"><Terminal size={11}/>&nbsp;{finding.location}</div>}{finding.cve&&<div className="finding-meta cve">CVE: {finding.cve}</div>}</div>)}</div>);}

function FindingsPanel({findings}){const [filter,setFilter]=useState("ALL");const tabs=["ALL","CRITICAL","HIGH","MEDIUM","LOW"];const visible=filter==="ALL"?findings:findings.filter(f=>(f.severity||"").toUpperCase()===filter.toUpperCase());return(<div className="panel"><div className="panel-head"><AlertOctagon size={16}/>Security Findings<span className="panel-count">{findings.length} total</span></div><div className="tab-row">{tabs.map(t=><button key={t} className={`tab-btn ${filter===t?"active":""}`} onClick={()=>setFilter(t)}>{t} <span className="tab-count">{t==="ALL"?findings.length:findings.filter(f=>(f.severity||"").toUpperCase()===t.toUpperCase()).length}</span></button>)}</div><div className="findings-list">{visible.length===0?<div className="empty-state">No findings at this severity.</div>:visible.map((f,i)=><FindingCard key={i} finding={f}/>)}</div></div>);}

function AIPanel({ai}){if(!ai)return null;const text=typeof ai==="string"?ai:(ai.threat_summary||ai.summary||ai.analysis||"No analysis available");const factors=ai.risk_factors||ai.key_findings||[];const recs=ai.recommendations||ai.mitigations||[];return(<div className="panel ai-panel"><div className="panel-head"><Cpu size={16}/>AI Threat Analysis<span className="ai-badge">LLaMA 3.3 70B Groq</span></div><div className="ai-body"><div className="ai-typing"><p className="ai-text">{text}</p></div>{factors.length>0&&<div className="ai-section"><div className="ai-section-head">Key Risk Factors</div>{factors.map((r,i)=><div key={i} className="ai-factor-row"><Zap size={12} color="var(--c-medium)"/>{r}</div>)}</div>}{recs.length>0&&<div className="ai-section"><div className="ai-section-head">Recommendations</div>{recs.map((r,i)=><div key={i} className="ai-factor-row"><CheckCircle size={12} color="var(--c-low)"/>{r}</div>)}</div>}</div></div>);}

function ThreatIntelPanel({intel}){if(!intel||(!intel.hash_match&&!intel.phishing_urls?.length))return null;const level=intel.threat_level||"clean";const color=level==="malicious"?"var(--c-critical)":level==="suspicious"?"var(--c-high)":"var(--c-low)";return(<div className="panel" style={{marginBottom:16,borderLeft:`3px solid ${color}`}}><div className="panel-head"><Shield size={16}/>Threat Intelligence<span className="ai-badge" style={{background:`${color}22`,color,borderColor:`${color}44`}}>{level.toUpperCase()}</span><span style={{marginLeft:"auto",fontSize:11,color:"var(--fg-dim)"}}>{(intel.intel_source||[]).join(" + ")}</span></div><div style={{padding:"10px 16px",display:"flex",flexDirection:"column",gap:10}}>{intel.hash_match&&(<div style={{padding:"8px 12px",borderRadius:6,background:"var(--c-critical)11",border:"1px solid var(--c-critical)44"}}><div style={{fontSize:12,fontWeight:700,color:"var(--c-critical)"}}>Hash Match — MalwareBazaar</div><div style={{fontSize:11,color:"var(--fg-dim)",marginTop:4}}>Family: {intel.hash_match.family} | First seen: {intel.hash_match.first_seen}</div><div style={{fontSize:11,color:"var(--fg-dim)"}}>{(intel.hash_match.tags||[]).join(", ")}</div></div>)}{intel.phishing_urls?.length>0&&(<div><div style={{fontSize:11,fontWeight:700,color:"var(--c-high)",marginBottom:6}}>PHISHING URLs DETECTED ({intel.phishing_urls.length})</div>{intel.phishing_urls.map((u,i)=><div key={i} style={{fontFamily:"monospace",fontSize:11,color:"var(--c-high)",padding:"4px 8px",background:"var(--c-high)11",borderRadius:4,marginBottom:3}}>{u}</div>)}</div>)}</div></div>);}
function ScoreBreakdown({breakdown}){if(!breakdown||breakdown.length===0)return null;return(<div className="panel" style={{marginBottom:16}}><div className="panel-head"><Activity size={16}/>Score Breakdown</div><table className="mitre-table" style={{width:"100%"}}><thead><tr><th>Category</th><th>Points</th><th>Detail</th></tr></thead><tbody>{breakdown.map((b,i)=><tr key={i}><td>{b.category}</td><td style={{color:"var(--c-high)",fontWeight:700}}>+{b.points}</td><td style={{color:"var(--fg-dim)"}}>{b.detail}</td></tr>)}</tbody></table></div>);}
function MitreTable({entries}){if(!entries||entries.length===0)return null;return(<div className="panel mitre-panel"><div className="panel-head"><Eye size={16}/>MITRE ATT&CK Mobile<span className="mitre-count">{entries.length} techniques</span></div><div className="mitre-scroll"><table className="mitre-table"><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Confidence</th></tr></thead><tbody>{entries.map((e,i)=>{const id=e.technique_id||e.id||"T????",name=e.name||e.technique_name||"Unknown",tactic=e.tactic||"Unknown",conf=Math.round((e.confidence||1)*100),color=mitreColor(tactic);return(<tr key={i} className="mitre-row"><td><a href={`https://attack.mitre.org/techniques/${id}`} target="_blank" rel="noreferrer" className="mitre-id">{id}</a></td><td className="mitre-name">{name}</td><td><span className="mitre-tac" style={{background:`${color}22`,color,borderColor:`${color}44`}}>{tactic}</span></td><td><div className="conf-bar-wrap"><div className="conf-bar" style={{width:`${conf}%`,background:color}}/><span className="conf-pct">{conf}%</span></div></td></tr>);})}</tbody></table></div></div>);}

function PermissionsPanel({permissions}){const _p=Array.isArray(permissions)?permissions:(permissions?.dangerous??[]);const permsArr=_p.map(p=>typeof p==="object"?p.permission:p).filter(Boolean);if(!permsArr||permsArr.length===0)return null;const danger=permsArr.filter(p=>DANGEROUS.some(k=>p.includes(k)));const normal=permsArr.filter(p=>!danger.includes(p));return(<div className="panel"><div className="panel-head"><Lock size={16}/>Permissions<span className="panel-count">{permissions.length} total</span>{danger.length>0&&<span className="danger-count">{danger.length} dangerous</span>}</div><div className="perm-grid">{danger.map((p,i)=><div key={i} className="perm-chip danger-chip"><AlertTriangle size={11}/>{p.replace("android.permission.","")}</div>)}{normal.map((p,i)=><div key={i} className="perm-chip">{p.replace("android.permission.","")}</div>)}</div></div>);}

function AppInfoPanel({info, vt, score}){if(!info)return null;const rows=[["Package",info.package_name||info.package],["Version",info.version||info.version_name],["Min SDK",info.min_sdk],["Target SDK",info.target_sdk],["SHA-256",vt?.sha256?vt.sha256.slice(0,16)+"...":null]].filter(([,v])=>v);return(<div className="panel"><div className="panel-head"><Package size={16}/>App Information</div><div className="info-table">{rows.map(([k,v])=><div key={k} className="info-row"><span className="info-key">{k}</span><span className="info-val">{v}</span></div>)}</div><div style={{padding:"0 14px 12px"}}><VTBadge vt={vt} score={score}/></div></div>);}

function BehavioralPanel({behavioral}){
  if(!behavioral||(!behavioral.runtime_indicators?.length&&!behavioral.dynamic_behaviors?.length&&!behavioral.anti_analysis_techniques?.length))return null;
  const runtime=behavioral.runtime_indicators||[];
  const dynamic=behavioral.dynamic_behaviors||[];
  const anti=behavioral.anti_analysis_techniques||[];
  const sevColor=(s)=>s==="Critical"?"var(--c-critical)":s==="High"?"var(--c-high)":s==="Medium"?"var(--c-medium)":"var(--c-low)";
  const catColor=(c)=>c==="Surveillance"?"#8b5cf6":c==="Data Exfiltration"?"#ef4444":c==="Persistence"?"#f97316":c==="Credential Theft"?"#ec4899":c==="Privilege Escalation"?"#eab308":"#6b7280";
  return(
    <div className="panel" style={{marginTop:16}}>
      <div className="panel-head"><Activity size={16}/>Dynamic Behavior Analysis
        <span className="panel-count">{dynamic.length} behaviors</span>
        {behavioral.evasion_detected&&<span className="danger-count">Evasion Detected</span>}
      </div>
      <div style={{padding:"12px 16px",display:"flex",flexDirection:"column",gap:16}}>
        {dynamic.length>0&&(
          <div>
            <div style={{fontSize:11,fontWeight:700,color:"var(--c-medium)",letterSpacing:"0.1em",marginBottom:8,textTransform:"uppercase"}}>Behavioral Threats</div>
            <div style={{display:"flex",flexDirection:"column",gap:8}}>
              {dynamic.map((b,i)=>(
                <div key={i} style={{padding:"10px 14px",borderRadius:8,background:`${sevColor(b.severity)}11`,border:`1px solid ${sevColor(b.severity)}44`,borderLeft:`3px solid ${sevColor(b.severity)}`}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:4}}>
                    <span style={{fontWeight:700,fontSize:13,color:"var(--fg)"}}>{b.behavior}</span>
                    <span style={{fontSize:11,fontWeight:700,color:sevColor(b.severity),padding:"2px 8px",borderRadius:4,background:`${sevColor(b.severity)}22`,border:`1px solid ${sevColor(b.severity)}44`}}>{b.severity.toUpperCase()}</span>
                  </div>
                  <p style={{fontSize:12,color:"var(--fg-dim)",margin:0,lineHeight:1.6}}>{b.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}
        {runtime.length>0&&(
          <div>
            <div style={{fontSize:11,fontWeight:700,color:"var(--c-medium)",letterSpacing:"0.1em",marginBottom:8,textTransform:"uppercase"}}>Runtime Indicators ({runtime.length})</div>
            <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
              {runtime.map((r,i)=>(
                <div key={i} title={r.description} style={{padding:"4px 10px",borderRadius:6,background:`${catColor(r.category)}18`,border:`1px solid ${catColor(r.category)}44`,fontSize:11,color:catColor(r.category),fontWeight:600,cursor:"default"}}>
                  {r.indicator}
                </div>
              ))}
            </div>
          </div>
        )}
        {anti.length>0&&(
          <div>
            <div style={{fontSize:11,fontWeight:700,color:"var(--c-critical)",letterSpacing:"0.1em",marginBottom:8,textTransform:"uppercase"}}>Anti-Analysis Techniques ({anti.length})</div>
            <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
              {anti.map((a,i)=>(
                <div key={i} title={a.description} style={{padding:"4px 10px",borderRadius:6,background:"var(--c-critical)18",border:"1px solid var(--c-critical)44",fontSize:11,color:"var(--c-critical)",fontWeight:600}}>
                  {a.technique}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ScanHistoryPanel(){
  const [history,setHistory]=React.useState([]);
  const [loading,setLoading]=React.useState(true);
  React.useEffect(()=>{
    fetch(`${API}/history`)
      .then(r=>r.json())
      .then(d=>{ setHistory(d.scans||[]); setLoading(false); })
      .catch(()=>setLoading(false));
  },[]);
  if(loading)return null;
  if(history.length===0)return null;
  const scoreColor=(s)=>s>=80?"var(--c-critical)":s>=60?"var(--c-high)":s>=40?"var(--c-medium)":s>=20?"var(--c-low)":"#22c55e";
  return(
    <div className="panel" style={{marginBottom:"16px"}}>
      <div className="panel-head"><Clock size={16}/>Recent Scans<span className="panel-count">{history.length} scans</span></div>
      <div style={{padding:"8px"}}>
        {[...history].reverse().slice(0,5).map((s,i)=>(
          <div key={i} style={{display:"flex",alignItems:"center",gap:"10px",padding:"7px 8px",borderRadius:"6px",cursor:"pointer",transition:"background 0.15s"}}
            onMouseEnter={e=>e.currentTarget.style.background="var(--bg-card-h)"}
            onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
            <div style={{width:"36px",height:"36px",borderRadius:"8px",background:`${scoreColor(s.risk_score)}22`,border:`1px solid ${scoreColor(s.risk_score)}44`,display:"flex",alignItems:"center",justifyContent:"center",fontFamily:"var(--font-mono)",fontSize:"12px",fontWeight:"bold",color:scoreColor(s.risk_score),flexShrink:0}}>{s.risk_score}</div>
            <div style={{minWidth:0,flex:1}}>
              <div style={{fontSize:"12px",fontWeight:"500",color:"var(--text-0)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{s.filename}</div>
              <div style={{fontSize:"10px",color:"var(--text-2)",fontFamily:"var(--font-mono)"}}>{s.package||s.package_name||"Unknown package"}</div>
            </div>
            <div style={{fontSize:"10px",color:"var(--text-2)",flexShrink:0}}>{new Date(s.scan_time).toLocaleTimeString()}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SmaliPanel({smali}){
  const [activeTab,setActiveTab]=useState(0);
  const [showRaw,setShowRaw]=useState(false);
  if(!smali||!smali.available||!smali.methods||smali.methods.length===0)return null;
  const threatColor=(t)=>t==="critical"?"var(--c-critical)":t==="high"?"var(--c-high)":t==="medium"?"var(--c-medium)":"var(--c-low)";
  const m=smali.methods[activeTab]||smali.methods[0];
  return(
    <div className="panel" style={{marginTop:16}}>
      <div className="panel-head">
        <Terminal size={16}/>LLM Smali Deobfuscation
        <span className="panel-count">{smali.method_count} methods</span>
        <span className="ai-badge" style={{background:`${threatColor(smali.overall_threat_level)}22`,color:threatColor(smali.overall_threat_level),borderColor:`${threatColor(smali.overall_threat_level)}44`}}>{smali.overall_threat_level?.toUpperCase()}</span>
        <span style={{marginLeft:"auto",fontSize:11,color:"var(--fg-dim)"}}>Groq LLaMA 3.3 70B</span>
      </div>
      <div style={{padding:"8px 16px 0",display:"flex",gap:6,flexWrap:"wrap"}}>
        {smali.methods.map((m,i)=>(
          <button key={i} onClick={()=>setActiveTab(i)}
            style={{padding:"4px 10px",borderRadius:4,fontSize:11,fontFamily:"monospace",cursor:"pointer",
              background:activeTab===i?`${threatColor(m.threat_level)}22`:"var(--bg)",
              color:activeTab===i?threatColor(m.threat_level):"var(--fg-dim)",
              border:`1px solid ${activeTab===i?threatColor(m.threat_level)+"44":"var(--border)"}`}}>
            {m.method_name}()
            <span style={{marginLeft:4,fontSize:9,fontWeight:700,color:threatColor(m.threat_level)}}>{m.threat_level?.toUpperCase()}</span>
          </button>
        ))}
      </div>
      <div style={{padding:"12px 16px"}}>
        <div style={{fontSize:11,color:"var(--fg-dim)",marginBottom:8,fontFamily:"monospace"}}>{m.class_name} → {m.method_name}{m.descriptor}</div>
        {m.threat_summary&&<div style={{padding:"8px 12px",borderRadius:6,background:`${threatColor(m.threat_level)}11`,border:`1px solid ${threatColor(m.threat_level)}33`,fontSize:11,color:"var(--fg)",marginBottom:10}}>{m.threat_summary}</div>}
        {m.techniques?.length>0&&(
          <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:10}}>
            {m.techniques.map((t,i)=><span key={i} style={{fontSize:10,padding:"2px 8px",borderRadius:3,background:"var(--c-high)22",color:"var(--c-high)",border:"1px solid var(--c-high)44"}}>{t}</span>)}
          </div>
        )}
        <div style={{display:"flex",gap:8,marginBottom:8}}>
          <button onClick={()=>setShowRaw(false)} style={{padding:"4px 12px",borderRadius:4,fontSize:11,cursor:"pointer",background:!showRaw?"var(--accent)":"var(--bg)",color:!showRaw?"#000":"var(--fg-dim)",border:"1px solid var(--border)"}}>Python Pseudocode</button>
          <button onClick={()=>setShowRaw(true)} style={{padding:"4px 12px",borderRadius:4,fontSize:11,cursor:"pointer",background:showRaw?"var(--accent)":"var(--bg)",color:showRaw?"#000":"var(--fg-dim)",border:"1px solid var(--border)"}}>Raw Smali</button>
        </div>
        <pre style={{background:"var(--bg)",border:"1px solid var(--border)",borderRadius:6,padding:12,fontSize:10,fontFamily:"monospace",color:"var(--fg)",overflow:"auto",maxHeight:200,margin:0,whiteSpace:"pre-wrap"}}>
          {showRaw?(m.smali_preview||m.smali_full||""):(m.pseudocode||"# No pseudocode available")}
        </pre>
      </div>
    </div>
  );
}

function DynamicPanel({dynamic}){
  if(!dynamic||!dynamic.dynamic_available)return null;
  const apis=dynamic.api_calls_intercepted||[];
  const network=dynamic.network_calls||[];
  const files=dynamic.file_operations||[];
  const crypto=dynamic.crypto_operations||[];
  const sevColor=(s)=>s==="critical"?"var(--c-critical)":s==="high"?"var(--c-high)":s==="medium"?"var(--c-medium)":"var(--c-low)";
  const riskScore=dynamic.dynamic_risk_score||0;
  const riskColor=riskScore>=80?"var(--c-critical)":riskScore>=60?"var(--c-high)":riskScore>=40?"var(--c-medium)":"var(--c-low)";
  return(
    <div className="panel" style={{marginTop:16}}>
      <div className="panel-head"><Zap size={16}/>Dynamic Analysis
        <span className="panel-count">{dynamic.total_events} events</span>
        {dynamic.analysis_method==="frida_live_instrumentation" ? <span className="ai-badge" style={{background:"var(--c-critical)22",color:"var(--c-critical)",borderColor:"var(--c-critical)44"}}>LIVE FRIDA</span> : <span className="ai-badge" style={{background:"var(--c-medium)22",color:"var(--c-medium)",borderColor:"var(--c-medium)44"}}>OBSERVED SANDBOX</span>}
        <span style={{marginLeft:"auto",fontSize:12,color:riskColor,fontWeight:800,background:`${riskColor}22`,padding:"2px 10px",borderRadius:4,border:`1px solid ${riskColor}44`}}>RISK: {riskScore}/100</span>
      </div>
      <div style={{padding:"10px 16px 4px",fontSize:12,color:"var(--fg-dim)"}}>{dynamic.summary}</div>
      <div style={{display:"flex",gap:12,padding:"8px 16px 12px",borderBottom:"1px solid var(--border)"}}>
        {[["API Calls",apis.length,"var(--c-critical)"],["Network",network.length,"var(--c-high)"],["File Ops",files.length,"var(--c-medium)"],["Crypto",crypto.length,"var(--c-low)"]].map(([label,count,color])=>(
          <div key={label} style={{flex:1,padding:"8px 12px",borderRadius:6,background:`${color}11`,border:`1px solid ${color}33`,textAlign:"center"}}>
            <div style={{fontSize:20,fontWeight:800,color}}>{count}</div>
            <div style={{fontSize:10,color:"var(--fg-dim)",marginTop:2,letterSpacing:"0.05em"}}>{label}</div>
          </div>
        ))}
      </div>
      <div style={{padding:"12px 16px 16px",display:"flex",flexDirection:"column",gap:14}}>
        {apis.length>0&&(
          <div>
            <div style={{display:"flex",alignItems:"center",gap:6,fontSize:11,fontWeight:700,color:"var(--c-critical)",letterSpacing:"0.1em",marginBottom:8,textTransform:"uppercase"}}><Terminal size={12}/>API Calls Intercepted ({apis.length})</div>
            <div style={{display:"flex",flexDirection:"column",gap:6}}>
              {apis.map((a,i)=>(
                <div key={i} style={{padding:"10px 12px",borderRadius:6,background:`${sevColor(a.threat_level)}0d`,border:`1px solid ${sevColor(a.threat_level)}33`,borderLeft:`3px solid ${sevColor(a.threat_level)}`}}>
                  <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                    <span style={{fontFamily:"monospace",fontSize:12,color:"var(--fg)",fontWeight:700}}>{a.api}</span>
                    <span style={{fontSize:10,fontWeight:800,color:sevColor(a.threat_level),padding:"2px 8px",borderRadius:3,background:`${sevColor(a.threat_level)}22`,letterSpacing:"0.05em"}}>{(a.threat_level||"").toUpperCase()}</span>
                  </div>
                  <div style={{fontSize:10,color:"var(--fg-dim)",marginTop:3,fontFamily:"monospace"}}>{a.class}</div>
                  {a.args?.length>0&&<div style={{fontSize:10,color:"var(--fg-dim)",fontFamily:"monospace",marginTop:3,padding:"3px 6px",background:"var(--bg)",borderRadius:3}}>args: [{a.args.join(", ")}]</div>}
                </div>
              ))}
            </div>
          </div>
        )}
        {network.length>0&&(
          <div>
            <div style={{display:"flex",alignItems:"center",gap:6,fontSize:11,fontWeight:700,color:"var(--c-high)",letterSpacing:"0.1em",marginBottom:8,textTransform:"uppercase"}}><Wifi size={12}/>Network Calls ({network.length})</div>
            {network.map((n,i)=>(
              <div key={i} style={{padding:"8px 12px",borderRadius:6,background:"var(--c-high)0d",border:"1px solid var(--c-high)33",marginBottom:4}}>
                <span style={{fontFamily:"monospace",fontSize:11,color:"var(--c-high)",fontWeight:700}}>{n.method||"GET"}</span>
                <span style={{fontFamily:"monospace",fontSize:11,color:"var(--fg-dim)",marginLeft:8}}>{n.url||n.host||""}</span>
              </div>
            ))}
          </div>
        )}
        {files.length>0&&(
          <div>
            <div style={{display:"flex",alignItems:"center",gap:6,fontSize:11,fontWeight:700,color:"var(--c-medium)",letterSpacing:"0.1em",marginBottom:8,textTransform:"uppercase"}}><Database size={12}/>File Operations ({files.length})</div>
            {files.map((f,i)=>(
              <div key={i} style={{padding:"8px 12px",borderRadius:6,background:"var(--c-medium)0d",border:"1px solid var(--c-medium)33",fontFamily:"monospace",fontSize:11,marginBottom:4,display:"flex",alignItems:"center",gap:8}}>
                <span style={{color:"var(--c-medium)",fontWeight:800,padding:"1px 6px",background:"var(--c-medium)22",borderRadius:3}}>{(f.operation||"").toUpperCase()}</span>
                <span style={{color:"var(--fg)",flex:1}}>{f.path}</span>
                <span style={{color:"var(--fg-dim)",fontSize:10}}>{f.size_bytes} bytes</span>
              </div>
            ))}
          </div>
        )}
        {crypto.length>0&&(
          <div>
            <div style={{display:"flex",alignItems:"center",gap:6,fontSize:11,fontWeight:700,color:"var(--c-low)",letterSpacing:"0.1em",marginBottom:8,textTransform:"uppercase"}}><Lock size={12}/>Crypto Operations ({crypto.length})</div>
            {crypto.map((c,i)=>(
              <div key={i} style={{padding:"10px 12px",borderRadius:6,background:"var(--c-low)0d",border:"1px solid var(--c-low)33",marginBottom:4,display:"flex",justifyContent:"space-between",alignItems:"center"}}>
                <div>
                  <div style={{fontSize:12,fontWeight:800,color:"var(--c-low)",fontFamily:"monospace"}}>{c.algorithm}</div>
                  <div style={{fontSize:11,color:"var(--fg-dim)",marginTop:2}}>{c.purpose}</div>
                </div>
                <Lock size={14} color="var(--c-low)" opacity={0.5}/>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}


function ConfusionMatrixPanel(){
  const [data,setData]=React.useState(null);
  const [loading,setLoading]=React.useState(false);

  const load=async()=>{
    setLoading(true);
    try{
      const r=await fetch(`${API}/batch-results`);
      const j=await r.json();
      setData(j);
    }catch(e){console.error(e);}
    setLoading(false);
  };

  // eslint-disable-next-line react-hooks/set-state-in-effect
  React.useEffect(()=>{void load();},[]);

  if(loading) return <div className="card" style={{textAlign:"center",padding:32,color:"var(--fg-dim)"}}>Running batch test...</div>;
  if(!data) return null;

  const m=data.matrix;
  const cells=[
    {label:"True Positive",val:m.tp,color:"var(--c-low)",sub:"Malware correctly detected"},
    {label:"False Positive",val:m.fp,color:"var(--c-medium)",sub:"Benign flagged as malware"},
    {label:"False Negative",val:m.fn,color:"var(--c-high)",sub:"Malware missed"},
    {label:"True Negative",val:m.tn,color:"var(--c-low)",sub:"Benign correctly cleared"},
  ];
  const metrics=[
    {label:"Accuracy", val:(m.accuracy*100).toFixed(1)+"%"},
    {label:"Precision",val:(m.precision*100).toFixed(1)+"%"},
    {label:"Recall",   val:(m.recall*100).toFixed(1)+"%"},
    {label:"F1 Score", val:(m.f1_score*100).toFixed(1)+"%"},
  ];

  return(
    <div className="card" style={{background:"var(--bg-card)",border:"1px solid var(--border)",borderRadius:"var(--radius-lg)"}}>
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:16}}>
        <span style={{fontSize:18}}>📊</span>
        <h3 style={{margin:0,fontSize:14,color:"var(--fg)"}}>ML Classifier — Batch Test Results</h3>
        <span style={{marginLeft:"auto",fontSize:11,color:"var(--fg-dim)"}}>{m.total_samples} samples · {m.correct} correct</span>
      </div>

      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,marginBottom:16}}>
        {cells.map((c,i)=>(
          <div key={i} style={{background:"var(--panel-bg)",borderRadius:8,padding:"12px 16px",border:`1px solid ${c.color}44`}}>
            <div style={{fontSize:28,fontWeight:700,color:c.color}}>{c.val}</div>
            <div style={{fontSize:12,fontWeight:600,color:"var(--fg)"}}>{c.label}</div>
            <div style={{fontSize:10,color:"var(--fg-dim)",marginTop:2}}>{c.sub}</div>
          </div>
        ))}
      </div>

      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8}}>
        {metrics.map((mt,i)=>(
          <div key={i} style={{textAlign:"center",background:"var(--panel-bg)",borderRadius:6,padding:"8px 4px",border:"1px solid var(--border)"}}>
            <div style={{fontSize:20,fontWeight:700,color:"var(--accent)"}}>{mt.val}</div>
            <div style={{fontSize:10,color:"var(--fg-dim)"}}>{mt.label}</div>
          </div>
        ))}
      </div>

      <div style={{marginTop:16}}>
        <div style={{fontSize:11,color:"var(--fg-dim)",marginBottom:6}}>Detection breakdown ({m.total_samples} APKs)</div>
        <div style={{height:8,borderRadius:4,overflow:"hidden",display:"flex"}}>
          <div style={{flex:m.tp,background:"var(--c-low)"}} title={`TP: ${m.tp}`}/>
          <div style={{flex:m.tn,background:"#22c55e55"}} title={`TN: ${m.tn}`}/>
          <div style={{flex:m.fp,background:"var(--c-medium)"}} title={`FP: ${m.fp}`}/>
          <div style={{flex:m.fn,background:"var(--c-high)"}} title={`FN: ${m.fn}`}/>
        </div>
        <div style={{display:"flex",gap:12,marginTop:6,flexWrap:"wrap"}}>
          {[["TP",m.tp,"var(--c-low)"],["TN",m.tn,"#22c55e"],["FP",m.fp,"var(--c-medium)"],["FN",m.fn,"var(--c-high)"]].map(([l,v,c])=>(
            <span key={l} style={{fontSize:10,color:"var(--fg-dim)"}}>
              <span style={{color:c,fontWeight:700}}>{l}</span> {v}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

function ResultsDashboard({data,onReset}){
  const findings=data.ai_analysis?.findings??data.findings??[];
  const score=(data.score?.score??data.risk_score??0);
  const aiAnalysis=data.ai_analysis??data.ai??data.analysis??null;
  const mitre=data.mitre_mappings??data.ai_analysis?.mitre_techniques??data.score?.mitre??[];
  const perms=Array.isArray(data.permissions)?data.permissions:(data.permissions?.dangerous??data.permissions?.all??[]);
  const appInfo=data.app_info??null;
  const vt=data.virustotal??null;
  const behavioral=data.behavioral_analysis??null;
  const dynamicData=data.dynamic??null;
  const smaliData=data.smali_analysis??null;
  const breakdown=data.score_breakdown??[];
  const staticScore=data.static_score??score;
  const dynamicScore=data.dynamic_score??0;
  const scoringMode=data.scoring_mode??"static_only";
  const threatIntel=data.threat_intel??null;
  const counts=findings.reduce((acc,f)=>{const raw=(f.severity||"low");const k=raw.toLowerCase();acc[k]=(acc[k]||0)+1;return acc;},{});

  const downloadReport=async()=>{
    try{
      const resp=await fetch(`${API}/report`,{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify(data)
      });
      if(!resp.ok) throw new Error("Report generation failed");
      const blob=await resp.blob();
      const url=URL.createObjectURL(blob);
      const a=document.createElement("a");
      a.href=url;
      a.download=`APKGuard_${data.filename||"report"}_${Date.now()}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }catch(e){
      console.error("Report error:",e);
      alert("Report generation failed: "+e.message);
    }
  }

  const exportYaraRule = () => {
    if (!appInfo) return;
    const ruleName = appInfo.package_name?.replace(/\./g, '_') || appInfo.package?.replace(/\./g, '_') || "APKGuard_Malware";
    const sha256 = vt?.sha256 || "UNKNOWN_HASH";
    const yaraContent = `rule ${ruleName} {
    meta:
        description = "Auto-generated by APKGuard AI v2.0"
        author = "null Pointers"
        date = "${new Date().toISOString().split('T')[0]}"
        hash_sha256 = "${sha256}"
    strings:
        $pkg = "${appInfo.package_name || appInfo.package || "UNKNOWN_PACKAGE"}"
    condition:
        $pkg or hash.sha256(0, filesize) == "${sha256}"
}`;
    const blob = new Blob([yaraContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${ruleName}.yar`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return(
    <div className="dash-root">
      <div className="scanline" aria-hidden/><div className="grid-bg" aria-hidden/>
      <header className="dash-header">
        <div className="logo-wrap-sm"><Shield size={20} strokeWidth={1.5}/><span>APKGuard <b>AI</b></span></div>
        {appInfo&&<div className="app-info-pill"><Package size={12}/><span>{appInfo.package_name||appInfo.package||appInfo.name}</span>{(appInfo.version||appInfo.version_name)&&<span className="app-ver">v{appInfo.version||appInfo.version_name}</span>}</div>}
        <div className="header-actions">
          <button className="dl-btn" onClick={downloadReport}><Download size={14}/>Download Report</button>
          <button className="dl-btn" onClick={exportYaraRule} style={{ marginLeft: "8px", borderColor: "var(--c-high)", color: "var(--c-high)" }}><FileText size={14}/>Export YARA</button>
          <button className="reset-btn" onClick={onReset}>New Scan</button>
        </div>
      </header>
      <div className="hero-row">
        <div className="gauge-card">
          <RiskGauge score={score}/>
          <div style={{display:"flex",gap:5,justifyContent:"center",marginTop:10,flexWrap:"wrap",width:"100%",padding:"0 4px"}}>
            <span style={{fontSize:9,padding:"2px 6px",borderRadius:4,background:"var(--c-high)22",color:"var(--c-high)",border:"1px solid var(--c-high)44",whiteSpace:"nowrap"}}>S:{staticScore}</span>
            {dynamicScore>0&&<span style={{fontSize:9,padding:"2px 6px",borderRadius:4,background:"var(--c-critical)22",color:"var(--c-critical)",border:"1px solid var(--c-critical)44",whiteSpace:"nowrap"}}>D:{dynamicScore}</span>}
            <span style={{fontSize:9,padding:"2px 6px",borderRadius:4,background:"var(--panel-bg)",color:"var(--fg-dim)",border:"1px solid var(--border)",whiteSpace:"nowrap"}}>{scoringMode==="static_only"?"Static":"frida_live"===scoringMode?"Frida":"Sim"}</span>
          </div>
        </div>
        <div className="stat-card"><div className="stat-card-head"><Activity size={15}/>Finding Summary</div><StatBar counts={counts}/><div className="meta-row">{[[Wifi,"Network"],[Database,"Storage"],[Lock,"Crypto"],[Globe,"Privacy"]].map(([Icon,lbl])=><div key={lbl} className="meta-chip"><Icon size={12}/>{lbl}</div>)}</div></div>
        <AppInfoPanel info={appInfo} vt={vt} score={score}/>
      </div>
      <div className="content-grid"><FindingsPanel findings={findings}/><div className="right-col"><AIPanel ai={aiAnalysis}/><PermissionsPanel permissions={perms}/></div></div>
      <ThreatIntelPanel intel={threatIntel}/><ScoreBreakdown breakdown={breakdown}/><MitreTable entries={mitre}/>
      <BehavioralPanel behavioral={behavioral}/>
      <SmaliPanel smali={smaliData}/>
      <DynamicPanel dynamic={dynamicData}/>
      <ConfusionMatrixPanel/>
      <ScanHistoryPanel/>
    </div>
  );
}

function URLScanner(){
  const [msg,setMsg]=useState("");
  const [result,setResult]=useState(null);
  const [loading,setLoading]=useState(false);
  const riskColor=(r)=>r==="malicious"?"var(--c-critical)":r==="suspicious"?"var(--c-high)":"var(--c-low)";
  const scan=async()=>{
    if(!msg.trim())return;
    setLoading(true);setResult(null);
    try{
      const res=await fetch(`${API}/scan-url`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message:msg})});
      setResult(await res.json());
    }catch(e){setResult({error:e.message});}
    setLoading(false);
  };
  return(
    <div style={{maxWidth:700,margin:"0 auto",padding:"32px 16px"}}>
      <div style={{textAlign:"center",marginBottom:24}}>
        <div style={{display:"flex",alignItems:"center",justifyContent:"center",gap:10,marginBottom:8}}>
          <Shield size={28} strokeWidth={1.5} color="var(--accent)"/>
          <span style={{fontSize:22,fontWeight:800,color:"var(--fg)"}}>APKGuard <b style={{color:"var(--accent)"}}>AI</b></span>
        </div>
        <div style={{fontSize:13,color:"var(--fg-dim)",letterSpacing:"0.15em"}}>WHATSAPP / SMS URL SCANNER</div>
      </div>
      <div className="panel" style={{padding:20}}>
        <div style={{fontSize:12,fontWeight:700,color:"var(--fg-dim)",marginBottom:8,letterSpacing:"0.1em"}}>PASTE SUSPICIOUS MESSAGE OR URL</div>
        <textarea
          value={msg} onChange={e=>setMsg(e.target.value)}
          placeholder="Paste WhatsApp/SMS message or URL here..."
          style={{width:"100%",minHeight:120,background:"var(--bg)",border:"1px solid var(--border)",borderRadius:8,padding:12,color:"var(--fg)",fontSize:13,resize:"vertical",fontFamily:"inherit",boxSizing:"border-box"}}
        />
        <button onClick={scan} disabled={loading||!msg.trim()}
          style={{marginTop:12,width:"100%",padding:"10px 0",background:"var(--accent)",border:"none",borderRadius:8,color:"#000",fontWeight:800,fontSize:14,cursor:"pointer",opacity:loading||!msg.trim()?0.5:1}}>
          {loading?"Scanning...":"Scan for Threats"}
        </button>
      </div>
      {result&&!result.error&&(
        <div className="panel" style={{marginTop:16,padding:20}}>
          <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:16}}>
            <span style={{fontSize:14,fontWeight:700,color:"var(--fg)"}}>Scan Result</span>
            <span style={{padding:"3px 12px",borderRadius:20,fontWeight:800,fontSize:12,background:`${riskColor(result.overall_risk)}22`,color:riskColor(result.overall_risk),border:`1px solid ${riskColor(result.overall_risk)}44`}}>{result.overall_risk.toUpperCase()}</span>
            <span style={{marginLeft:"auto",fontSize:12,color:"var(--fg-dim)"}}>{result.urls_found} URL(s) found</span>
          </div>
          {result.urls.map((u,i)=>(
            <div key={i} style={{marginBottom:12,padding:"12px 14px",borderRadius:8,background:"var(--bg)",border:`1px solid ${riskColor(u.risk_level)}44`,borderLeft:`3px solid ${riskColor(u.risk_level)}`}}>
              <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:6}}>
                <span style={{fontFamily:"monospace",fontSize:12,color:"var(--fg)",wordBreak:"break-all"}}>{u.url}</span>
                <span style={{marginLeft:12,fontSize:11,fontWeight:800,color:riskColor(u.risk_level),whiteSpace:"nowrap"}}>{u.risk_score}/100</span>
              </div>
              {u.in_openphish&&<div style={{fontSize:11,color:"var(--c-critical)",fontWeight:700,marginBottom:4}}>Found in OpenPhish database</div>}
              {u.threats.map((t,j)=><div key={j} style={{fontSize:11,color:"var(--c-critical)",marginBottom:2}}> {t}</div>)}
              {u.suspicious_patterns.map((p,j)=><div key={j} style={{fontSize:11,color:"var(--c-high)",marginBottom:2}}> {p}</div>)}
              <div style={{fontSize:10,color:"var(--fg-dim)",marginTop:4}}>Domain: {u.domain} | TLD: {u.tld}</div>
            </div>
          ))}
        </div>
      )}
      {result?.error&&<div style={{color:"var(--c-critical)",marginTop:12,padding:12,background:"var(--c-critical)11",borderRadius:8}}>Error: {result.error}</div>}
    </div>
  );
}
export default function App(){const [results,setResults]=useState(null);const [tab,setTab]=useState("apk");return(<div>{tab==="apk"?(results?<ResultsDashboard data={results} onReset={()=>setResults(null)}/>:<UploadPage onResults={setResults}/>):<URLScanner/>}<div style={{position:"fixed",bottom:24,left:24,display:"flex",gap:8,zIndex:200}}><button onClick={()=>{setTab("apk");setResults(null);}} style={{padding:"8px 16px",borderRadius:8,background:tab==="apk"?"var(--accent)":"var(--panel-bg)",color:tab==="apk"?"#000":"var(--fg)",border:"1px solid var(--border)",fontWeight:700,cursor:"pointer",fontSize:12}}>APK Scanner</button><button onClick={()=>setTab("url")} style={{padding:"8px 16px",borderRadius:8,background:tab==="url"?"var(--accent)":"var(--panel-bg)",color:tab==="url"?"#000":"var(--fg)",border:"1px solid var(--border)",fontWeight:700,cursor:"pointer",fontSize:12}}>URL Scanner</button></div></div>);}
