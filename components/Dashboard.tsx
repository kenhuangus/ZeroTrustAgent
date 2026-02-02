import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Shield, ShieldAlert, CheckCircle, Activity } from 'lucide-react';

const data = [
  { name: 'Baseline', BU: 95, UA: 0, ASR: 88 },
  { name: 'Tool Filter', BU: 92, UA: 3, ASR: 45 },
  { name: 'Context FW', BU: 90, UA: 5, ASR: 2 },
];

export const Dashboard: React.FC = () => {
  return (
    <div className="p-6 space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-slate-400">Total Compilations</h3>
            <Activity className="h-4 w-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold text-white">1,284</div>
          <div className="text-xs text-green-400 mt-1">+12% from last hour</div>
        </div>
        
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-slate-400">Blocked Injections</h3>
            <ShieldAlert className="h-4 w-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-white">142</div>
          <div className="text-xs text-rose-400 mt-1">High severity (A1/A2)</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-slate-400">Sanitization Rate</h3>
            <Shield className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-white">11.4%</div>
          <div className="text-xs text-slate-500 mt-1">Of untrusted inputs</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-4 rounded-lg">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-slate-400">Active Policy</h3>
            <CheckCircle className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white">v1.0.4</div>
          <div className="text-xs text-slate-500 mt-1">Strict Mode</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-lg">
          <h3 className="text-lg font-medium text-white mb-6">Security Evaluation Metrics</h3>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
                <XAxis dataKey="name" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#f1f5f9' }}
                  itemStyle={{ color: '#f1f5f9' }}
                />
                <Legend />
                <Bar dataKey="BU" name="Benign Utility (%)" fill="#10b981" />
                <Bar dataKey="UA" name="Utility Attenuation (%)" fill="#f59e0b" />
                <Bar dataKey="ASR" name="Attack Success Rate (%)" fill="#ef4444" />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 text-xs text-slate-500">
            * Lower ASR is better. Higher BU is better. Context Firewall minimizes ASR with minimal impact on Utility.
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 p-6 rounded-lg">
          <h3 className="text-lg font-medium text-white mb-4">Live Threat Feed</h3>
          <div className="space-y-4">
            {[
              { time: '10:42:01', type: 'tool_coercion', src: 'web_content', action: 'Masked', risk: 'High' },
              { time: '10:41:45', type: 'instruction_override', src: 'user_message', action: 'Masked', risk: 'Medium' },
              { time: '10:40:12', type: 'credential_leak', src: 'retrieved_doc', action: 'Redacted', risk: 'Critical' },
              { time: '10:38:55', type: 'tool_coercion', src: 'web_content', action: 'Masked', risk: 'High' },
              { time: '10:35:20', type: 'jailbreak_attempt', src: 'user_message', action: 'Rejected', risk: 'Critical' },
            ].map((log, idx) => (
              <div key={idx} className="flex items-center justify-between p-3 bg-slate-950/50 rounded border border-slate-800">
                <div className="flex items-center space-x-3">
                  <div className="text-xs font-mono text-slate-500">{log.time}</div>
                  <div>
                    <div className="text-sm font-medium text-rose-300">{log.type}</div>
                    <div className="text-xs text-slate-400">Source: {log.src}</div>
                  </div>
                </div>
                <div className="flex flex-col items-end">
                   <span className="text-xs font-bold text-amber-500">{log.action}</span>
                   <span className="text-[10px] text-slate-600 uppercase tracking-wide">{log.risk}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
