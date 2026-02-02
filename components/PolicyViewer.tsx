import React, { useState } from 'react';
import { FileText, ShieldAlert, Code, Table as TableIcon } from 'lucide-react';
import { DEMO_POLICY_YAML, THREAT_MATRIX } from '../constants';

export const PolicyViewer: React.FC = () => {
  const [view, setView] = useState<'matrix' | 'yaml'>('matrix');

  return (
    <div className="h-full flex flex-col bg-slate-950">
      {/* Sub-header */}
      <div className="border-b border-slate-800 bg-slate-900/50 p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">CxFW-PL: Policy Language</h2>
          <p className="text-sm text-slate-500">
            Declarative security policies that map threats to enforcement invariants.
          </p>
        </div>
        <div className="flex bg-slate-900 p-1 rounded-lg border border-slate-800">
          <button
            onClick={() => setView('matrix')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium transition-all ${
              view === 'matrix' 
                ? 'bg-slate-800 text-white shadow-sm border border-slate-700' 
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <TableIcon className="h-3 w-3" />
            Threat Coverage Matrix
          </button>
          <button
            onClick={() => setView('yaml')}
            className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-medium transition-all ${
              view === 'yaml' 
                ? 'bg-slate-800 text-white shadow-sm border border-slate-700' 
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code className="h-3 w-3" />
            Policy Definition (YAML)
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        {view === 'matrix' ? (
          <div className="max-w-6xl mx-auto space-y-4">
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow-xl">
              <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <ShieldAlert className="h-5 w-5 text-rose-400" />
                    <h3 className="text-sm font-semibold text-slate-200 uppercase tracking-wide">Threat-to-Rule Mapping</h3>
                </div>
                <span className="text-xs text-slate-500">Section 8.2.1</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-950/50 text-xs font-semibold text-slate-500 border-b border-slate-800">
                      <th className="px-6 py-4 min-w-[200px]">Threat / Failure Mode</th>
                      <th className="px-6 py-4 min-w-[200px]">Attack Surface</th>
                      <th className="px-6 py-4 min-w-[300px]">CxFW-PL Constructs</th>
                      <th className="px-6 py-4 min-w-[150px]">Enforcement Point</th>
                      <th className="px-6 py-4">Invariants</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {THREAT_MATRIX.map((row, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/20 transition-colors group">
                        <td className="px-6 py-4">
                          <div className="text-sm font-medium text-rose-300 group-hover:text-rose-200">{row.threat}</div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-xs text-slate-400">{row.surface}</div>
                        </td>
                        <td className="px-6 py-4">
                          <code className="text-[10px] font-mono text-indigo-300 bg-indigo-950/30 px-2 py-1 rounded border border-indigo-900/50 block w-fit max-w-full whitespace-pre-wrap">
                            {row.constructs}
                          </code>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-1.5">
                             <div className="h-1.5 w-1.5 rounded-full bg-emerald-500"></div>
                             <span className="text-xs text-slate-300">{row.enforcement}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
                            {row.invariants}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        ) : (
          <div className="max-w-4xl mx-auto h-full flex flex-col">
             <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden flex flex-col h-full shadow-xl">
                <div className="px-4 py-2 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <FileText className="h-4 w-4 text-slate-400" />
                        <span className="text-xs font-mono text-slate-300">policy_bundle.yaml</span>
                    </div>
                    <div className="flex items-center gap-2">
                         <div className="h-2 w-2 rounded-full bg-yellow-500"></div>
                         <span className="text-[10px] text-slate-500 uppercase font-medium">Read Only</span>
                    </div>
                </div>
                <div className="flex-1 overflow-auto bg-[#0d1117] p-4">
                    <pre className="font-mono text-xs leading-relaxed">
                        {DEMO_POLICY_YAML.split('\n').map((line, i) => (
                            <div key={i} className="table-row">
                                <span className="table-cell select-none text-slate-700 text-right pr-4 w-8 border-r border-slate-800/50 mr-4">{i + 1}</span>
                                <span className="table-cell pl-4 whitespace-pre text-slate-300">
                                    {line.replace(/^(.*?)(:)(.*)$/, (match, key, sep, val) => 
                                        `<span class="text-sky-300">${key}</span><span class="text-slate-500">${sep}</span><span class="text-emerald-300">${val}</span>`
                                    ).replace(/#.*$/, match => `<span class="text-slate-600 italic">${match}</span>`)
                                    .replace(/".*?"/g, match => `<span class="text-orange-300">${match}</span>`)
                                    .split('<span').reduce((acc: any[], part, idx) => {
                                        // Simple hack to render HTML strings safely in React for this demo without dangerouslySetInnerHTML on the whole block
                                        // Ideally use a real syntax highlighter lib
                                        if (idx === 0) return [part];
                                        const [content, rest] = part.split('>');
                                        const [inner, end] = rest.split('</span');
                                        let className = "";
                                        if (part.includes('text-sky-300')) className = "text-sky-300";
                                        if (part.includes('text-slate-500')) className = "text-slate-500";
                                        if (part.includes('text-emerald-300')) className = "text-emerald-300";
                                        if (part.includes('text-slate-600')) className = "text-slate-600 italic";
                                        if (part.includes('text-orange-300')) className = "text-orange-300";
                                        
                                        return [...acc, <span key={idx} className={className}>{inner}</span>, end];
                                    }, [])}
                                </span>
                            </div>
                        ))}
                    </pre>
                </div>
             </div>
          </div>
        )}
      </div>
    </div>
  );
};
