import React from 'react';
import { CxBOM } from '../types';
import { StatusBadge } from './StatusBadge';
import { Lock, FileJson, Hash } from 'lucide-react';

interface Props {
  cxbom: CxBOM;
}

export const CxBOMViewer: React.FC<Props> = ({ cxbom }) => {
  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
            <FileJson className="h-5 w-5 text-indigo-400" />
            Context Bill of Materials
          </h2>
          <p className="text-sm text-slate-500 mt-1">
            Cryptographically verifiable record of everything that entered the model context.
          </p>
        </div>
        <div className="text-right">
          <div className="text-xs text-slate-500 mb-1">Integrity Hash</div>
          <code className="text-xs font-mono text-emerald-400 bg-slate-900 px-2 py-1 rounded border border-emerald-500/20">
            {cxbom.integrity.cxbomHash}
          </code>
        </div>
      </div>

      {/* Goal Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="px-4 py-2 bg-slate-800/50 border-b border-slate-800 flex items-center gap-2">
          <Lock className="h-3 w-3 text-slate-400" />
          <h3 className="text-xs font-semibold text-slate-300 uppercase">Goal Binding</h3>
        </div>
        <div className="p-4 grid grid-cols-2 gap-4">
          <div>
            <span className="text-xs text-slate-500 block">Task</span>
            <span className="text-sm text-slate-200">{cxbom.goal.task}</span>
          </div>
          <div>
            <span className="text-xs text-slate-500 block">Policy Version</span>
            <span className="text-sm font-mono text-slate-200">{cxbom.goal.policyVersion}</span>
          </div>
          <div className="col-span-2">
            <span className="text-xs text-slate-500 block mb-1">Constraints</span>
            <div className="flex flex-wrap gap-2">
              {cxbom.goal.constraints.map((c, i) => (
                <span key={i} className="text-xs bg-slate-950 border border-slate-700 px-2 py-1 rounded text-slate-300">
                  {c}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Composition Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
         <div className="px-4 py-2 bg-slate-800/50 border-b border-slate-800 flex items-center gap-2">
          <Hash className="h-3 w-3 text-slate-400" />
          <h3 className="text-xs font-semibold text-slate-300 uppercase">Composition Manifest</h3>
        </div>
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-xs text-slate-500">
              <th className="px-4 py-3 font-medium">Type</th>
              <th className="px-4 py-3 font-medium">Trust Tier</th>
              <th className="px-4 py-3 font-medium">Sanitization</th>
              <th className="px-4 py-3 font-medium">Source SHA-256</th>
            </tr>
          </thead>
          <tbody>
            {cxbom.contextItems.map((item) => (
              <tr key={item.id} className="border-b border-slate-800/50 last:border-0 hover:bg-slate-800/30">
                <td className="px-4 py-3">
                  <div className="flex flex-col">
                    <span className="text-sm text-slate-200 font-mono">{item.type}</span>
                    <span className="text-[10px] text-slate-500">{item.id}</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <StatusBadge tier={item.trustTier} />
                </td>
                <td className="px-4 py-3">
                  <div className="flex flex-col gap-1">
                     <StatusBadge status={item.sanitizationStatus} />
                     {item.signals.length > 0 && (
                       <span className="text-[10px] text-rose-400">Signals: {item.signals.join(', ')}</span>
                     )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <code className="text-[10px] font-mono text-slate-500 bg-slate-950 px-1 py-0.5 rounded">
                    {item.sha256}
                  </code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
