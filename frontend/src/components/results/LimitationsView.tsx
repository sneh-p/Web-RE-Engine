import React from 'react';
import { AlertTriangle } from 'lucide-react';

interface LimitationsViewProps {
  limitations: string[];
}

// What the analysis could not do (missing tools, caps hit, refused archives) — shown for every job type
export const LimitationsView: React.FC<LimitationsViewProps> = ({ limitations }) => {
  if (limitations.length === 0) return null;
  return (
    <div className="border border-amber-900/60 rounded-xl bg-amber-950/20 px-4 py-3 space-y-2">
      <div className="flex items-center space-x-2 text-amber-400 text-xs font-bold">
        <AlertTriangle className="w-4 h-4" />
        <span>Analysis limitations ({limitations.length})</span>
      </div>
      <ul className="list-disc pl-5 space-y-1 text-xs text-rea-text">
        {limitations.map((l, i) => (
          <li key={i}>{l}</li>
        ))}
      </ul>
    </div>
  );
};
