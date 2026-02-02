import React from 'react';
import { TRUST_TIER_COLORS } from '../constants';
import { TrustTier } from '../types';

interface Props {
  tier?: TrustTier;
  status?: string;
  className?: string;
}

export const StatusBadge: React.FC<Props> = ({ tier, status, className = '' }) => {
  if (tier) {
    return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${TRUST_TIER_COLORS[tier]} ${className} uppercase tracking-wider`}>
        {tier}
      </span>
    );
  }
  
  if (status) {
     const colors = status === 'clean' ? 'bg-green-500/10 text-green-400 border-green-500/20' 
        : status === 'masked' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20'
        : 'bg-red-500/10 text-red-400 border-red-500/20';

      return (
      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${colors} ${className} uppercase tracking-wider`}>
        {status}
      </span>
    );
  }

  return null;
};
