import React from 'react';
import { AlertCircle, AlertTriangle, CheckCircle2, Info } from 'lucide-react';

interface BannerProps {
  variant: 'info' | 'warning' | 'error' | 'success';
  title?: string;
  children: React.ReactNode;
}

export const Banner: React.FC<BannerProps> = ({ variant, title, children }) => {
  const getIcon = () => {
    switch (variant) {
      case 'warning':
        return <AlertTriangle size={20} aria-hidden="true" />;
      case 'error':
        return <AlertCircle size={20} aria-hidden="true" />;
      case 'success':
        return <CheckCircle2 size={20} aria-hidden="true" />;
      case 'info':
      default:
        return <Info size={20} aria-hidden="true" />;
    }
  };

  const role = variant === 'error' || variant === 'warning' ? 'alert' : 'status';

  return (
    <div className={`banner banner-${variant}`} role={role}>
      <div style={{ flexShrink: 0, marginTop: '2px' }}>{getIcon()}</div>
      <div>
        {title && <div className="banner-title">{title}</div>}
        <div>{children}</div>
      </div>
    </div>
  );
};
