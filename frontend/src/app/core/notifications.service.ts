import { Injectable, signal } from '@angular/core';

export type NoticeKind = 'success' | 'error' | 'info';

export interface Notice {
  id: number;
  kind: NoticeKind;
  text: string;
  /** Shown in small print so a user can quote it in a support request. */
  correlationId?: string;
}

/** A minimal toast queue. Notices auto-dismiss unless they are errors. */
@Injectable({ providedIn: 'root' })
export class NotificationsService {
  private nextId = 1;
  private readonly items = signal<Notice[]>([]);
  readonly notices = this.items.asReadonly();

  success(text: string): void {
    this.push({ kind: 'success', text });
  }

  info(text: string): void {
    this.push({ kind: 'info', text });
  }

  error(text: string, correlationId?: string): void {
    this.push({ kind: 'error', text, correlationId });
  }

  dismiss(id: number): void {
    this.items.update((current) => current.filter((notice) => notice.id !== id));
  }

  private push(notice: Omit<Notice, 'id'>): void {
    const id = this.nextId++;
    this.items.update((current) => [...current, { ...notice, id }]);
    if (notice.kind !== 'error') {
      setTimeout(() => this.dismiss(id), 4000);
    }
  }
}
