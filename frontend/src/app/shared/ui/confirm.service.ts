import { Injectable, signal } from '@angular/core';

export interface ConfirmRequest {
  title: string;
  message: string;
  confirmLabel?: string;
  /** Styles the confirm button as destructive and makes Cancel the default focus. */
  destructive?: boolean;
}

interface PendingConfirm extends ConfirmRequest {
  resolve: (confirmed: boolean) => void;
}

/**
 * Gates the actions that cannot be undone - deleting a user, rotating a secret,
 * signing every device out. Nothing here is a security control; the point is that
 * an irreversible action should take two decisions rather than one.
 */
@Injectable({ providedIn: 'root' })
export class ConfirmService {
  private readonly pending = signal<PendingConfirm | null>(null);
  readonly current = this.pending.asReadonly();

  ask(request: ConfirmRequest): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      this.pending.set({ ...request, resolve });
    });
  }

  answer(confirmed: boolean): void {
    const request = this.pending();
    this.pending.set(null);
    request?.resolve(confirmed);
  }
}
