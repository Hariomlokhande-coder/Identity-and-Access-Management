import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ClientsApi } from '../../../core/api/clients.api';
import { AuthService } from '../../../core/auth/auth.service';
import { ClientResponse, ClientType } from '../../../core/models/client';
import { NotificationsService } from '../../../core/notifications.service';
import { InstantPipe, clientStatusTone } from '../../../shared/format';
import { BadgeComponent } from '../../../shared/ui/badge.component';
import { ConfirmService } from '../../../shared/ui/confirm.service';

/**
 * Registered OAuth2 client applications.
 *
 * The client secret is the one thing here that exists in plaintext exactly once,
 * in the response to creating or rotating it - the server keeps only a hash. It is
 * shown in a panel that has to be dismissed deliberately, because navigating away
 * from it loses the secret for good.
 */
@Component({
  selector: 'app-client-list',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule, BadgeComponent, InstantPipe],
  template: `
    <div class="page-header">
      <div>
        <h1>Applications</h1>
        <p class="page-header__subtitle">
          Clients allowed to start an authorization flow against this platform.
        </p>
      </div>
      @if (canManage()) {
        <button type="button" class="btn btn--primary" (click)="creating.set(!creating())">
          {{ creating() ? 'Cancel' : 'Register application' }}
        </button>
      }
    </div>

    @if (secret(); as issued) {
      <section class="card secret">
        <h2>Store this secret now</h2>
        <p class="secret__notice">{{ issued.notice }}</p>
        @if (issued.secret) {
          <div class="secret__value">
            <code>{{ issued.secret }}</code>
            <button type="button" class="btn btn--sm" (click)="copy(issued.secret)">Copy</button>
          </div>
        }
        <button type="button" class="btn mt-2" (click)="secret.set(null)">I have saved it</button>
      </section>
    }

    @if (creating()) {
      <section class="card" style="margin-bottom: 1.25rem">
        <h2>Register an application</h2>
        <form [formGroup]="form" (ngSubmit)="create()" novalidate>
          <div class="grid">
            <label class="field">
              <span class="field__label">Name</span>
              <input type="text" formControlName="name" />
            </label>
            <label class="field">
              <span class="field__label">Type</span>
              <select formControlName="clientType">
                <option value="CONFIDENTIAL">Confidential (has a secret)</option>
                <option value="PUBLIC">Public (browser or mobile, PKCE only)</option>
              </select>
            </label>
          </div>

          <label class="field">
            <span class="field__label">Redirect URIs</span>
            <textarea rows="3" formControlName="redirectUris" placeholder="One per line"></textarea>
            <p class="field__hint">
              Matched exactly at authorize time. A URI that is not listed here is refused.
            </p>
          </label>

          <label class="field">
            <span class="field__label">Scopes</span>
            <input type="text" formControlName="scopes" placeholder="openid profile email" />
            <p class="field__hint">Space separated.</p>
          </label>

          <div class="grid">
            <label class="checkbox"><input type="checkbox" formControlName="requireConsent" /> Ask the user for consent</label>
            <label class="checkbox"><input type="checkbox" formControlName="requirePkce" /> Require PKCE</label>
          </div>

          <button type="submit" class="btn btn--primary mt-2" [disabled]="busy() || form.invalid">
            {{ busy() ? 'Registering…' : 'Register' }}
          </button>
        </form>
      </section>
    }

    @if (loading()) {
      <p class="muted">Loading…</p>
    } @else {
      <div class="clients">
        @for (client of clients(); track client.id) {
          <section class="card">
            <div class="client__head">
              <div>
                <h2 class="client__name">{{ client.name }}</h2>
                <p class="client__id mono">{{ client.clientId }}</p>
              </div>
              <div class="row-actions">
                <app-badge [label]="client.status" [tone]="statusTone(client.status)" />
                <app-badge [label]="client.clientType" />
                @if (canManage()) {
                  @if (client.clientType === 'CONFIDENTIAL') {
                    <button type="button" class="btn btn--sm" (click)="rotate(client)">Rotate secret</button>
                  }
                  <button type="button" class="btn btn--sm btn--danger-quiet" (click)="remove(client)">Delete</button>
                }
              </div>
            </div>

            <dl class="facts">
              <div>
                <dt>Redirect URIs</dt>
                <dd>
                  @for (uri of client.redirectUris; track uri) {
                    <div class="mono">{{ uri }}</div>
                  } @empty {
                    <span class="muted">None</span>
                  }
                </dd>
              </div>
              <div>
                <dt>Scopes</dt>
                <dd>
                  @for (scope of client.scopes; track scope) {
                    <span class="chip">{{ scope }}</span>
                  } @empty {
                    <span class="muted">None</span>
                  }
                </dd>
              </div>
              <div>
                <dt>Requires</dt>
                <dd>
                  {{ client.requireConsent ? 'Consent' : 'No consent' }} ·
                  {{ client.requirePkce ? 'PKCE' : 'PKCE optional' }}
                </dd>
              </div>
              <div>
                <dt>Registered</dt>
                <dd>{{ client.createdAt | instant }}</dd>
              </div>
            </dl>
          </section>
        } @empty {
          <section class="card"><p class="empty">No applications registered.</p></section>
        }
      </div>
    }
  `,
  styles: `
    .clients { display: grid; gap: 1rem; }
    .client__head { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; flex-wrap: wrap; }
    .client__name { margin: 0; font-size: 1rem; }
    .client__id { margin: 0.15rem 0 0; font-size: 0.75rem; color: var(--fg-muted); overflow-wrap: anywhere; }
    .facts { margin: 1rem 0 0; display: grid; gap: 0.6rem; }
    .facts > div { display: grid; grid-template-columns: 150px 1fr; gap: 1rem; align-items: baseline; }
    dt { color: var(--fg-muted); font-size: 0.78rem; }
    dd { margin: 0; font-size: 0.85rem; overflow-wrap: anywhere; }
    .grid { display: grid; gap: 0 1rem; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); }

    .secret {
      border-color: var(--warn-border);
      background: var(--warn-bg);
      color: var(--warn-fg);
      margin-bottom: 1.25rem;
    }
    .secret__notice { margin: 0 0 0.75rem; font-size: 0.85rem; }
    .secret__value { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
    .secret__value code {
      flex: 1 1 20rem;
      padding: 0.5rem 0.65rem;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 7px;
      overflow-wrap: anywhere;
      color: var(--fg);
    }
    @media (max-width: 560px) {
      .facts > div { grid-template-columns: 1fr; gap: 0.15rem; }
    }
  `,
})
export class ClientListComponent {
  private readonly api = inject(ClientsApi);
  private readonly fb = inject(FormBuilder);
  private readonly confirm = inject(ConfirmService);
  private readonly notifications = inject(NotificationsService);
  private readonly auth = inject(AuthService);

  protected readonly clients = signal<ClientResponse[]>([]);
  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  protected readonly creating = signal(false);
  protected readonly secret = signal<{ secret?: string; notice: string } | null>(null);

  protected readonly statusTone = clientStatusTone;
  protected readonly canManage = computed(() => this.auth.has('CLIENT_MANAGE'));

  protected readonly form = this.fb.nonNullable.group({
    name: ['', [Validators.required]],
    clientType: ['CONFIDENTIAL' as ClientType, [Validators.required]],
    redirectUris: ['', [Validators.required]],
    scopes: ['openid profile email'],
    requireConsent: [true],
    requirePkce: [true],
  });

  constructor() {
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.api.list().subscribe({
      next: (clients) => {
        this.clients.set(clients);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected create(): void {
    if (this.form.invalid || this.busy()) {
      this.form.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    const raw = this.form.getRawValue();

    this.api
      .create({
        name: raw.name,
        clientType: raw.clientType,
        redirectUris: splitLines(raw.redirectUris),
        scopes: splitSpaces(raw.scopes),
        requireConsent: raw.requireConsent,
        requirePkce: raw.requirePkce,
      })
      .subscribe({
        next: (response) => {
          this.busy.set(false);
          this.creating.set(false);
          this.form.reset({
            clientType: 'CONFIDENTIAL',
            scopes: 'openid profile email',
            requireConsent: true,
            requirePkce: true,
          });
          this.secret.set({ secret: response.clientSecret, notice: response.notice });
          this.load();
        },
        error: () => this.busy.set(false),
      });
  }

  protected async rotate(client: ClientResponse): Promise<void> {
    const confirmed = await this.confirm.ask({
      title: 'Rotate the secret for ' + client.name + '?',
      message:
        'The current secret stops working immediately. The application cannot authenticate again until it is updated with the new one.',
      confirmLabel: 'Rotate secret',
      destructive: true,
    });
    if (!confirmed) {
      return;
    }
    this.api.rotateSecret(client.id).subscribe((response) => {
      this.secret.set({ secret: response.clientSecret, notice: response.notice });
    });
  }

  protected async remove(client: ClientResponse): Promise<void> {
    const confirmed = await this.confirm.ask({
      title: 'Delete ' + client.name + '?',
      message: 'Every authorization flow and token belonging to this application stops working.',
      confirmLabel: 'Delete application',
      destructive: true,
    });
    if (!confirmed) {
      return;
    }
    this.api.delete(client.id).subscribe(() => {
      this.notifications.success('Application deleted.');
      this.load();
    });
  }

  protected copy(value: string): void {
    navigator.clipboard?.writeText(value).then(
      () => this.notifications.success('Secret copied to the clipboard.'),
      () => this.notifications.error('Could not copy. Select the text and copy it manually.'),
    );
  }
}

function splitLines(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function splitSpaces(value: string): string[] {
  return value.split(/\s+/).filter(Boolean);
}
