import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { RolesApi } from '../../../core/api/roles.api';
import { AuthService } from '../../../core/auth/auth.service';
import { PermissionResponse, ROLE_NAME_PATTERN, RoleResponse } from '../../../core/models/role';
import { NotificationsService } from '../../../core/notifications.service';
import { ConfirmService } from '../../../shared/ui/confirm.service';

/**
 * Roles and the permissions they carry.
 *
 * Editing a role changes what every account holding it can do, which is why the
 * permission list is spelled out rather than summarised - the blast radius of a
 * checkbox here is every user with that role.
 */
@Component({
  selector: 'app-role-list',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ReactiveFormsModule],
  template: `
    <div class="page-header">
      <div>
        <h1>Roles</h1>
        <p class="page-header__subtitle">
          A role is a named set of permissions. Roles scope either to the whole platform
          or to a single client application.
        </p>
      </div>
      @if (canManage()) {
        <button type="button" class="btn btn--primary" (click)="creating.set(!creating())">
          {{ creating() ? 'Cancel' : 'New role' }}
        </button>
      }
    </div>

    @if (creating()) {
      <section class="card" style="margin-bottom: 1.25rem">
        <h2>Create a role</h2>
        <form [formGroup]="form" (ngSubmit)="create()" novalidate>
          <div class="create-grid">
            <label class="field">
              <span class="field__label">Name</span>
              <input type="text" formControlName="name" placeholder="ORDER_MANAGER" />
              @if (form.controls.name.touched && form.controls.name.invalid) {
                <p class="field__error">Upper snake case, starting with a letter.</p>
              }
            </label>
            <label class="field">
              <span class="field__label">Client id (optional)</span>
              <input type="text" formControlName="clientId" placeholder="Leave blank for platform-wide" />
            </label>
          </div>
          <label class="field">
            <span class="field__label">Description</span>
            <input type="text" formControlName="description" />
          </label>

          <fieldset class="perms">
            <legend class="field__label">Permissions</legend>
            @for (permission of permissions(); track permission.id) {
              <label class="checkbox" [title]="permission.description ?? ''">
                <input
                  type="checkbox"
                  [checked]="draft().has(permission.name)"
                  (change)="toggle(permission.name)"
                />
                <span class="mono">{{ permission.name }}</span>
              </label>
            }
          </fieldset>

          <button type="submit" class="btn btn--primary mt-2" [disabled]="busy() || form.invalid">
            {{ busy() ? 'Creating…' : 'Create role' }}
          </button>
        </form>
      </section>
    }

    @if (loading()) {
      <p class="muted">Loading…</p>
    } @else {
      <div class="roles">
        @for (role of roles(); track role.id) {
          <section class="card">
            <div class="role__head">
              <div>
                <h2 class="role__name mono">{{ role.name }}</h2>
                <p class="role__meta">
                  {{ role.description || 'No description' }}
                  @if (role.clientId) {
                    · scoped to <span class="mono">{{ role.clientId }}</span>
                  } @else {
                    · platform-wide
                  }
                  @if (role.systemRole) {
                    <span class="chip">system</span>
                  }
                </p>
              </div>
              @if (canManage()) {
                <div class="row-actions">
                  @if (editing() === role.id) {
                    <button type="button" class="btn btn--sm" (click)="cancelEdit()">Cancel</button>
                    <button type="button" class="btn btn--sm btn--primary" [disabled]="busy()" (click)="save(role)">
                      Save
                    </button>
                  } @else {
                    <button type="button" class="btn btn--sm" (click)="startEdit(role)">Edit</button>
                    @if (!role.systemRole) {
                      <button type="button" class="btn btn--sm btn--danger-quiet" (click)="remove(role)">Delete</button>
                    }
                  }
                </div>
              }
            </div>

            @if (editing() === role.id) {
              <fieldset class="perms mt-2">
                <legend class="field__label">Permissions</legend>
                @for (permission of permissions(); track permission.id) {
                  <label class="checkbox" [title]="permission.description ?? ''">
                    <input
                      type="checkbox"
                      [checked]="draft().has(permission.name)"
                      (change)="toggle(permission.name)"
                    />
                    <span class="mono">{{ permission.name }}</span>
                  </label>
                }
              </fieldset>
            } @else {
              <div class="mt-1">
                @for (permission of role.permissions; track permission) {
                  <span class="chip">{{ permission }}</span>
                } @empty {
                  <span class="muted" style="font-size: 0.82rem">No permissions</span>
                }
              </div>
            }
          </section>
        } @empty {
          <section class="card"><p class="empty">No roles defined.</p></section>
        }
      </div>
    }
  `,
  styles: `
    .roles { display: grid; gap: 1rem; }
    .role__head { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; flex-wrap: wrap; }
    .role__name { margin: 0; font-size: 0.95rem; }
    .role__meta { margin: 0.2rem 0 0; font-size: 0.8rem; color: var(--fg-muted); }
    .create-grid { display: grid; gap: 0 1rem; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); }
    .perms {
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem;
      margin: 0;
      display: grid;
      gap: 0.3rem;
      grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr));
    }
  `,
})
export class RoleListComponent {
  private readonly api = inject(RolesApi);
  private readonly fb = inject(FormBuilder);
  private readonly confirm = inject(ConfirmService);
  private readonly notifications = inject(NotificationsService);
  private readonly auth = inject(AuthService);

  protected readonly roles = signal<RoleResponse[]>([]);
  protected readonly permissions = signal<PermissionResponse[]>([]);
  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  protected readonly creating = signal(false);
  protected readonly editing = signal<string | null>(null);

  /** Permission names checked in whichever editor is open. */
  protected readonly draft = signal<ReadonlySet<string>>(new Set());

  protected readonly canManage = computed(() => this.auth.has('ROLE_MANAGE'));

  protected readonly form = this.fb.nonNullable.group({
    name: ['', [Validators.required, Validators.pattern(ROLE_NAME_PATTERN)]],
    description: [''],
    clientId: [''],
  });

  constructor() {
    this.load();
    this.api.permissions().subscribe((permissions) => this.permissions.set(permissions));
  }

  private load(): void {
    this.loading.set(true);
    this.api.list().subscribe({
      next: (roles) => {
        this.roles.set(roles);
        this.loading.set(false);
      },
      error: () => this.loading.set(false),
    });
  }

  protected toggle(name: string): void {
    this.draft.update((current) => {
      const next = new Set(current);
      if (!next.delete(name)) {
        next.add(name);
      }
      return next;
    });
  }

  protected startEdit(role: RoleResponse): void {
    this.creating.set(false);
    this.editing.set(role.id);
    this.draft.set(new Set(role.permissions));
  }

  protected cancelEdit(): void {
    this.editing.set(null);
    this.draft.set(new Set());
  }

  protected save(role: RoleResponse): void {
    this.busy.set(true);
    this.api
      .updatePermissions(role.id, {
        description: role.description ?? undefined,
        permissions: [...this.draft()],
      })
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.cancelEdit();
          this.notifications.success('Role updated.');
          this.load();
        },
        error: () => this.busy.set(false),
      });
  }

  protected create(): void {
    if (this.form.invalid || this.busy()) {
      this.form.markAllAsTouched();
      return;
    }
    this.busy.set(true);
    const { name, description, clientId } = this.form.getRawValue();

    this.api
      .create({
        name,
        description: description || undefined,
        clientId: clientId || undefined,
        permissions: [...this.draft()],
      })
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.creating.set(false);
          this.form.reset();
          this.draft.set(new Set());
          this.notifications.success('Role created.');
          this.load();
        },
        error: () => this.busy.set(false),
      });
  }

  protected async remove(role: RoleResponse): Promise<void> {
    const confirmed = await this.confirm.ask({
      title: 'Delete ' + role.name + '?',
      message:
        'Every account holding this role loses the permissions it grants, on their next token refresh.',
      confirmLabel: 'Delete role',
      destructive: true,
    });
    if (!confirmed) {
      return;
    }
    this.api.delete(role.id).subscribe(() => {
      this.notifications.success('Role deleted.');
      this.load();
    });
  }
}
