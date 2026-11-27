import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { ConfirmComponent } from './shared/ui/confirm.component';
import { ToastsComponent } from './shared/ui/toasts.component';

/**
 * The root. Everything visible is routed; the only fixtures here are the two
 * overlays that any screen can raise.
 */
@Component({
  selector: 'app-root',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterOutlet, ToastsComponent, ConfirmComponent],
  template: `
    <router-outlet />
    <app-toasts />
    <app-confirm />
  `,
})
export class App {}
