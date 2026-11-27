import { HttpParams } from '@angular/common/http';
import { environment } from '../../../environments/environment';
import { PageQuery } from '../models/common';

/** Joins a backend path onto the configured API origin. */
export function apiUrl(path: string): string {
  return `${environment.apiBase}${path}`;
}

/**
 * Builds query parameters, dropping anything undefined, null or blank so that an
 * untouched filter never reaches the server as an empty string.
 */
export function toParams(source: Record<string, unknown>): HttpParams {
  let params = new HttpParams();
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined || value === null || value === '') {
      continue;
    }
    params = params.set(key, String(value));
  }
  return params;
}

export function pageParams(page: PageQuery, extra: Record<string, unknown> = {}): HttpParams {
  return toParams({ page: page.page, size: page.size, sort: page.sort, ...extra });
}
