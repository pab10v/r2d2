/**
 * Google Drive backup helper (end-to-end encrypted payload).
 *
 * Uses chrome.identity.getAuthToken to obtain an OAuth token.
 * Requires:
 * - manifest permissions: "identity"
 * - manifest host_permissions: "https://www.googleapis.com/*"
 *
 * Notes:
 * - This stores backups into the user's Drive `appDataFolder` (hidden app storage).
 * - Payload should already be encrypted (e.g. SecureVault.encryptExport()).
 */

(function initDriveSync(global) {
  const DRIVE_FILE_NAME = 'r2d2-vault-backup.json';
  const DRIVE_MIME = 'application/json';
  const DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive.appdata';

  async function getAuthToken(interactive) {
    return new Promise((resolve, reject) => {
      chrome.identity.getAuthToken(
        { interactive: Boolean(interactive), scopes: [DRIVE_SCOPE] },
        (token) => {
        if (chrome.runtime.lastError) {
          const msg = chrome.runtime.lastError.message || 'Unknown chrome.identity error';
          // Make common setup issues clearer for developers.
          const hint =
            msg.includes('OAuth2 not granted or revoked') ||
            msg.includes('OAuth2 request failed') ||
            msg.includes('Invalid client_id') ||
            msg.includes('The OAuth client was not found')
              ? ' (OAuth setup required in manifest: oauth2.client_id + drive scope)'
              : '';
          reject(new Error(`${msg}${hint}`));
          return;
        }
        if (!token) {
          reject(new Error('No auth token'));
          return;
        }
        resolve(token);
        }
      );
    });
  }

  async function removeCachedToken(token) {
    if (!token) return;
    return new Promise((resolve) => {
      chrome.identity.removeCachedAuthToken({ token }, () => resolve());
    });
  }

  async function driveFetch(token, url, init = {}) {
    const headers = new Headers(init.headers || {});
    headers.set('Authorization', `Bearer ${token}`);
    return fetch(url, { ...init, headers });
  }

  async function findExistingBackupFileId(token) {
    const latest = await getLatestBackupMetadata(token);
    return latest?.id || null;
  }

  async function getLatestBackupMetadata(token) {
    // Search appDataFolder for exact filename.
    const q = encodeURIComponent(`name='${DRIVE_FILE_NAME}' and trashed=false`);
    const url = `https://www.googleapis.com/drive/v3/files?spaces=appDataFolder&q=${q}&fields=files(id,name,modifiedTime)&orderBy=modifiedTime desc&pageSize=1`;
    const res = await driveFetch(token, url);
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Drive list failed (${res.status}): ${text || 'unknown error'}`);
    }
    const data = await res.json();
    return data?.files?.[0] || null;
  }

  async function uploadBackupJson(token, jsonObject) {
    const existingId = await findExistingBackupFileId(token);
    const metadata = {
      name: DRIVE_FILE_NAME,
      parents: ['appDataFolder'],
      mimeType: DRIVE_MIME
    };

    const boundary = 'r2d2_drive_boundary_' + Math.random().toString(16).slice(2);
    const delimiter = `--${boundary}`;
    const closeDelim = `--${boundary}--`;

    const body =
      `${delimiter}\r\n` +
      `Content-Type: application/json; charset=UTF-8\r\n\r\n` +
      `${JSON.stringify(metadata)}\r\n` +
      `${delimiter}\r\n` +
      `Content-Type: ${DRIVE_MIME}\r\n\r\n` +
      `${JSON.stringify(jsonObject)}\r\n` +
      `${closeDelim}\r\n`;

    const base = 'https://www.googleapis.com/upload/drive/v3/files';
    const url = existingId
      ? `${base}/${encodeURIComponent(existingId)}?uploadType=multipart`
      : `${base}?uploadType=multipart`;

    const method = existingId ? 'PATCH' : 'POST';
    const res = await driveFetch(token, url, {
      method,
      headers: {
        'Content-Type': `multipart/related; boundary=${boundary}`
      },
      body
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Drive upload failed (${res.status}): ${text || 'unknown error'}`);
    }
    return res.json();
  }

  async function downloadBackupJson(token) {
    const fileId = await findExistingBackupFileId(token);
    if (!fileId) return null;
    const url = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media`;
    const res = await driveFetch(token, url);
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`Drive download failed (${res.status}): ${text || 'unknown error'}`);
    }
    return res.json();
  }

  global.R2D2DriveSync = {
    getAuthToken,
    removeCachedToken,
    getLatestBackupMetadata,
    uploadBackupJson,
    downloadBackupJson
  };
})(typeof window !== 'undefined' ? window : self);

