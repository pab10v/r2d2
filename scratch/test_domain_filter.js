// Quick regression checks for domain matching rules in background.js.
// Run: node scratch/test_domain_filter.js

function normalizeHostLikeValue(value) {
  if (!value || typeof value !== 'string') return '';

  let normalized = value.trim().toLowerCase();
  if (!normalized) return '';

  const atIndex = normalized.lastIndexOf('@');
  if (atIndex > 0) {
    normalized = normalized.slice(atIndex + 1);
  }

  normalized = normalized.replace(/^[a-z]+:\/\//, '');
  normalized = normalized.split('/')[0].split(':')[0];
  normalized = normalized.replace(/^www\./, '');
  normalized = normalized.replace(/\.+$/g, '');
  normalized = normalized.replace(/[^a-z0-9.-]/g, '');
  return normalized;
}

function getRegistrableDomain(host) {
  const parts = host.split('.').filter(Boolean);
  if (parts.length <= 2) return host;

  const last = parts[parts.length - 1];
  const secondLast = parts[parts.length - 2];
  if (last.length === 2 && secondLast.length <= 3 && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function accountMatchesDomain(account, domain) {
  const normalizedHost = normalizeHostLikeValue(domain);
  const hostLabels = normalizedHost.split('.').filter(Boolean);
  const registrable = getRegistrableDomain(normalizedHost);
  const candidates = [account.issuer, account.name]
    .map((value) => normalizeHostLikeValue(value))
    .filter(Boolean);

  return candidates.some((candidate) => {
    if (candidate.includes('.')) {
      return normalizedHost === candidate || normalizedHost.endsWith(`.${candidate}`);
    }
    return hostLabels.includes(candidate) || registrable.startsWith(`${candidate}.`);
  });
}

function assertCase(name, condition) {
  if (!condition) {
    throw new Error(`FAILED: ${name}`);
  }
  console.log(`OK: ${name}`);
}

const accountGoogle = { issuer: 'Google', name: 'thepartnersforlifeinsurance@gmail.com' };
const accountGithub = { issuer: 'github.com', name: 'work' };
const accountCloudflare = { issuer: 'dash.cloudflare.com', name: 'Cloudflare' };

assertCase(
  'label match on primary domain',
  accountMatchesDomain(accountGoogle, 'myaccount.google.com')
);

assertCase(
  'email host match',
  accountMatchesDomain(accountGoogle, 'gmail.com')
);

assertCase(
  'full domain candidate exact/suffix',
  accountMatchesDomain(accountGithub, 'github.com') &&
    accountMatchesDomain(accountGithub, 'docs.github.com')
);

assertCase(
  'subdomain candidate exact/suffix',
  accountMatchesDomain(accountCloudflare, 'dash.cloudflare.com') &&
    accountMatchesDomain(accountCloudflare, 'api.dash.cloudflare.com')
);

assertCase(
  'no false positive for substring-only host label',
  !accountMatchesDomain(accountGoogle, 'notgoogle.com')
);

assertCase(
  'no unrelated domain match',
  !accountMatchesDomain(accountGoogle, 'microsoft.com')
);

console.log('\nAll domain matching checks passed.');
