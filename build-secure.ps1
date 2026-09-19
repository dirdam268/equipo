param(
  [Parameter(Mandatory=$true)][string]$Password,
  [string]$Src = "index-src.html",
  [string]$Out = "index.html"
)
$ErrorActionPreference = 'Stop'
$dir = $PSScriptRoot
$srcPath = Join-Path $dir $Src

# 1) Leer la app en claro y anteponer un sello para verificar el descifrado
$plainBytes = [System.IO.File]::ReadAllBytes($srcPath)
$sentinel = [System.Text.Encoding]::UTF8.GetBytes("EQP_OK|")
$data = New-Object byte[] ($sentinel.Length + $plainBytes.Length)
[Array]::Copy($sentinel, 0, $data, 0, $sentinel.Length)
[Array]::Copy($plainBytes, 0, $data, $sentinel.Length, $plainBytes.Length)

# 2) Derivar clave (PBKDF2-SHA256) y cifrar (AES-256-CBC)
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$salt = New-Object byte[] 16; $rng.GetBytes($salt)
$iv   = New-Object byte[] 16; $rng.GetBytes($iv)
$iter = 100000
$kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, $iter, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
$key = $kdf.GetBytes(32)
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $key; $aes.IV = $iv
$encryptor = $aes.CreateEncryptor()
$ct = $encryptor.TransformFinalBlock($data, 0, $data.Length)

$payload = @{
  v = 1; iter = $iter
  salt = [Convert]::ToBase64String($salt)
  iv   = [Convert]::ToBase64String($iv)
  ct   = [Convert]::ToBase64String($ct)
} | ConvertTo-Json -Compress

# 3) Pantalla de acceso (descifra en el navegador con Web Crypto)
$gate = @'
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Equipo</title>
<meta name="theme-color" content="#ffffff">
<meta name="robots" content="noindex, nofollow">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="Equipo">
<style>
  *{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
  :root{
    --bg:#ffffff; --card:#ffffff; --card2:#f3f6f9; --line:#e0e6ec;
    --txt:#16202b; --dim:#68757f; --acc:#0e8a4f;
  }
  body{
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
    background:var(--bg); color:var(--txt);
    min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px;
  }
  .gate{
    background:var(--card); border:1px solid var(--line); border-radius:14px;
    padding:32px 26px; width:100%; max-width:360px; border-top:3px solid var(--acc);
    box-shadow:0 2px 10px rgba(22,32,43,.06);
  }
  .eyebrow{
    font-size:10.5px; text-transform:uppercase; letter-spacing:.14em;
    color:var(--dim); margin-bottom:10px;
  }
  h1{font-size:24px; font-weight:700; letter-spacing:-.02em; margin-bottom:8px}
  .sub{font-size:13.5px; color:var(--dim); margin-bottom:24px; line-height:1.5}
  label{
    display:block; font-size:10.5px; text-transform:uppercase;
    letter-spacing:.1em; color:var(--dim); margin-bottom:7px;
  }
  input{
    width:100%; border:1px solid var(--line); border-radius:8px; background:var(--card2);
    color:var(--txt); padding:12px 14px; font-family:inherit; font-size:16px;
    outline:none; margin-bottom:14px;
  }
  input:focus{border-color:var(--acc)}
  button{
    width:100%; background:var(--acc); border:0; color:#fff; border-radius:8px;
    padding:13px; font-family:inherit; font-weight:700; font-size:12.5px;
    text-transform:uppercase; letter-spacing:.12em; cursor:pointer;
  }
  button:disabled{opacity:.55; cursor:default}
  .err{color:#cf2f2f; font-size:13px; font-weight:500; margin-top:14px; min-height:18px}
  .foot{
    margin-top:22px; padding-top:16px; border-top:1px solid var(--line);
    font-size:11.5px; color:var(--dim); line-height:1.6;
  }
</style>
</head>
<body>
<div class="gate">
  <div class="eyebrow">Acceso restringido</div>
  <h1>Estadísticas del equipo</h1>
  <div class="sub">Introduce la contraseña para continuar.</div>
  <label for="pw">Contraseña</label>
  <input id="pw" type="password" autocomplete="current-password" autofocus>
  <button id="go">Entrar</button>
  <div class="err" id="err"></div>
  <div class="foot">Solo se pide la primera vez en cada dispositivo.</div>
</div>
<script>
const PAYLOAD = __PAYLOAD__;
const CLAVE_MEM = 'eq_pw';
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function decryptApp(password) {
  const salt = b64(PAYLOAD.salt), iv = b64(PAYLOAD.iv), ct = b64(PAYLOAD.ct);
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PAYLOAD.iter, hash: 'SHA-256' },
    km, { name: 'AES-CBC', length: 256 }, false, ['decrypt']
  );
  const buf = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ct);
  const text = new TextDecoder().decode(buf);
  if (!text.startsWith('EQP_OK|')) throw new Error('sello');
  return text.slice(7);
}

async function enter() {
  const btn = document.getElementById('go');
  const err = document.getElementById('err');
  const pw = document.getElementById('pw').value;
  if (!pw) { err.textContent = 'Introduce la contraseña.'; return; }
  btn.disabled = true; err.textContent = 'Descifrando…';
  try {
    const html = await decryptApp(pw);
    // Recordar en este dispositivo: solo se pide la primera vez
    try { localStorage.setItem(CLAVE_MEM, pw); } catch(_) {}
    document.open(); document.write(html); document.close();
  } catch (e) {
    try { localStorage.removeItem(CLAVE_MEM); } catch(_) {}
    err.textContent = 'Contraseña incorrecta.';
    btn.disabled = false;
  }
}

document.getElementById('go').addEventListener('click', enter);
document.getElementById('pw').addEventListener('keydown', e => { if (e.key === 'Enter') enter(); });

// Si ya se validó antes en este dispositivo, entrar directo sin preguntar
const saved = (() => { try { return localStorage.getItem(CLAVE_MEM); } catch(_) { return null; } })();
if (saved) {
  document.getElementById('pw').value = saved;
  enter();
}
</script>
</body>
</html>
'@

$gate = $gate.Replace('__PAYLOAD__', $payload)
$outPath = Join-Path $dir $Out
[System.IO.File]::WriteAllText($outPath, $gate, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("OK -> {0} generado. Datos cifrados: {1} KB" -f $Out, [math]::Round($ct.Length/1024))
