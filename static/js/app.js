// Tiny password-strength hint on the register page (purely cosmetic; the server enforces the real rules).
(function () {
  var pw = document.getElementById("password");
  var out = document.getElementById("strength");
  if (!pw || !out) return;
  pw.addEventListener("input", function () {
    var v = pw.value, score = 0;
    if (v.length >= 10) score++;
    if (v.length >= 14) score++;
    if (/[A-Z]/.test(v) && /[a-z]/.test(v)) score++;
    if (/\d/.test(v)) score++;
    if (/[^A-Za-z0-9]/.test(v)) score++;
    out.textContent = v ? ["Very weak", "Weak", "Fair", "Good", "Strong", "Excellent"][score] : "";
  });
})();
