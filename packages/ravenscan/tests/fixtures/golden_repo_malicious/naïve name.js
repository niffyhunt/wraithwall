// Malicious-input fixture: raw ESC byte below must never reach a terminal.
// [31mfake-red</ESC>[0m  — comment marker form of the escape.
const payload = "<img src=x onerror=alert(1)>";
export function sink(input) {
  document.body.innerHTML = input;
  return eval(input); // hostile sink, fixture only
}
