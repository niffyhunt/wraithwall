// Synthetic fixture — deterministic content for golden tests only.
const params = new URLSearchParams(window.location.search);

export function render(userInput) {
  document.getElementById("out").innerHTML = userInput; // fixture XSS sink
}

export function evaluate() {
  return eval(params.get("expr")); // fixture eval sink
}
