// SAFE: a UMD-wrapped BROWSER widget. The module.exports block exists only for
// bundlers; the code manipulates the DOM and has no server capability.
(function (root, factory) {
  if (typeof module === "object" && module.exports) { module.exports = factory(); }
  else { root.MyWidget = factory(); }
})(typeof self !== "undefined" ? self : this, function () {
  function Widget(el) { this.el = document.querySelector(el); }
  Widget.prototype.render = function (html) { this.el.innerHTML = html; };
  return Widget;
});
