// SAFE: browser/client-side script. exec() here is RegExp.exec, not a shell.
// "SELECT" is a CSS query, paths are URL fragments. No server, DB, or FS.
(function () {
  var rx = /(\w+)=(\w+)/;
  function parseQuery() {
    var hash = window.location.hash;
    var m = rx.exec(hash);                 // RegExp.exec -- NOT command exec
    if (m) document.getElementById("out").textContent = m[2];
  }
  jQuery(document).on("click", ".SELECT", function () {
    var path = "/users/" + jQuery(this).data("id");  // a URL path, not a filesystem path
    window.history.pushState({}, "", path);
  });
  window.addEventListener("hashchange", parseQuery);
})();
