(function () {
  var input = document.querySelector("[data-file-search]");
  if (!input) {
    return;
  }

  var status = document.querySelector("[data-file-search-status]");
  var empty = document.querySelector("[data-file-search-empty]");

  function normalize(value) {
    return (value || "").toLowerCase().trim();
  }

  function filterFiles() {
    var query = normalize(input.value);
    var items = Array.prototype.slice.call(document.querySelectorAll(".file-item"));
    var visible = 0;

    items.forEach(function (item) {
      var name = normalize(item.getAttribute("data-file-name") || item.textContent);
      var show = query === "" || name.indexOf(query) !== -1;
      item.hidden = !show;

      if (show) {
        visible += 1;
      }
    });

    if (status) {
      if (query === "") {
        status.textContent = items.length + " fichier(s)";
      } else {
        status.textContent = visible + " / " + items.length + " fichier(s)";
      }
    }

    if (empty) {
      empty.hidden = visible > 0;
    }
  }

  input.addEventListener("input", filterFiles);
  filterFiles();
})();
