// inserts a word break opportunity after each underscore
// in order to improve the style of long cipher suite names
function set_breakpoints() {
  var arr = document.getElementsByClassName("long-string");
  for (var i = 0; i < arr.length; i++) {
    arr[i].innerHTML = arr[i].innerHTML.replace(/_/g, "_<wbr/>");
  }
}

// execute when page is loaded
window.onload = set_breakpoints();
