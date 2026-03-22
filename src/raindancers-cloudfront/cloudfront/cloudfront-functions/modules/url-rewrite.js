function rewriteToIndex(event) {
  var uri = event.request.uri;
  if (!uri.match(/\.[a-zA-Z0-9]+$/)) {
    event.request.uri = uri.replace(/\/?$/, '/index.html');
  }
}
