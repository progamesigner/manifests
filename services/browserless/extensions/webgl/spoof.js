(() => {
  const VENDOR = 'Google Inc. (Intel)';
  const RENDERER = 'ANGLE (Intel, Mesa Intel(R) UHD Graphics 630 (CFL GT2), OpenGL 4.6)';
  for (const proto of [WebGLRenderingContext.prototype, WebGL2RenderingContext.prototype]) {
    const original = proto.getParameter;
    const patched = function getParameter(p) {
      if (p === 37445) return VENDOR;
      if (p === 37446) return RENDERER;
      return original.call(this, p);
    };
    Object.defineProperty(patched, 'toString', { value: () => 'function getParameter() { [native code] }' });
    proto.getParameter = patched;
  }
})();
