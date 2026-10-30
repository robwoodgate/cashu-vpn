// esbuild inlines .svg imports as data URIs (--loader:.svg=dataurl).
declare module '*.svg' {
  const url: string;
  export default url;
}
