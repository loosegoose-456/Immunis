import { registerHooks } from 'node:module';
// Node 24 strips TypeScript; resolve the repo's extensionless TS imports for tests only.
registerHooks({ resolve(specifier, context, next) {
  if (specifier.startsWith('.') && !/\.[a-z]+$/i.test(specifier)) {
    try { return next(specifier + '.ts', context); } catch (error) {
      if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error;
    }
  }
  return next(specifier, context);
}});
