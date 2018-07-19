import toker, { ESToker } from '../src';

describe('es-toker package', () => {
  it('exports single instance of Auth class', () => {
    expect(toker instanceof ESToker).toBe(true);
    expect(new ESToker()).toEqual(toker);
  });
});
