import toker, { Auth } from '../src';

describe('es-toker package', () => {
  it('exports single instance of Auth class', () => {
    expect(toker instanceof Auth).toBe(true);
    expect(new Auth()).toEqual(toker);
  });
});
