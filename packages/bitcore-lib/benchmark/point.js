'use strict';

const { createHash } = require('node:crypto');
const benchmark = require('./backends');

const hash = (label, index) => createHash('sha256').update(`${label}-${index}`).digest('hex');

function load() {
  return {
    btc: require('..'),
    cash: require('../../bitcore-lib-cash'),
    ltc: require('../../bitcore-lib-ltc'),
    doge: require('../../bitcore-lib-doge')
  };
}

benchmark(__filename, libraries => {
  const fixtures = Array.from({ length: 16 }, () => ({}));
  const operations = {};

  for (const [coin, { crypto: { Point, BN } }] of Object.entries(libraries)) {
    const g = Point.getG();
    for (const [index, row] of fixtures.entries()) {
      const scalar = new BN(hash('scalar', index), 16);
      const point = g.mul(scalar);
      const x = point.getX();
      const y = point.getY();
      row[coin] = { scalar, point, x, y, odd: y.isOdd(), other: g.mul(scalar.addn(1)) };
      if (coin === 'btc') {
        const large = label => new BN(Array.from({ length: 16 }, (_, part) => hash(label + part, index)).join(''), 16);
        row[coin].a = large('a');
        row[coin].b = large('b');
        row[coin].divisor = new BN(hash('divisor', index), 16);
        row[coin].base = x.toRed(BN.red('k256'));
      }
    }

    const add = (name, operation) => { operations[`${coin}.${name}`] = row => operation(row[coin]); };
    add('Point(x,y)', f => Point(f.x, f.y));
    add('validate', f => f.point.validate());
    add('fromX', f => Point.fromX(f.odd, f.x));
    add('mulG', f => g.mul(f.scalar));
    add('mul', f => f.point.mul(f.scalar));
    add('add', f => f.point.add(f.other));
    if (coin === 'btc') {
      add('liftX', f => f.point.liftX());
      add('BN.mul4096', f => f.a.mul(f.b));
      add('BN.div4096by256', f => f.a.div(f.divisor));
      add('BN.mod4096by256', f => f.a.mod(f.divisor));
      add('BN.redPow256', f => f.base.redPow(f.scalar));
    }
    if (coin === 'cash') add('hasSquare', f => f.point.hasSquare());
  }

  return { fixtures, operations };
}, { load, warmupMs: 100, sampleMs: 250 });
