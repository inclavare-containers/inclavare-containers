import SVG from 'svg.js'
import { mountSVG } from './index.js'

import box from '../../../svg/box.svg'
import debris1 from '../../../svg/float/debris-1.svg'
import debris2 from '../../../svg/float/debris-2.svg'
import debris3 from '../../../svg/float/debris-3.svg'

function loadBoxSVG() {
  /*const boxSvgMap = {
    // a: {
    //   svg: a,
    //   // transform: 'tranlateX(45)'
    // },
    debris1: {
      svg: debris1,
    },
    debris2: {
      svg: debris2,
    },
    debris3: {
      svg: debris3,
    },
    box: {
      svg: box,
    },
  }

  mountSVG("#js-home-animation", boxSvgMap)
*/}



function interpolate(x) {
  return x
}

function boxAnimation() {
  /*if (window.innerWidth <= 568) {
    SVG.select('#box svg').first().size(400, 400)
  } else {
    SVG.select('#box svg').first().size(600, 600)
  }

  SVG.select('#debris1 svg').first().size(200, 200)
  SVG.select('#debris2 svg').first().size(200, 200)
  SVG.select('#debris3 svg').first().size(200, 200)

  // 上下
  const a = SVG.select('#box #a')
  const h = SVG.select('#box #h')

  // 前后
  const b = SVG.select('#box #b')
  const d = SVG.select('#box #d')

  // 左
  const c = SVG.select('#box #c')
  const e = SVG.select('#box #e')

  // 右
  const f = SVG.select('#box #f')
  const g = SVG.select('#box #g')

  function animate(fraction, animateConfig) {
    const len = interpolate(fraction) * 700

    const config = {
      ease: '<>',
      duration: 1,
      // delay: 0,
      ...animateConfig,
    }

    // 上下
    a.animate(config).move(-len * 0.2, -len * 0.7)
    h.animate(config).move(len * 0.2, len * 0.8)

    // 前后
    b.animate(config).move(len * 0.5, -len * 0.3)
    d.animate(config).move(-len * 0.5, len * 0.3)

    // 左
    c.animate(config).move(-len, -len * 0.8)
    e.animate(config).move(-len * 0.5, 0)

    // 右
    f.animate(config).move(len * 0.7, len * 0.3)
    g.animate(config).move(len * 0.7, -len * 0.5)
  }

  ;
  (function debrisFloatAnimate() {
    SVG.select('#debris1 svg g').animate({
      duration: 5000,
    }).move(-Math.random() * 200, Math.random() * 70)

    SVG.select('#debris2 svg g').animate({
      duration: 5000,
    }).move(Math.random() * 140, Math.random() * 100)

    SVG.select('#debris3 svg g').animate({
      duration: 5000,
    }).move(Math.random() * 100, Math.random() * 100)

    setTimeout(debrisFloatAnimate, 8000)
  })()


  function calcDuration(percent) {
    return percent * 5000
  }

  // init state
  animate(0.3)

  ;
  (function boxAnimate() {
    animate(0.7, {
      duration: calcDuration(0.4),
    })

    animate(0.3, {
      duration: calcDuration(0.4),
    })

    animate(0.8, {
      duration: calcDuration(0.5),
    })

    animate(0.4, {
      duration: calcDuration(0.4),
    })

    animate(1, {
      duration: calcDuration(0.6),
    })

    animate(0, {
      ease: '-',
      duration: 400,
      delay: 100,
    })

    // total = 2.3 * 5 + 0.4

    setTimeout(boxAnimate, 1000 * 16)
  })()
*/}

export {
  loadBoxSVG,
  boxAnimation,
}
