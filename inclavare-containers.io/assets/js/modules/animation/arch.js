import SVG from 'svg.js'
import { $, $$ } from '../utils'
import { mountSVG } from './index.js'

import arch from '../../../svg/arch.svg'

import {
  INITstate,
  TLstate,
  TRstate,
  BLstate,
  BRstate,
  BGColor,
} from './archState'

function loadArchSVG() {
  const archSvgMap = {
    arch: {
      svg: arch,
    },
  }

  mountSVG("#js-arch-animation", archSvgMap)
}

function eachDir(fn) {
  fn('TL')
  fn('TR')
  fn('BR')
  fn('BL')
}

function archAnimation() {
  SVG.select('#arch svg').first().size(600, 440)

  const animateConfig = {
    duration: 300,
  }

  const groupMap = {
    TR: SVG.select('#arch #tr').first(),
    TL: SVG.select('#arch #tl').first(),
    BL: SVG.select('#arch #bl').first(),
    BR: SVG.select('#arch #br').first(),
  }

  const cirMap = {
    TR: SVG.select('#arch #cir-tr').first(),
    TL: SVG.select('#arch #cir-tl').first(),
    BL: SVG.select('#arch #cir-bl').first(),
    BR: SVG.select('#arch #cir-br').first(),
  }

  const iconMap = {
    TR: SVG.select('#arch #icon-micro').first(),
    TL: SVG.select('#arch #icon-servi').first(),
    BL: SVG.select('#arch #icon-immut').first(),
    BR: SVG.select('#arch #icon-decla').first(),
  }
  const textMap = {
    TR: SVG.select('#arch #text-micro'),
    TL: SVG.select('#arch #text-servi tspan'),
    BL: SVG.select('#arch #text-immut tspan'),
    BR: SVG.select('#arch #text-decla'),
  }
  const textBGMap = {
    TR: SVG.select('#arch #text-bg-tr').first(),
    TL: SVG.select('#arch #text-bg-tl').first(),
    BL: SVG.select('#arch #text-bg-bl').first(),
    BR: SVG.select('#arch #text-bg-br').first(),
  }

  const lineBorder = SVG.select('#arch #border-line').first()
  const lineBG = SVG.select('#arch #main-bg').first()
  const lineCross1 = SVG.select('#arch #cross-line-1').first()
  const lineCross2 = SVG.select('#arch #cross-line-2').first()

  const shadow = SVG.select('#arch #cir-shadow').first()
  const textCloud = SVG.select('#arch #text-cloud').first()

  let dir_last = 'INIT'

  const STATE_MAP = {
    INIT: INITstate,
    TL: TLstate,
    TR: TRstate,
    BL: BLstate,
    BR: BRstate,
  }

  function _setState(dir) {
    if (dir_last === dir) {
      return
    }

    const STATE = STATE_MAP[dir]

    eachDir(d => {
      const s = STATE[d].circle

      if (d === dir) {
        cirMap[d]
          .style({
            filter: "url(#dropshadow)",
          })
      } else {
        cirMap[d]
        .style({
          filter: "none",
        })
      }

      cirMap[d]
        .animate(animateConfig)
        .attr({
          cx: s.pos[0],
          cy: s.pos[1],
          r: s.r,
        })
        .style({
          fill: s.fill,
        })
    })

    eachDir(d => {
      const s = STATE[d].icon

      if (d === dir) {
        iconMap[d]
          .center(s.pos[0], s.pos[1])
          .attr({
            fill: s.fill,
            opacity: 0,
          })
          .animate({
            delay: animateConfig.duration,
            duration: 200,
          })
          .attr({
            opacity: 1
          })
      }

      iconMap[d]
        .center(s.pos[0], s.pos[1])
        .animate(animateConfig)
        .attr({
          fill: s.fill,
        })
    })

    eachDir(d => {
      const s = STATE[d].text

      const text = textMap[d]
      const textBG = textBGMap[d]
      const padding = 16

      let dmoveArr = [0, 0]
      if (s.dmove) {
        if (dir_last === d) {
          dmoveArr = [-s.dmove[0], -s.dmove[1]]
        } else if (dir === d) {
          dmoveArr = s.dmove
        }
      }

      if (s.hasBG) {
        const bbox = text.bbox();
        textBG.attr({
          x: bbox.x - padding * 2,
          y: bbox.y - padding,
          width: bbox.width + padding * 4,
          height: bbox.height + padding * 2,
          fill: '#fff',
          opacity: 0,
        });

        textBG
          .animate({
            duration: 5
          })
          .dmove(...dmoveArr)
          .animate({
            duration: animateConfig.duration
          })
          .attr({
            fill: BGColor,
            opacity: 1,
          });

      } else {

        textBG.attr({
          x: 0,
          y: 0,
          width: 0,
          height: 0,
          opacity: 0,
        });
      }

      text
        .animate({
          duration: 5
        })
        .dmove(...dmoveArr)
        .attr({
          fill: s.fill
        })
    })

    const points = new SVG.PointArray([
      STATE['TR'].circle.pos,
      STATE['TL'].circle.pos,
      STATE['BL'].circle.pos,
      STATE['BR'].circle.pos,
      STATE['TR'].circle.pos,
    ]).toString()

    lineBorder
      .animate(animateConfig)
      .attr({
        points,
      })
    lineBG
      .animate(animateConfig)
      .attr({
        points,
      })
    lineCross1
      .animate(animateConfig)
      .attr({
        x1: STATE['TL'].circle.pos[0],
        y1: STATE['TL'].circle.pos[1],
        x2: STATE['BR'].circle.pos[0],
        y2: STATE['BR'].circle.pos[1],
      })
    lineCross2
      .animate(animateConfig)
      .attr({
        x1: STATE['TR'].circle.pos[0],
        y1: STATE['TR'].circle.pos[1],
        x2: STATE['BL'].circle.pos[0],
        y2: STATE['BL'].circle.pos[1],
      })

    if (dir[1] === 'L') {
      shadow
        .animate(animateConfig)
        .move(0)
    } else {
      shadow
        .animate(animateConfig)
        .move(90)
    }

    let moveX = dir[1] === 'R' ? -440 : 100
    let moveY = dir[0] === 'T' ? 30 : -60
    if (dir === 'INIT') {
      moveX = 0
      moveY = 0
    }

    textCloud
      .animate(animateConfig)
      .move(moveX, moveY)
      .opacity(dir === 'INIT' ? 1 : 0.6)

    dir_last = dir
  }

  function setDescription(dir) {
    $$(`#js-arch .row`).forEach(it => {
      it.classList.remove('-selected');
    })
    $(`#js-arch .${dir}`).classList.add('-selected')
  }

  let isAnimate = false
  let nextDir = 'NONE'

  const setState = (dir) => {
    nextDir = dir
    if (isAnimate === false) {
      _setState(nextDir)
      isAnimate = true

      setTimeout(() => {
        isAnimate = false
        _setState(nextDir)
      }, 500)
    }
  }

  $$(`#js-arch .row`).forEach(it => {
    function getDir(dom) {
      return Array.from(dom.classList).filter(n => n === n.toUpperCase())[0]
    }

    // click
    // it.addEventListener('click', function() {
    //   const dir = getDir(this)
    //   setState(dir)
    //   setDescription(dir)
    // })

    // hover
    it.addEventListener('mouseenter', function() {
      const dir = getDir(this)
      setState(dir)
      setDescription(dir, true)
    })
    it.addEventListener('mouseleave', function() {
      const dir = getDir(this)
      setState(dir)
      setDescription(dir)
    })
  })

  Object.keys(cirMap).forEach(dir => {
    groupMap[dir].on('mouseenter', () => {
      setState(dir)
      setDescription(dir)
    })
  })

  textCloud.on('mouseenter', () => {
    setState('INIT')
    setDescription('INIT')
  })

  // setState('BR')
}

export {
  loadArchSVG,
  archAnimation,
}