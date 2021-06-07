import menuFunc from './modules/menu'
import tocFunc from './modules/toc'
import asideFunc from './modules/aside'
import searchFunc from './modules/search'
import paginationFunc from './modules/pagination'
import animationFunc from './modules/animation'

import zoom from 'zoom-image'
import 'zoom-image/css/zoom-image.css'

import { $$ } from './modules/utils'

const main = () => {

  // Animition
  animationFunc()

  // Menu
  menuFunc()

  // TOC
  tocFunc()

  // aside get_code
  asideFunc()

  // search page
  searchFunc()

  // pagination page
  paginationFunc()

  // image zoom
  $$('.typo img').forEach(imgElem => {
    zoom(imgElem)
  })
}

document.addEventListener('DOMContentLoaded', main)