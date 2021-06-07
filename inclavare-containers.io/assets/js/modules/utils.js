import get from 'lodash-es/get'
import { en, zh } from '../i18n'

/**
 * i18n
 */
export function i18n(path) {
  const lang = window.SITE_LANGUAGE
  const langJOSN = lang === "zh" ? zh : en

  return get(langJOSN, path, "")
}

/**
 * DOM Selector methods
 */

export const $ = document.querySelector.bind(document)

export const $$ = document.querySelectorAll.bind(document)

/**
 * Overlay
 */
export class Overlay {
  constructor() {
    const overlayDOM = document.createElement('div')
    overlayDOM.setAttribute('class', "js-overlay")

    document.body.appendChild(overlayDOM)
    this._overlayDOM = overlayDOM
    this._isShow = false
  }

  static create() {
    return new Overlay()
  }

  isShow() {
    return this._isShow
  }

  show() {
    this._overlayDOM.classList.add('-show')
    this._isShow = true
    // disable body's scroll
    document.body.classList.add('-noscroll')
  }

  hide() {
    this._overlayDOM.classList.remove('-show')
    this._isShow = false
    document.body.classList.remove('-noscroll')
  }

  addClickEvent(fn) {
    this._overlayDOM.addEventListener('click', fn, { once: true })
  }

  destroy() {
    document.body.classList.remove('-noscroll')
    this._overlayDOM.remove()
  }
}