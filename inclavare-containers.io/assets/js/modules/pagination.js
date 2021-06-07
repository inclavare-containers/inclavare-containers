import { $$ } from './utils'

const MAX_AD_LINKS = 2
// a magic number
const DOT = -98

export function createPagination(hrefFn) {
  const wrapHrefFn = (number) => {
    return number === DOT ? '' : hrefFn(number)
  }

  const paginationDOM = $$('.ss-pagination')[0]
  const dataset = paginationDOM.dataset

  const total = parseInt(dataset.total)
  const current = parseInt(dataset.current)

  const paginations = []

  let left = Math.max(1, current - MAX_AD_LINKS)
  let right = Math.min(total, current + MAX_AD_LINKS)

  if (right - left !== MAX_AD_LINKS * 2) {
    let l = MAX_AD_LINKS * 2 - (right - current)
    let r = MAX_AD_LINKS * 2 - (current - left)

    left = Math.max(1, current - l)
    right = Math.min(total, current + r)
  }

  for (let page = left; page <= right; page++) {
    paginations.push(page)
  }

  const first = paginations[0]
  const last = paginations[paginations.length - 1]

  if (first > 2) {
    paginations.unshift(DOT)
  }
  if (first > 1) {
    paginations.unshift(1)
  }

  if (last < total - 1) {
    paginations.push(DOT)
  }
  if (last < total) {
    paginations.push(total)
  }

  paginationDOM.innerHTML = `
  <ul class="list">
    ${paginations.map(number => {
      const href = wrapHrefFn(number) === "" ? "" : ` href="${wrapHrefFn(number)}"`
      return `<a${href}>
        <li class="item ${number === current ? '-active' : ''}">
          ${number === DOT ? '...' : number}
        </li>
      </a>`
    }).join('')}
  </ul>
  `
}


export default function() {
  if ($$('.ss-pagination').length === 0) {
    return
  }

  /**
   * example: 
   * '/tags/sofa/page/1/ -> '/tags/sofa'
   * */
  const pathArr = location.pathname.split('/').filter(str => str !== "")
  const pageIndex = pathArr.indexOf('page')
  const basePathArr = pathArr.slice(0, pageIndex === -1 ? undefined : pageIndex)

  const baseurl = basePathArr.join('/')

  const hrefFn = (number) => {
    return `/${baseurl}/page/${number}`
  }
  createPagination(hrefFn)
}