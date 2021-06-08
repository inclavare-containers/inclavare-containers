import { $, $$, Overlay } from './utils'

export default function() {

  function getTOCItem(dom) {
    return dom.parentElement.parentElement
  }

  if ($('.link.-current')) {
    let ele = getTOCItem($('.link.-current').parentElement)
    while (ele.classList.contains('item')) {
      ele.classList.add("-show")
      ele = getTOCItem(ele)
    }
  }

  if ($$('.arrow')) {
    $$('.arrow').forEach(arrow => {
      arrow.parentElement.addEventListener('click', function() {
        this.parentElement.classList.toggle('-show')
      })
    })
  }

  // TOC drawer
  if ($('#js-drawer-handle')) {
    const overlay = Overlay.create()

    $('#js-drawer-handle').addEventListener('click', function() {
      const show = () => {
        overlay.show()
        this.classList.add('-show')
        $('#js-drawer').classList.add('-show')
      }

      const hide = () => {
        $('#js-drawer').classList.remove('-show')
        this.classList.remove('-show')
        overlay.hide()
      }

      if (!overlay.isShow()) {
        show()
        overlay.addClickEvent(() => {
          hide()
        })
      } else {
        hide()
      }
    })
  }

  if ($('.ss-toc-list-card .icon')) {
    const iconDOM = $('.ss-toc-list-card .icon')
    const containerDOM = $('.ss-toc-list-card .ss-tooltip')

    // containerDOM.remove() // IE 11 not support this
    containerDOM.parentElement.removeChild(containerDOM)

    let showFlag = false
    let showJustNow = false

    function callback() {
      const rect = iconDOM.getBoundingClientRect()

      if (showFlag === false) {
        containerDOM.classList.add('-active')

        containerDOM.style.top = `${rect.top}px`
        containerDOM.style.left = `${rect.left + rect.width + 10}px`
        document.body.appendChild(containerDOM)

        showFlag = true
        showJustNow = true
      }
    }

    $('.ss-toc-list-card .icon').addEventListener('click', callback)

    // https://techstacker.com/posts/yz6e9Ksz6ARbNpQAZ/vanilla-javascript-how-to-detect-clicks-outside-of-an
    document.addEventListener('click', function(event) {
      if (showJustNow) {
        showJustNow = false
        return
      }

      if (showFlag && !event.target.closest(".ss-tooltip")) {
        document.body.removeChild(containerDOM)
        containerDOM.classList.remove('-active')

        showFlag = false
      }
    })

    // for DEBUG
    // callback()
  }
}