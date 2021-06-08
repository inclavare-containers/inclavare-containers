import { $, Overlay } from './utils'

export default function() {
  if (!$('#mobile-menu-icon')) {
    return
  }

  $('#mobile-menu-icon').addEventListener('click', function() {
    const overlay = Overlay.create()
    overlay.show()
    $('#mobile-menu').classList.add("-active")
    overlay.addClickEvent(() => {
      $('#mobile-menu').classList.remove("-active")
      overlay.hide()
    })
  })
}