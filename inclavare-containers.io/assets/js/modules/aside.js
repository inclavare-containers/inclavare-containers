import { $, $$, i18n } from './utils'

function tags() {
  if (!$(".ss-aside-tags")) {
    return
  }

  const button = $(".ss-aside-tags .card-extra")
  button.innerHTML = i18n('expand')

  let show = false

  button.addEventListener('click', function() {
    show = !show
    this.innerHTML = i18n(!show ? 'collapse' : 'expand')

    const tags = [].slice.call($$('.ss-aside-tags .tag'), 10)

    if (show) {
      tags.forEach(tag => {
        tag.style.display = 'none'
      })
    } else {
      tags.forEach(tag => {
        tag.style.display = 'inline-block'
      })
    }
  })

  button.click()
}

function getCode() {
  if (!$("#js-code")) {
    return
  }

  const _buttons = $$("#js-code .button")

  const httpBtn = _buttons[0]
  const sshBtn = _buttons[1]
  const input = $("#js-code .input")
  const copyBtn = $("#js-code .addon")

  const github = input.value.trim()

  httpBtn.addEventListener('click', () => {
    httpBtn.classList.add('-selected')
    sshBtn.classList.remove('-selected')
    input.value = `${github}.git`
  })

  sshBtn.addEventListener('click', () => {
    httpBtn.classList.remove('-selected')
    sshBtn.classList.add('-selected')
    input.value = `${github.replace('https:', 'git@github.com:')}.git`
  })

  let timer = null

  copyBtn.addEventListener('click', () => {
    if (timer) {
      window.clearTimeout(timer)
    }

    input.focus()
    input.select()
    try {
      document.execCommand('copy');
    } catch (err) {}
    input.blur()

    copyBtn.classList.add('-copyed')
    timer = window.setTimeout(() => {
      copyBtn.classList.remove('-copyed')
    }, 3000)
  })

  httpBtn.click()
}

export default function() {
  tags()
  getCode()
}