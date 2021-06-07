import { $, $$, i18n } from './utils'
import { createPagination } from './pagination'

import qs from 'query-string'
import algoliasearch from 'algoliasearch'

export default function searchFunc() {

  // menu search input
  if ($("#js-menu-search")) {

    function jump2Search(id) {
      const query = $(`#${id} .input`).value
      window.location.href = `/search/?${qs.stringify({query})}`
    }

    const bindListener = (id) => {
      $(`#${id} .input`).addEventListener('keydown', function(event) {
        if (event.key === 'Enter') {
          jump2Search(id)
        }
      })
  
      $(`#${id} .icon`).addEventListener('click', function() {
        jump2Search(id)
      })
    }

    bindListener('js-menu-search')
    bindListener('js-menu-search-mobile')
  }

  if (!$(".ss-search")) {
    return
  }

  const input = $('#js-search-input')
  const button = $('#js-search-button')
  const typeRadio = $$('#js-result-type input')
  const list = $('#js-result-container')

  const client = algoliasearch('G2HVBB5ERN', '4b161290c268b4eeb154171c562aa1e4')
  const index = client.initIndex('sofastack')
  // index.setSettings({
  //   hitsPerPage: 10
  // })

  let searchParam = {
    query: '',
    type: 'all',

    page: 1,
  }

  const setType = (type) => {
    if (!type) {
      return
    }

    if (searchParam.type !== type) {
      searchParam.page = 1
    }
    searchParam.type = type

    typeRadio.forEach(radio => {
      if (radio.value === type) {
        radio.parentNode.classList.add('-selected')
      } else {
        radio.parentNode.classList.remove('-selected')
      }
    })

    searchFunc(input.value)
  }

  typeRadio.forEach(radio => {
    radio.addEventListener('click', function() {
      setType(this.value)
    })
  })

  const searchFunc = () => {
    const { query, type } = searchParam
    if (query === '') {
      return
    }

    // update URL but no need to refresh
    history.pushState(null, `${query} · Inclavare`, `/search/?${qs.stringify(searchParam)}`)

    index.search({ 
      query,
      facets:"type",
      facetFilters: type === 'all' ? undefined : `type:${type}`,
      page: searchParam.page - 1,
    }, (err, res) => {
      if (err) {
        // console.log(err)
        // console.log(err.debugData)
        return
      }
      
      const { hits } = res

      if (hits.length === 0) {
        list.innerHTML = `
          <div class="not-found">${i18n('noSearchResults')}</div>
        `
        return
      }

      list.innerHTML = hits.map((hit) => `
				<div class="ss-summary">
					<div class="title">
						<a href=${hit.permalink}>${hit.title}</a>
					</div>
					<div class="summary">
						${hit._highlightResult.summary.value}...
					</div>
					<div class="meta">
						${i18n('from')} · ${i18n(hit.type)}
					</div>
				</div>
      `).join('') + `
        <nav class="ss-pagination" 
          data-total="${res.nbPages}" 
          data-current="${res.page + 1}"
        ></nav>
      `

      createPagination((number) => {
        const param = { ...searchParam, page: number }
        return `/search/?${qs.stringify(param)}`
      })
    })
  }

  const urlQueryParam = qs.parseUrl(location.href).query
  if (urlQueryParam) {
    searchParam = {
      ...searchParam,
      ...urlQueryParam,
    }

    if (urlQueryParam.page) {
      searchParam.page = parseInt(urlQueryParam.page)
    }

    input.value = searchParam.query
    setType(searchParam.type)
  }

  input.addEventListener('input', function() {
    searchParam.query = this.value
  })

  input.addEventListener('keydown', function(event) {
    if (event.key === 'Enter') {
      searchFunc()
    }
  })

  button.addEventListener('click', () => {
    searchFunc()
  })
}
