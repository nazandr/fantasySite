/* global bootstrap: false */
import '/assets/dist/js/bootstrap.bundle.min.js'
(function () {
  'use strict'

  document.querySelectorAll('[data-bs-toggle="popover"]')
    .forEach(function (popover) {
      new bootstrap.Popover(popover)
    })

    var popover = new bootstrap.Popover(document.querySelector('.popover-dismiss'), {
      trigger: 'focus'
    })
})()
