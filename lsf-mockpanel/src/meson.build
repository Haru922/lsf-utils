lsf_mockpanel_dep = [
  lsf_dep,
  dependency('gtk+-3.0', version: '>= 3.22.20'),
  dependency('webkit2gtk-4.0', version: '>= 2.26.0')
]

lsf_mockpanel_sources = [
  'lsf-mockpanel.c'
]

lsf_mockpanel = executable(
  'lsf-mockpanel',
  lsf_mockpanel_sources,
  dependencies: lsf_mockpanel_dep,
  install: true
)
