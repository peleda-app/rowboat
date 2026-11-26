import starlight from '@astrojs/starlight'
import mermaid from 'astro-mermaid'
import { defineConfig } from 'astro/config'
import starlightLinksValidator from 'starlight-links-validator'
import starlightSidebarTopics from 'starlight-sidebar-topics'

const repoUrl = 'https://github.com/peleda-app/rowboat'

const group = (label: string, directory: string, collapsed = false) => ({
  label,
  collapsed,
  items: [{ autogenerate: { directory } }],
})

export default defineConfig({
  site: 'https://peleda-app.github.io',
  base: '/rowboat',
  trailingSlash: 'always',
  outDir: './dist',
  integrations: [
    mermaid({
      theme: 'base',
      autoTheme: false,
      enableLog: false,
      mermaidConfig: {
        fontFamily: '"Geist Variable", ui-sans-serif, system-ui, sans-serif',
        flowchart: { curve: 'basis', padding: 14, nodeSpacing: 36, rankSpacing: 52 },
        themeVariables: {
          darkMode: true,
          fontSize: '14px',
          background: '#0b0b0c',
          mainBkg: '#18181b',
          primaryColor: '#18181b',
          primaryTextColor: '#ededef',
          primaryBorderColor: '#3a3a40',
          nodeBorder: '#3a3a40',
          secondaryColor: '#111113',
          tertiaryColor: '#0e0e10',
          textColor: '#b4b4bb',
          lineColor: '#5fb3a1',
          clusterBkg: '#0e0e10',
          clusterBorder: '#2a2a2e',
          titleColor: '#9a9aa2',
          edgeLabelBackground: '#0b0b0c',
          actorBkg: '#18181b',
          actorBorder: '#3a3a40',
          actorTextColor: '#ededef',
          actorLineColor: '#2a2a2e',
          signalColor: '#5fb3a1',
          signalTextColor: '#b4b4bb',
          noteBkgColor: '#111113',
          noteBorderColor: '#2a2a2e',
          noteTextColor: '#b4b4bb',
          dropShadow: 'none',
        },
      },
    }),
    starlight({
      title: 'Skein',
      description:
        'Skein connects to mail, calendar and contacts providers, turns every change into an append-only journal with the original bytes of every object, and carries out write commands placed next to that journal.',
      favicon: '/favicon.svg',
      logo: { src: './src/assets/skein.svg' },
      social: [{ icon: 'github', label: 'GitHub', href: repoUrl }],
      editLink: { baseUrl: `${repoUrl}/edit/main/skein/apps/docs/` },
      customCss: ['@fontsource-variable/geist', '@fontsource-variable/geist-mono', './src/styles/theme.css'],
      expressiveCode: {
        themes: ['github-dark-default', 'github-light-default'],
        styleOverrides: {
          borderRadius: '0.6rem',
          codeFontFamily: '"Geist Mono Variable", ui-monospace, monospace',
          codeFontSize: '0.8125rem',
          uiFontFamily: '"Geist Variable", ui-sans-serif, system-ui, sans-serif',
          frames: { shadowColor: 'transparent' },
        },
      },
      plugins: [
        starlightLinksValidator({ errorOnLocalLinks: true }),
        starlightSidebarTopics([
          {
            id: 'start',
            label: 'Getting started',
            link: '/start/',
            icon: 'rocket',
            items: [{ autogenerate: { directory: 'start' } }],
          },
          {
            id: 'concepts',
            label: 'Concepts',
            link: '/concepts/',
            icon: 'open-book',
            items: [{ autogenerate: { directory: 'concepts' } }],
          },
          {
            id: 'providers',
            label: 'Providers',
            link: '/providers/',
            icon: 'email',
            items: [
              'providers',
              group('Mail', 'providers/mail'),
              group('Calendars and contacts', 'providers/pim'),
              group('Sending', 'providers/send'),
              group('Authorization', 'providers/auth'),
              'providers/scheduling',
            ],
          },
          {
            id: 'operate',
            label: 'Deploy and store',
            link: '/deploy/',
            icon: 'laptop',
            items: ['deploy', group('Deployment', 'deploy/run'), group('Storage', 'deploy/storage')],
          },
          {
            id: 'consumers',
            label: 'Consumers',
            link: '/consumers/',
            icon: 'list-format',
            items: [{ autogenerate: { directory: 'consumers' } }],
          },
          {
            id: 'extending',
            label: 'Extending',
            link: '/extending/',
            icon: 'puzzle',
            items: [{ autogenerate: { directory: 'extending' } }],
          },
        ]),
      ],
    }),
  ],
})
