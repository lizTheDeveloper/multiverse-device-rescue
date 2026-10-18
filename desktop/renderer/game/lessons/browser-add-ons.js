export default {
  id: 'browser-add-ons',
  title: 'Browser add-ons',
  recommendedFor: ['hacked', 'sketchy', 'helping'],
  modules: ['browser_extension_audit', 'chrome_extensions', 'safari_extensions'],
  districts: ['gatehouse'],
  sources: ['guides/remediation/review_browser_extensions.md'],
  briefing: 'Browser extensions (also called add-ons) run code on the pages you visit.',
  whatTheScanLooksFor: 'On a Mac, the checkup lists your extensions in Chrome, Firefox and Safari, flags names known to be harmful or adware, and points out ones asking for an unusually broad set of permissions.',
  questions: [
    {
      teach: 'Many good extensions, like ad blockers and password managers, need broad permissions to do their job. So a broad set of permissions is a prompt to look, not a verdict. What matters is whether the permissions fit what the extension is for.',
      prompt: 'Which extension’s permissions would you question?',
      options: [
        { text: 'A screenshot tool that wants to read your cookies and block web requests', correct: true,
          feedback: 'Right. A screenshot tool has no reason to need those.' },
        { text: 'A password manager that wants to work on every site', correct: false,
          feedback: 'That one’s expected. The guide names password managers as needing this kind of access.' },
        { text: 'An ad blocker that sees every page', correct: false,
          feedback: 'Also expected. The guide names ad blockers as needing this kind of access.' },
      ],
    },
    {
      teach: 'It also matters who publishes an extension: a company or developer you recognise and trust. An extension you don’t remember installing may have come bundled with other software. Look it up by name in the browser’s extension store before deciding whether to keep it.',
      prompt: 'You find an extension you don’t remember installing. What’s a good first step?',
      options: [
        { text: 'Look it up in the extension store and check who publishes it', correct: true,
          feedback: 'Right. If it doesn’t check out, remove it. If it does, no action is needed.' },
        { text: 'Leave it. If it’s in the browser, it must be fine.', correct: false,
          feedback: 'Not always. It may have come bundled with other software. Check who publishes it first.' },
      ],
    },
    {
      teach: 'Each browser has a page that lists its extensions. In Chrome it’s `chrome://extensions/`. In Firefox it’s `about:addons`. In Safari, go to Safari > Settings > Extensions.',
      prompt: 'Where do you see your extensions in Chrome?',
      options: [
        { text: '`chrome://extensions/`', correct: true,
          feedback: 'Right. Firefox uses `about:addons`. For Safari, it’s this: Safari > Settings > Extensions.' },
        { text: '`about:addons`', correct: false,
          feedback: 'That’s Firefox’s page. Chrome’s is `chrome://extensions/`.' },
        { text: 'Safari > Settings > Extensions', correct: false,
          feedback: 'That’s Safari. Chrome’s is `chrome://extensions/`.' },
      ],
    },
    {
      teach: 'Every extension is more code running on every page you visit, even a harmless one. A simple test for each: have I used this in the last month?',
      prompt: 'You haven’t used an extension in the last month. What’s a good move?',
      options: [
        { text: 'Remove it. You can always reinstall it later.', correct: true,
          feedback: 'Right. Fewer extensions means less code running on every page you visit.' },
        { text: 'Keep every extension, just in case', correct: false,
          feedback: 'Each one is more code running on every page you visit. If you don’t use it, it can go.' },
      ],
    },
  ],
};
