export default {
  id: 'browser-add-ons',
  title: 'Browser add-ons',
  recommendedFor: ['hacked', 'sketchy', 'helping'],
  modules: ['browser_extension_audit', 'chrome_extensions', 'safari_extensions'],
  sources: ['guides/remediation/review_browser_extensions.md'],
  briefing: 'Browser extensions run code on the pages you visit. Many good ones, like ad blockers and password managers, need broad permissions to do their job, so a broad set of permissions is a prompt to look, not a verdict. What matters is whether the permissions fit what the extension is for, and whether you recognise and trust the publisher.',
  whatTheScanLooksFor: 'On a Mac, the checkup lists your extensions in Chrome, Firefox and Safari, flags names known to be harmful or adware, and points out ones asking for an unusually broad set of permissions.',
  questions: [
    {
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
