export default {
  id: 'locked-door',
  title: 'Updates and the locked door',
  recommendedFor: ['identity', 'helping', 'unsure'],
  modules: ['automatic_updates', 'update_checker', 'encryption_check', 'filevault_recovery', 'win_bitlocker_check', 'lock_screen_check', 'screen_lock_check'],
  sources: [
    'guides/remediation/enable_automatic_updates.md',
    'guides/remediation/enable_disk_encryption.md',
    'guides/remediation/enforce_lock_screen.md',
    'guides/remediation/enable_bitlocker.md',
  ],
  briefing: 'Three settings do a lot of quiet work. Automatic updates install security fixes. On a Mac, “Install Security Responses and system files” is the most important one, because it covers rapid-response security patches. FileVault, on a Mac, encrypts the whole startup disk, so its contents can’t be read without the password or recovery key, even if the disk is taken out. And a lock screen that asks for your password straight away gives someone less chance to use the computer while you step away.',
  whatTheScanLooksFor: 'On a Mac, the checkup looks at your update settings, whether FileVault is on, and how soon the screen asks for a password. On Windows, it checks whether BitLocker is encrypting your drives.',
  questions: [
    {
      prompt: 'On a Mac, where do you turn on automatic updates?',
      options: [
        { text: 'System Settings > General > Software Update', correct: true,
          feedback: 'Right. Click the “i” next to “Automatic updates” to see each switch.' },
        { text: 'System Settings > Privacy & Security > FileVault', correct: false,
          feedback: 'That’s disk encryption. Updates are under General.' },
        { text: 'System Settings > Lock Screen', correct: false,
          feedback: 'That’s where the lock screen settings live. Updates are under General.' },
      ],
    },
    {
      prompt: 'You turn on FileVault and it shows you a recovery key. Where should it go?',
      options: [
        { text: 'Paste it into Device Rescue so it’s kept safe', correct: false,
          feedback: 'Don’t paste it into this tool or into a chat. Anyone who has it can unlock the whole disk.' },
        { text: 'Write it down, or save it in a password manager', correct: true,
          feedback: 'Right. Treat it like a master password.' },
        { text: 'In a note that syncs to an account someone else can get into', correct: false,
          feedback: 'Keep it where nobody else can read it. Anyone who has it can unlock the whole disk.' },
      ],
    },
    {
      prompt: 'How soon after the screen locks should your Mac ask for the password?',
      options: [
        { text: 'Immediately', correct: true,
          feedback: 'Right. A long delay gives someone a chance to use it while you’re away.' },
        { text: 'Only after a restart', correct: false,
          feedback: 'That leaves it open whenever you step away. Choose “Immediately” in the Lock Screen settings.' },
      ],
    },
  ],
};
