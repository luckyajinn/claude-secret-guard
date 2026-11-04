import { expect, test } from 'claude-code/testing'

import { addedByFile, parseGitOps, splitCommand, splitNull } from './git'
import type { GitOp } from './git'

// The first git command a line holds (the test says what it expects of it).
const op = (command: string, index = 0): GitOp => {
  const found = parseGitOps(command)[index]

  if (found === undefined) {
    throw new Error(`no git add or commit in: ${command}`)
  }

  return found
}

test('splitCommand splits on shell operators and takes the quotes off', () => {
  expect(splitCommand('git add . && git commit -m "a message; with && inside"')).toEqual([
    ['git', 'add', '.'],
    ['git', 'commit', '-m', 'a message; with && inside'],
  ])
  expect(splitCommand("echo 'one two' | grep two\nls -la")).toEqual([['echo', 'one two'], ['grep', 'two'], ['ls', '-la']])
  expect(splitCommand('echo $(git add .)')).toEqual([['echo', '$'], ['git', 'add', '.']])
})

test('splitCommand keeps Windows path backslashes', () => {
  expect(splitCommand('git add C:\\Users\\me\\a.txt "C:\\My Files\\b.txt"')).toEqual([
    ['git', 'add', 'C:\\Users\\me\\a.txt', 'C:\\My Files\\b.txt'],
  ])
})

test('parseGitOps finds add and commit, in order', () => {
  const ops = parseGitOps('git add -A && git commit -m "x" && git push')

  expect(ops.map(op => op.kind)).toEqual(['add', 'commit'])
  expect(ops[0]?.isEverything).toBe(true)
  expect(ops[1]?.isCommitAll).toBe(false)
})

test('parseGitOps reads the paths of git add', () => {
  expect(op('git add src/a.ts "my file.ts" .').paths).toEqual(['src/a.ts', 'my file.ts', '.'])
  expect(op('git add -- -odd-name').paths).toEqual(['-odd-name'])
  expect(op('FOO=1 git add src/a.ts').paths).toEqual(['src/a.ts'])
  expect(op('sudo git.exe add a.txt').paths).toEqual(['a.txt'])
})

test('parseGitOps reads the flags of git add', () => {
  expect(op('git add -u').isTrackedOnly).toBe(true)
  expect(op('git add --update src').isTrackedOnly).toBe(true)
  expect(op('git add -f .env').isForce).toBe(true)
  expect(op('git add -Af')).toMatchObject({ isEverything: true, isForce: true })
  expect(op('git add -A src')).toMatchObject({ isEverything: false, paths: ['src'] })
  expect(op('git add --pathspec-from-file=list.txt').isEverything).toBe(true)
})

test('parseGitOps skips what stages nothing', () => {
  expect(op('git add --dry-run .').isSkipped).toBe(true)
  expect(op('git add -n .').isSkipped).toBe(true)
  expect(op('git add -p').isSkipped).toBe(true)
  expect(op('git commit --dry-run').isSkipped).toBe(true)
})

test('parseGitOps reads the flags of git commit', () => {
  expect(op('git commit -am "msg"').isCommitAll).toBe(true)
  expect(op('git commit -a -m msg').isCommitAll).toBe(true)
  expect(op('git commit --all -m msg').isCommitAll).toBe(true)
  expect(op('git commit -m msg').isCommitAll).toBe(false)
  expect(op('git commit -mmsg -a').isCommitAll).toBe(true)
  expect(op('git commit -m "use -a to commit all"').isCommitAll).toBe(false)
  expect(op('git commit -F notes.txt src/a.ts').paths).toEqual(['src/a.ts'])
  expect(op('git commit -m msg -- src/a.ts').paths).toEqual(['src/a.ts'])
  expect(op('git commit --amend --no-edit').paths).toEqual([])
})

test('parseGitOps reads git -C and ignores other global options', () => {
  expect(op('git -C sub commit -m x').dir).toBe('sub')
  expect(op('git -C /abs/repo add .').dir).toBe('/abs/repo')
  expect(op('git -C a -C b add .').dir).toBe('a/b')
  expect(op('git -c user.name=x --no-pager commit -m y').kind).toBe('commit')
  expect(op('git -c user.name=x --no-pager commit -m y').dir).toBeUndefined()
  expect(op('git --git-dir=.git add .').kind).toBe('add')
})

test('parseGitOps does not mistake text for a command', () => {
  expect(parseGitOps('git commit -m "git add . && git commit"').map(op => op.kind)).toEqual(['commit'])
  expect(parseGitOps('echo "git add ."')).toEqual([])
  expect(parseGitOps('git status && git log')).toEqual([])
  expect(parseGitOps('grep -r "git commit" docs')).toEqual([])
  expect(op('cd sub && git commit -m x').dir).toBeUndefined()
  expect(parseGitOps('')).toEqual([])
})

// ---------------------------------------------------------------------------
// Diffs

const DIFF = [
  'diff --git a/src/app.ts b/src/app.ts',
  'index 1111111..2222222 100644',
  '--- a/src/app.ts',
  '+++ b/src/app.ts',
  '@@ -10,0 +11,2 @@ function main() {',
  '+const a = 1',
  '+const b = 2',
  '@@ -40 +42 @@',
  '-old line',
  '+new line',
  'diff --git a/README.md b/README.md',
  '--- a/README.md',
  '+++ b/README.md',
  '@@ -1,2 +1,3 @@',
  ' kept',
  '-gone',
  '+++ looks like a header but is content',
  '+tail',
  '\\ No newline at end of file',
  'diff --git a/gone.txt b/gone.txt',
  'deleted file mode 100644',
  '--- a/gone.txt',
  '+++ /dev/null',
  '@@ -1 +0,0 @@',
  '-bye',
].join('\n')

test('addedByFile returns each file\u2019s added lines with their real line numbers', () => {
  const files = addedByFile(DIFF)

  expect(files.map(f => f.file)).toEqual(['src/app.ts', 'README.md'])
  expect(files[0]?.lines).toEqual([11, 12, 42])
  expect(files[0]?.text).toBe('const a = 1\nconst b = 2\nnew line')
  expect(files[1]?.lines).toEqual([2, 3])
  expect(files[1]?.text).toBe('++ looks like a header but is content\ntail')
})

test('addedByFile treats a content line that looks like a file header as content', () => {
  const readme = addedByFile(DIFF)[1]

  expect((readme?.text ?? '').split('\n')[0]).toBe('++ looks like a header but is content')
})

test('addedByFile copes with an empty diff, a deletion only and a binary file', () => {
  expect(addedByFile('')).toEqual([])
  expect(addedByFile(['--- a/x', '+++ /dev/null', '@@ -1,2 +0,0 @@', '-a', '-b'].join('\n'))).toEqual([])
  expect(addedByFile(['diff --git a/i.png b/i.png', 'Binary files a/i.png and b/i.png differ'].join('\n'))).toEqual([])
})

test('splitNull splits git -z output', () => {
  expect(splitNull('a.txt\0dir/b c.txt\0')).toEqual(['a.txt', 'dir/b c.txt'])
  expect(splitNull('')).toEqual([])
})
