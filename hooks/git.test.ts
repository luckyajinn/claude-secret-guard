import { expect, test } from 'claude-code/testing'

import { addedByFile, binaryPaths, parseGitOps, splitCommand, splitNull, unwide } from './git'
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
  // A `cd` is followed, and the folder it left is looked at too (the `cd` may have been in a subshell).
  expect(parseGitOps('cd sub && git commit -m x').map(o => o.dir)).toEqual(['sub', undefined])
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

// ---------------------------------------------------------------------------
// Ways of writing git that used to hide it

test('a line continuation, a shell keyword and an escaped command word do not hide git', () => {
  expect(parseGitOps('git \\\n  commit -m x').map(o => o.kind)).toEqual(['commit'])
  expect(parseGitOps('git `\n  commit -m x').map(o => o.kind)).toEqual(['commit'])
  expect(parseGitOps('g\\it comm\\it -m x').map(o => o.kind)).toEqual(['commit'])
  expect(parseGitOps('g`it add .').map(o => o.kind)).toEqual(['add'])
  expect(parseGitOps('if true; then git commit -a -m x; fi').map(o => o.kind)).toEqual(['commit'])
  expect(parseGitOps('{ git add .; }').map(o => o.kind)).toEqual(['add'])
  expect(parseGitOps('! git commit -m x').map(o => o.kind)).toEqual(['commit'])
  expect(parseGitOps('C:\\Git\\cmd\\git.exe commit -m x').map(o => o.kind)).toEqual(['commit'])
})

test('a shell run with -c, eval and a prefix command are read inside', () => {
  expect(parseGitOps('bash -c "git commit -am wip"').map(o => [o.kind, o.isCommitAll])).toEqual([['commit', true]])
  expect(parseGitOps("sh -lc 'git add -A'").map(o => o.kind)).toEqual(['add'])
  expect(parseGitOps('powershell -Command "git add ."').map(o => o.kind)).toEqual(['add'])
  expect(parseGitOps('cmd /c git commit -m x').map(o => o.kind)).toEqual(['commit'])
  expect(parseGitOps('eval "git commit -a -m x"').map(o => o.kind)).toEqual(['commit'])
  expect(parseGitOps('sudo -u me git commit -m x').map(o => o.kind)).toEqual(['commit'])
  expect(parseGitOps('env -i GIT_AUTHOR_NAME=x git add .').map(o => o.kind)).toEqual(['add'])
  // A shell that runs something else is not git.
  expect(parseGitOps('bash -c "ls -la"')).toEqual([])
  expect(parseGitOps('bash script.sh')).toEqual([])
})

test('a command that is a variable is read the widest way', () => {
  expect(parseGitOps('$G commit -m x').map(o => [o.kind, o.isCommitAll])).toEqual([['commit', true]])
  expect(parseGitOps('$G add f.txt').map(o => [o.kind, o.isEverything])).toEqual([['add', true]])
  expect(parseGitOps('$G status')).toEqual([])
})

test('cd is followed, and --git-dir, --work-tree and GIT_DIR point somewhere else', () => {
  expect(parseGitOps('cd app && git add .').map(o => o.dir)).toEqual(['app', undefined])
  expect(parseGitOps('cd /srv/app && git commit -m x').map(o => o.dir)).toEqual(['/srv/app', undefined])
  expect(parseGitOps('cd a && cd b && git add .').map(o => o.dir)).toEqual(['a/b', undefined])
  expect(parseGitOps('Set-Location web; git add .').map(o => o.dir)).toEqual(['web', undefined])
  // A target the shell has to expand cannot be followed.
  expect(parseGitOps('cd ~/x && git add .').map(o => o.dir)).toEqual([undefined])
  expect(parseGitOps('git --git-dir=/r/.git add .').map(o => o.dir)).toEqual(['/r'])
  expect(parseGitOps('git --work-tree=/w --git-dir=/r/.git commit -m x').map(o => o.dir)).toEqual(['/w'])
  expect(parseGitOps('GIT_DIR=/r/.git git add .').map(o => o.dir)).toEqual(['/r'])
})

test('abbreviated long options are read as git reads them', () => {
  expect(op('git add --upd').isTrackedOnly).toBe(true)
  expect(op('git add --dry-r').isSkipped).toBe(true)
  expect(op('git commit --inter -m x').isCommitAll).toBe(true)
  expect(op('git commit --pathspec-from-file=list.txt').isCommitAll).toBe(true)
  expect(op('git commit --all -m x').isCommitAll).toBe(true)
})

test('binaryPaths lists the files a diff calls binary, and not a deleted one', () => {
  const diff = [
    'Binary files a/x.txt and b/x.txt differ',
    'Binary files /dev/null and b/new dir/y.txt differ',
    'Binary files a/z and /dev/null differ',
  ].join('\n')

  expect(binaryPaths(diff)).toEqual(['x.txt', 'new dir/y.txt'])
})

test('unwide reads UTF-16 text that arrives with a NUL after every letter, and leaves a real binary alone', () => {
  const wide = `${'password = x'.split('').join('\0')}\0`

  expect(unwide(wide)).toBe('password = x')
  expect(unwide('plain')).toBe('plain')
  expect(unwide('ab\0cdefghijklmnop')).toBeUndefined()
})
