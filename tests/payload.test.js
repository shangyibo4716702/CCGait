import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { relative, sep } from 'node:path'

import { collectPayloadSources } from '../src/win/build.js'
import { PROJECT_ROOT } from '../src/config.js'

/**
 * 载荷完整性：从源码跑得通、装完却坏掉，是这类打包 bug 的典型症状
 * （UI 的 index.html / styles.css 曾经漏打包，装完后打开界面直接 404）。
 * 这里直接对比「src/ 下真正存在的运行时文件」与「会被打进载荷的文件」。
 */

/** 运行时资源（不含 .cs：那是构建输入，编译进 exe）。 */
const RUNTIME_FILE = /\.(js|ps1|cjs|mjs|json|md|html|css|svg|ico)$/i

describe('installer payload', () => {
  it('ships every runtime file under src/', () => {
    const payload = new Set(
      collectPayloadSources(PROJECT_ROOT).map((absolute) =>
        relative(PROJECT_ROOT, absolute).split(sep).join('/'),
      ),
    )

    const missing = []
    const walk = async (dir) => {
      const { readdirSync } = await import('node:fs')
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.name.startsWith('.')) continue
        const full = `${dir}/${entry.name}`
        if (entry.isDirectory()) {
          await walk(full)
          continue
        }
        if (!RUNTIME_FILE.test(entry.name)) continue
        const key = relative(PROJECT_ROOT, full).split(sep).join('/')
        if (!payload.has(key)) missing.push(key)
      }
    }
    walk(`${PROJECT_ROOT}/src`)

    assert.deepEqual(missing, [], `以下运行时文件没有被打进安装包：\n  ${missing.join('\n  ')}`)
  })

  it('includes the UI entry assets the server serves at /', () => {
    const payload = collectPayloadSources(PROJECT_ROOT).map((absolute) =>
      relative(PROJECT_ROOT, absolute).split(sep).join('/'),
    )
    assert.ok(payload.includes('src/ui/public/index.html'), '缺少 UI 首页 index.html')
    assert.ok(payload.includes('src/ui/public/styles.css'), '缺少 UI 样式 styles.css')
    assert.ok(payload.includes('src/ui/public/app.js'), '缺少 UI 脚本 app.js')
  })

  it('never ships C# build inputs', () => {
    const payload = collectPayloadSources(PROJECT_ROOT)
    const cs = payload.filter((absolute) => absolute.endsWith('.cs'))
    assert.deepEqual(cs, [], '编译输入的 .cs 不该进载荷')
  })

  it('serves every asset index.html references', () => {
    const html = readFileSync(`${PROJECT_ROOT}/src/ui/public/index.html`, 'utf8')
    const referenced = [...html.matchAll(/(?:src|href)="(\/[^"#]+)"/g)].map((match) => match[1])
    assert.ok(referenced.length > 0, 'index.html 没有引用任何资源？')
    for (const ref of referenced) {
      const asset = `${PROJECT_ROOT}/src/ui/public${ref}`
      assert.ok(existsSync(asset), `index.html 引用的资源不存在：${ref}`)
    }
  })
})
