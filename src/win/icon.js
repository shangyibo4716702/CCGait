import { deflateSync } from 'node:zlib'
import { createHash } from 'node:crypto'
import { mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * 应用图标生成：手写 PNG / ICO 编码器，不引入任何图像库。
 *
 * 为什么自己画：Windows 客户端的托盘、快捷方式、任务栏都需要一个图标文件，
 * 而项目坚持零依赖 —— 手写编码器约百行，换来"克隆下来就能跑、不装任何东西"。
 *
 * 图形：深色圆角方块 + **白色描边盾牌** + 白色对勾（线稿风格，与界面侧边栏 logo 一致）。
 *
 * 为什么把描边做粗：任务栏/通知区只有 16px，细描边在那个尺寸上会碎成一段段浅色，
 * 看着就是"糊的"。这里用 2.4/24 的线宽（比界面上那版还粗），缩到 16px 仍是完整轮廓。
 * 用 4 倍超采样再降采样做抗锯齿，避免锯齿边缘。
 */

/**
 * 底色：接近纯黑的单一色。
 *
 * 早先用的是竖向渐变，缩到 24/32px 之后那点明暗差会被抗锯齿抹成一片灰雾，
 * 看起来就是"糊"。参考 MoA Studio 的图标：纯色底 + 粗笔画，小尺寸下依然锐利。
 */
const BACKGROUND = [30, 30, 32]
/** 线稿：纯白，在近黑底上有最高对比度。 */
const STROKE = [255, 255, 255]

/**
 * 按输出尺寸给一组线宽参数。
 *
 * 规律和直觉相反：**尺寸越小，相对线宽要越粗、留白要越少**。
 * 16~32px 下 2px 的笔画会被抗锯齿摊成半透明的灰边，远看就是"糊"；
 * 参考 MoA Studio 的图标也能看出来：主体极粗、几乎占满画布，小尺寸才锐利。
 * 同时把对勾略微缩小，避免加粗后与盾牌轮廓粘在一起。
 *
 * 早期版本做反了（小尺寸收细线宽），实测任务栏图标发虚，就是这里的原因。
 */
function strokeProfile(size) {
  if (size <= 16) return { shield: 3.0 / 24, check: 2.6 / 24, checkScale: 0.72 }
  if (size <= 24) return { shield: 2.7 / 24, check: 2.4 / 24, checkScale: 0.78 }
  if (size <= 32) return { shield: 2.5 / 24, check: 2.4 / 24, checkScale: 0.84 }
  if (size <= 48) return { shield: 2.3 / 24, check: 2.5 / 24, checkScale: 0.9 }
  return { shield: 2.2 / 24, check: 2.5 / 24, checkScale: 0.92 }
}

/**
 * 盾牌轮廓（24 单位设计稿 → 归一化）。
 *
 * 比界面里那条路径**更宽、更矮**：界面看到的 logo 尺寸大，留白舒服；但缩到 24~32px 时，
 * 细长轮廓会被抗锯齿摊成灰边，整块糊掉。参考 MoA Studio 的图标可以看出来：
 * 主体占满画面、笔画粗、留白少 —— 那才是小尺寸下清晰的写法。
 */
function shieldOutline(samples = 24) {
  const points = [
    [12 / 24, 2.2 / 24],
    [19.6 / 24, 5.4 / 24],
    [19.6 / 24, 12 / 24],
  ]
  const cubic = (x0, y0, cx1, cy1, cx2, cy2, x1, y1) => {
    for (let index = 1; index <= samples; index += 1) {
      const t = index / samples
      const mt = 1 - t
      const x =
        mt * mt * mt * x0 + 3 * mt * mt * t * cx1 + 3 * mt * t * t * cx2 + t * t * t * x1
      const y =
        mt * mt * mt * y0 + 3 * mt * mt * t * cy1 + 3 * mt * t * t * cy2 + t * t * t * y1
      points.push([x / 24, y / 24])
    }
  }
  // 右半边下收 → 底部 → 左半边下收
  cubic(19.6, 12, 19.6, 16.8, 16.2, 20.6, 12, 21.9)
  cubic(12, 21.9, 7.8, 20.6, 4.4, 16.8, 4.4, 12)
  points.push([4.4 / 24, 5.4 / 24])
  return points
}

const SHIELD_POINTS = shieldOutline()

/** 对勾：两段线，取自界面里 M9 12l2 2 4-4。 */
const CHECK_POINTS = [
  [9 / 24, 12 / 24],
  [11 / 24, 14 / 24],
  [15 / 24, 10 / 24],
]

/**
 * 小尺寸用的对勾：整体往中心收一圈。
 *
 * 16px 下原尺寸的对勾顶点几乎顶到盾牌轮廓，两个白色形状粘成一块，
 * 远看就是一个白点。收缩之后轮廓和对勾之间留出底色缝隙，才分得开。
 */
function shrunkCheck(points, factor) {
  return points.map(([x, y]) => [0.5 + (x - 0.5) * factor, 0.5 + (y - 0.5) * factor])
}

/** 点到折线的最短距离。 */
function distanceToPolyline(u, v, points, closed = false) {
  let best = Infinity
  const limit = closed ? points.length : points.length - 1
  for (let index = 0; index < limit; index += 1) {
    const [x1, y1] = points[index]
    const [x2, y2] = points[(index + 1) % points.length]
    const distance = distanceToSegment(u, v, x1, y1, x2, y2)
    if (distance < best) best = distance
  }
  return best
}

/** 点是否在圆角矩形内（底）。 */
function insideRoundedSquare(u, v, radius = 0.22, inset = 0.02) {
  const dx = Math.max(inset + radius - u, 0, u - (1 - inset - radius))
  const dy = Math.max(inset + radius - v, 0, v - (1 - inset - radius))
  return Math.hypot(dx, dy) <= radius
}

function crc32(buffer) {
  let table = crc32.table
  if (!table) {
    table = crc32.table = new Int32Array(256)
    for (let index = 0; index < 256; index += 1) {
      let value = index
      for (let bit = 0; bit < 8; bit += 1) {
        value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1
      }
      table[index] = value
    }
  }
  let crc = -1
  for (let index = 0; index < buffer.length; index += 1) {
    crc = (crc >>> 8) ^ table[(crc ^ buffer[index]) & 0xff]
  }
  return (crc ^ -1) >>> 0
}

function chunk(type, data) {
  const length = Buffer.alloc(4)
  length.writeUInt32BE(data.length, 0)
  const typeAndData = Buffer.concat([Buffer.from(type, 'ascii'), data])
  const crc = Buffer.alloc(4)
  crc.writeUInt32BE(crc32(typeAndData), 0)
  return Buffer.concat([length, typeAndData, crc])
}

/** RGBA 像素数组 → PNG 缓冲区。 */
export function encodePng(width, height, rgba) {
  const raw = Buffer.alloc((width * 4 + 1) * height)
  for (let y = 0; y < height; y += 1) {
    const rowStart = y * (width * 4 + 1)
    raw[rowStart] = 0 // filter: none
    rgba.copy(raw, rowStart + 1, y * width * 4, (y + 1) * width * 4)
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(width, 0)
  ihdr.writeUInt32BE(height, 4)
  ihdr[8] = 8 // bit depth
  ihdr[9] = 6 // color type: RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ])
}

/** ICO 容器（PNG 载荷，Vista+ 支持）。 */
export function encodeIco(pngBuffers) {
  const count = pngBuffers.length
  const header = Buffer.alloc(6)
  header.writeUInt16LE(0, 0)
  header.writeUInt16LE(1, 2) // type: icon
  header.writeUInt16LE(count, 4)

  const directory = Buffer.alloc(16 * count)
  let offset = 6 + 16 * count
  const images = []
  pngBuffers.forEach((png, index) => {
    const size = png.length
    const entry = 16 * index
    // IHDR 里的真实宽高。ICO 目录必须写对尺寸：假尺寸会让外壳按错误的尺寸挑图，
    // 结果就是任务栏/通知区拿到被放大的糊图（256 记作 0，其余按实际像素写）。
    const dimension = png.readUInt32BE(16)
    const encoded = dimension >= 256 ? 0 : dimension
    directory[entry] = encoded
    directory[entry + 1] = encoded
    directory[entry + 2] = 0 // palette
    directory[entry + 3] = 0
    directory.writeUInt16LE(1, entry + 4) // color planes
    directory.writeUInt16LE(32, entry + 6) // bits per pixel
    directory.writeUInt32LE(size, entry + 8)
    directory.writeUInt32LE(offset, entry + 12)
    offset += size
    images.push(png)
  })
  return Buffer.concat([header, directory, ...images])
}

const mix = (a, b, t) => a + (b - a) * t

/** 距离点到线段的最短距离（用于画粗线条）。 */
function distanceToSegment(px, py, x1, y1, x2, y2) {
  const dx = x2 - x1
  const dy = y2 - y1
  const lengthSquared = dx * dx + dy * dy
  const t = lengthSquared === 0 ? 0 : Math.max(0, Math.min(1, ((px - x1) * dx + (py - y1) * dy) / lengthSquared))
  const cx = x1 + t * dx
  const cy = y1 + t * dy
  return Math.hypot(px - cx, py - cy)
}

/**
 * 在归一化坐标（0..1）上采样一个点：返回 [r,g,b,a]。
 * 形状用纯几何描述：圆角矩形（底）、盾牌轮廓（描边）、对勾（描边）。
 *
 * profile 是当前尺寸的线宽方案（见 strokeProfile）：小尺寸用更粗的笔画、更小的对勾，
 * 这样白线在像素网格上才立得住，不会被抗锯齿摊成灰边。
 */
function sample(u, v, profile = strokeProfile(256)) {
  // 底：圆角正方形，圆角半径 0.22、内缩 0.02
  if (!insideRoundedSquare(u, v)) return [0, 0, 0, 0]

  // 线稿：盾牌轮廓 + 对勾，两处都用「到折线的距离 < 半个线宽」判描边。
  // 只有描边是白的，其余是底色 —— 这正是界面里那个 logo 的观感。
  const checkPoints = profile.checkScale < 1 ? shrunkCheck(CHECK_POINTS, profile.checkScale) : CHECK_POINTS
  const onShield = distanceToPolyline(u, v, SHIELD_POINTS, true) <= profile.shield / 2
  const onCheck = distanceToPolyline(u, v, checkPoints) <= profile.check / 2
  if (onShield || onCheck) return [...STROKE, 255]

  return [...BACKGROUND, 255]
}

/**
 * 生成指定尺寸的图标 RGBA。
 *
 * 抗锯齿强度按尺寸分档，这里有一个非直观的取舍：
 * - 大尺寸（>=48）用 4× 超采样，曲线才不会有阶梯；
 * - 小尺寸（24~32）用 2× —— 4× 会把 2~3px 的笔画摊成两圈半透明灰边，
 *   实测 32px 下中间灰占 14%，而参考的 MoA Studio 图标只有 10%，视觉上就是"糊"；
 *   2× 把过渡收窄到单像素，既保留平滑又不会发虚；
 * - 16px 仍用 4×：那一档笔画只有 2px，硬边会直接变成锯齿（实测过，用户也否了）。
 */
export function renderIconRgba(size) {
  const profile = strokeProfile(size)
  const supersample = size >= 48 ? 4 : size >= 24 ? 2 : 4
  const rgba = Buffer.alloc(size * size * 4)
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      let r = 0
      let g = 0
      let b = 0
      let a = 0
      for (let sy = 0; sy < supersample; sy += 1) {
        for (let sx = 0; sx < supersample; sx += 1) {
          const u = (x + (sx + 0.5) / supersample) / size
          const v = (y + (sy + 0.5) / supersample) / size
          const [pr, pg, pb, pa] = sample(u, v, profile)
          const weight = pa / 255
          r += pr * weight
          g += pg * weight
          b += pb * weight
          a += pa
        }
      }
      const samples = supersample * supersample
      const alphaAverage = a / samples
      const weightSum = alphaAverage === 0 ? 1 : alphaAverage / 255
      const offset = (y * size + x) * 4
      rgba[offset] = Math.round(r / samples / weightSum)
      rgba[offset + 1] = Math.round(g / samples / weightSum)
      rgba[offset + 2] = Math.round(b / samples / weightSum)
      // 硬边模式（无超采样）下 alpha 只有 0 或 255：圆角外透明、圆角内实心，
      // 不再产生"半透明灰边"——灰边正是小图标看起来发虚的直接原因。
      rgba[offset + 3] = Math.round(alphaAverage)
    }
  }
  return rgba
}

export function buildIconPng(size) {
  const rgba = renderIconRgba(size)
  return encodePng(size, size, rgba)
}

/**
 * 生成多尺寸 .ico。
 *
 * 尺寸必须覆盖 Windows 真正会用的那些，否则它会拿相邻尺寸去缩放，缩放就会糊：
 *   16（通知区）· 20/24（100% 缩放的任务栏）· 32（125%/经典任务栏）
 *   40（125% 大图标）· 48（资源管理器）· 64/96 · 128/256（大图标/预览）
 * 早先只做了 16/32/48/64/128/256：100% 缩放下任务栏要 24，只能把 32 缩下去，
 * 实测就是"任务栏图标明显发虚"。
 */
export function buildIco() {
  return encodeIco(ICON_SIZES.map((size) => buildIconPng(size)))
}

/**
 * 供页面 favicon 的 ICO。
 *
 * 关键取舍：**故意不给 16px 那一档**。
 * 应用窗口（Edge APP 模式）的任务栏图标取自页面 favicon，而 Windows 任务栏在
 * 100% 缩放下显示 24px。如果 favicon 里同时有 16 和 32，Chromium 会给窗口一个
 * 16px 的图标，Windows 再把它放大到 24 —— 放大必然发虚（实测任务栏一直是糊的）。
 * 只给 32 和 48，Windows 只能**缩小**，缩小是清晰的。
 *
 * 快捷方式用的 ccgait.ico 不受这个限制，仍是全尺寸档（见 buildIco）。
 */
export function buildFaviconIco() {
  return encodeIco([32, 48].map((size) => buildIconPng(size)))
}

/** ICO 里包含的尺寸（导出给测试钉住：少一个就会退化成缩放糊图）。 */
export const ICON_SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]

/**
 * 写图标文件；返回路径。dir 缺省时用 stateDir。
 *
 * 除了固定的 ccgait.ico，还会写一份**带内容哈希**的同内容副本（ccgait-<hash>.ico）。
 * 为什么需要：Windows 的图标缓存按**路径**索引，同一个路径换了内容它不一定重读 ——
 * 实测换完图标之后，桌面快捷方式还是旧图。快捷方式指向带哈希的新路径，缓存必然失效。
 */
export function writeIconFiles(dir) {
  mkdirSync(dir, { recursive: true })
  const ico = buildIco()
  const icoPath = join(dir, 'ccgait.ico')
  const pngPath = join(dir, 'ccgait.png')
  writeFileSync(icoPath, ico)
  writeFileSync(pngPath, buildIconPng(256))

  // 版本化副本：快捷方式用这个路径，图标一改路径就变，绕开系统图标缓存。
  const hash = createHash('sha256').update(ico).digest('hex').slice(0, 8)
  const versionedPath = join(dir, `ccgait-${hash}.ico`)
  writeFileSync(versionedPath, ico)
  // 顺手清掉旧版本副本，避免状态目录里堆一串历史图标。
  try {
    for (const name of readdirSync(dir)) {
      if (!/^ccgait-[0-9a-f]{8}\.ico$/.test(name)) continue
      if (join(dir, name) === versionedPath) continue
      rmSync(join(dir, name), { force: true })
    }
  } catch {
    // 清理失败不影响主流程。
  }

  return { ico: icoPath, versionedIco: versionedPath, png: pngPath, hash }
}

/**
 * 生成同一套图形的 SVG 版本。
 *
 * 为什么位图之外还要 SVG：应用窗口是 Edge APP 模式，任务栏那一格用的是页面 favicon。
 * 位图只有固定几个尺寸，Edge 拿最小的那张放大时就会糊（实测任务栏图标明显发虚）。
 * Chromium 支持 SVG favicon，可以按目标分辨率即时光栅化，任何 DPI 下都清晰。
 *
 * 图形与位图版严格一致：深色圆角方块 + 白色描边盾牌 + 白色对勾。
 */
export function buildIconSvg(size = 256) {
  const rounded = size * 0.22
  const shieldPath = 'M12 3l7 3v6c0 4.4-2.9 7.9-7 9-4.1-1.1-7-4.6-7-9V6z'
  const checkPath = 'M9 12l2 2 4-4'
  // 线宽与位图版的大尺寸档保持一致；SVG 由内核按目标分辨率渲染，本身就是清晰的。
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">`,
    `<rect x="${size * 0.02}" y="${size * 0.02}" width="${size * 0.96}" height="${size * 0.96}" rx="${rounded}" fill="rgb(${BACKGROUND.join(',')})"/>`,
    `<g transform="scale(${size / 24})" fill="none" stroke="rgb(${STROKE.join(',')})" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">`,
    `<path d="${shieldPath}"/>`,
    `<path d="${checkPath}"/>`,
    '</g>',
    '</svg>',
  ].join('')
}
