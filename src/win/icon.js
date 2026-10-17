import { deflateSync } from 'node:zlib'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * 应用图标生成：手写 PNG / ICO 编码器，不引入任何图像库。
 *
 * 为什么自己画：Windows 客户端的托盘、快捷方式、任务栏都需要一个图标文件，
 * 而项目坚持零依赖 —— 手写编码器约百行，换来"克隆下来就能跑、不装任何东西"。
 *
 * 图形：深色圆角方块 + **实心**亮蓝盾牌 + 白色粗对勾。
 * 实心而不是描边，是为了小尺寸：任务栏/通知区只有 16px，1~2px 的描边在那个尺寸上
 * 会碎成一段段浅色，看着就是"糊的"；实心色块 + 一个粗对勾，缩到 16px 仍然是
 * 一眼能认出的剪影。
 * 用 4 倍超采样再降采样做抗锯齿，避免锯齿边缘。
 */

/** 底色：上浅下深的冷灰，让图标在浅色任务栏上也有明确边界。 */
const BACKGROUND_TOP = [32, 37, 51]
const BACKGROUND_BOTTOM = [15, 18, 25]
/** 盾牌：亮蓝到深蓝的竖向渐变（填充，不描边）。 */
const SHIELD_TOP = [124, 178, 255]
const SHIELD_BOTTOM = [43, 102, 236]
/** 对勾：纯白，在蓝底上有最高对比度。 */
const CHECK = [255, 255, 255]

/** 盾牌几何（归一化坐标）：顶部平边 → 两侧直下 → 下半部收成圆角尖。 */
const SHIELD_TOP_Y = 0.175
const SHIELD_SHOULDER_Y = 0.545
const SHIELD_BOTTOM_Y = 0.845
const SHIELD_HALF_WIDTH = 0.275

function insideShield(u, v) {
  if (v < SHIELD_TOP_Y || v > SHIELD_BOTTOM_Y) return false
  const dx = Math.abs(u - 0.5)
  if (dx > SHIELD_HALF_WIDTH) return false
  if (v <= SHIELD_SHOULDER_Y) return true
  const t = (v - SHIELD_SHOULDER_Y) / (SHIELD_BOTTOM_Y - SHIELD_SHOULDER_Y)
  // 指数 < 1 让收拢来得晚一点，底部收成圆角尖而不是三角。
  return dx <= SHIELD_HALF_WIDTH * (1 - t) ** 0.72
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
 * 形状用纯几何描述：圆角矩形（底）、实心盾牌（填充）、粗对勾（描边）。
 */
function sample(u, v) {
  // 底：圆角正方形，圆角半径 0.22、内缩 0.02
  const radius = 0.22
  const inset = 0.02
  const dx = Math.max(inset + radius - u, 0, u - (1 - inset - radius))
  const dy = Math.max(inset + radius - v, 0, v - (1 - inset - radius))
  if (Math.hypot(dx, dy) > radius) return [0, 0, 0, 0]

  if (insideShield(u, v)) {
    const t = (v - SHIELD_TOP_Y) / (SHIELD_BOTTOM_Y - SHIELD_TOP_Y)
    let color = SHIELD_TOP.map((channel, index) => Math.round(mix(channel, SHIELD_BOTTOM[index], t)))
    // 对勾：两段粗线（圆头端点），宽度 0.05 —— 比原来细描边粗一倍，缩到 16px 也不会断。
    const stroke = 0.05
    const check =
      distanceToSegment(u, v, 0.383, 0.494, 0.466, 0.583) < stroke ||
      distanceToSegment(u, v, 0.466, 0.583, 0.638, 0.4) < stroke
    if (check) color = CHECK
    return [...color, 255]
  }

  return [
    ...BACKGROUND_TOP.map((channel, index) => Math.round(mix(channel, BACKGROUND_BOTTOM[index], v))),
    255,
  ]
}

/** 生成指定尺寸的图标 RGBA（4 倍超采样抗锯齿）。 */
export function renderIconRgba(size) {
  const scale = 4
  const rgba = Buffer.alloc(size * size * 4)
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      let r = 0
      let g = 0
      let b = 0
      let a = 0
      for (let sy = 0; sy < scale; sy += 1) {
        for (let sx = 0; sx < scale; sx += 1) {
          const u = (x + (sx + 0.5) / scale) / size
          const v = (y + (sy + 0.5) / scale) / size
          const [pr, pg, pb, pa] = sample(u, v)
          const weight = pa / 255
          r += pr * weight
          g += pg * weight
          b += pb * weight
          a += pa
        }
      }
      const samples = scale * scale
      const alphaAverage = a / samples
      const weightSum = alphaAverage === 0 ? 1 : alphaAverage / 255
      const offset = (y * size + x) * 4
      rgba[offset] = Math.round(r / samples / weightSum)
      rgba[offset + 1] = Math.round(g / samples / weightSum)
      rgba[offset + 2] = Math.round(b / samples / weightSum)
      rgba[offset + 3] = Math.round(alphaAverage)
    }
  }
  return rgba
}

export function buildIconPng(size) {
  const rgba = renderIconRgba(size)
  return encodePng(size, size, rgba)
}

/** 生成多尺寸 .ico（16/32/48/64/128/256）。 */
export function buildIco() {
  const sizes = [16, 32, 48, 64, 128, 256]
  return encodeIco(sizes.map((size) => buildIconPng(size)))
}

/** 写图标文件；返回路径。dir 缺省时用 stateDir。 */
export function writeIconFiles(dir) {
  mkdirSync(dir, { recursive: true })
  const icoPath = join(dir, 'ccgait.ico')
  const pngPath = join(dir, 'ccgait.png')
  writeFileSync(icoPath, buildIco())
  writeFileSync(pngPath, buildIconPng(256))
  return { ico: icoPath, png: pngPath }
}
