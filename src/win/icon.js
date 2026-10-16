import { deflateSync } from 'node:zlib'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * 应用图标生成：手写 PNG / ICO 编码器，不引入任何图像库。
 *
 * 为什么自己画：Windows 客户端的托盘、快捷方式、任务栏都需要一个图标文件，
 * 而项目坚持零依赖 —— 手写编码器约百行，换来"克隆下来就能跑、不装任何东西"。
 *
 * 图形：深色圆角方块 + 强调色盾牌轮廓 + 对勾（与环境闸门的语义一致）。
 * 用 4 倍超采样再降采样做抗锯齿，避免锯齿边缘。
 */

const ACCENT = [79, 140, 255]
const BACKGROUND = [22, 25, 34]
const CHECK = [54, 211, 153]

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
    directory[entry] = 0 // width 256 encoded as 0
    directory[entry + 1] = 0 // height 256 encoded as 0
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
 * 形状用纯几何描述：圆角矩形（背景）、盾牌（描边）、对勾（描边）。
 */
function sample(u, v) {
  // 背景：圆角矩形，圆角半径 0.22
  const radius = 0.22
  const inset = 0.02
  const left = inset
  const right = 1 - inset
  const top = inset
  const bottom = 1 - inset
  const dx = Math.max(left + radius - u, 0, u - (right - radius))
  const dy = Math.max(top + radius - v, 0, v - (bottom - radius))
  const insideRounded = Math.hypot(dx, dy) <= radius
  if (!insideRounded) return [0, 0, 0, 0]

  let color = BACKGROUND
  let alpha = 255

  // 盾牌轮廓：中心 (0.5,0.46)，宽 0.5，高 0.56，底端收成尖角
  const sx = (u - 0.5) / 0.25
  const sy = (v - 0.2) / 0.56
  const strokeWidth = 0.032
  const shieldOutline = (() => {
    if (sy < 0 || sy > 1) return false
    const halfWidth = sy < 0.62 ? 1 : 1 - (sy - 0.62) / 0.38
    const edge = Math.abs(Math.abs(sx) - halfWidth) < strokeWidth / 0.25
    const topEdge = sy < strokeWidth / 0.56 && Math.abs(sx) < 1
    return edge || topEdge
  })()

  // 对勾：两段粗线
  const checkStroke = 0.031
  const check =
    distanceToSegment(u, v, 0.4, 0.5, 0.472, 0.585) < checkStroke ||
    distanceToSegment(u, v, 0.472, 0.585, 0.615, 0.4) < checkStroke

  if (check) color = CHECK
  else if (shieldOutline) color = ACCENT

  // 背景做轻微上深下浅，避免纯色发闷
  if (color === BACKGROUND) {
    const shade = mix(0.86, 1.12, v)
    color = BACKGROUND.map((channel) => Math.min(255, Math.round(channel * shade)))
  }

  return [...color, alpha]
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
