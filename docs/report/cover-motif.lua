-- Grid of dataset rows for the title page (see cover.tex). Rows are filled
-- group by group: a group of 1 to 3 rows is linked by a bar and has a single
-- colour (80% train, 10% validation, 10% test). Deterministic (fixed seed).
math.randomseed(42)

local cols, rows = 15, 7
local size, gap = 0.42, 0.2
local x0, y0 = 9.6, 21.9

local function pick()
  local r = math.random()
  if r < 0.8 then
    return "train"
  elseif r < 0.9 then
    return "validation"
  end
  return "test"
end

for row = 0, rows - 1 do
  local col = 0
  while col < cols do
    local len = math.min(cols - col, ({ 1, 1, 2, 2, 3 })[math.random(5)])
    local colour = pick()
    for i = 0, len - 1 do
      local c = col + i
      -- Fade towards the left so the motif does not compete with the title.
      local opacity = 0.2 + 0.75 * (c / (cols - 1))
      local x = x0 + c * (size + gap)
      local y = y0 + row * (size + gap)
      tex.print(string.format(
        "\\fill[%s,opacity=%.2f,rounded corners=1pt] (%.3f,%.3f) rectangle ++(%.3f,%.3f);",
        colour, opacity, x, y, size, size))
      if i > 0 then
        tex.print(string.format(
          "\\fill[%s,opacity=%.2f] (%.3f,%.3f) rectangle ++(%.3f,%.3f);",
          colour, opacity, x - gap, y + size / 2 - 0.04, gap, 0.08))
      end
    end
    col = col + len
  end
end
