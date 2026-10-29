-- Prepare the Markdown report for the PDF: the H1 heading and the author
-- line that follows it are dropped (the title page shows the metadata fields
-- "short-title" and "author" instead, and the running header shows
-- "header-left"), and every other heading moves up one level
-- so that "##" sections are numbered 1, 2, 3...
function Pandoc(doc)
  local blocks = {}
  local after_title = false
  for _, block in ipairs(doc.blocks) do
    if after_title then
      -- Skip the author line right after the H1.
      after_title = false
    elseif block.t == "Header" and block.level == 1 then
      after_title = true
    elseif block.t == "Header" then
      block.level = block.level - 1
      table.insert(blocks, block)
    else
      table.insert(blocks, block)
    end
  end
  doc.blocks = blocks
  if doc.meta["short-title"] then
    doc.meta.title = doc.meta["short-title"]
  end
  -- The title page author is raw LaTeX; give the PDF metadata a plain name.
  if doc.meta["pdf-author"] then
    doc.meta["author-meta"] = doc.meta["pdf-author"]
  end
  return doc
end
