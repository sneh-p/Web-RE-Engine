import { Marked, type Tokens } from 'marked';

const escapeHtml = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

// AI output and analyst notes can quote sample content, so raw HTML is shown as text,
// images are dropped and only http(s) links survive
const safeMarked = new Marked({
  gfm: true,
  renderer: {
    html(token: Tokens.HTML | Tokens.Tag) {
      return escapeHtml(token.text);
    },
    image(token: Tokens.Image) {
      return escapeHtml(token.text || '');
    },
    link(this: any, token: Tokens.Link) {
      const text = this.parser.parseInline(token.tokens);
      if (!/^https?:\/\//i.test(token.href)) return text;
      return `<a href="${escapeHtml(token.href)}" rel="noopener noreferrer nofollow" target="_blank">${text}</a>`;
    },
  },
});

export function renderSafeMarkdown(md: string): string {
  return safeMarked.parse(md, { async: false }) as string;
}

export { escapeHtml };
