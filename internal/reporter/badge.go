package reporter

import (
	"fmt"

	"github.com/kodivante/MCPwn/v3/internal/scorer"
)

func GenerateBadge(s scorer.Score) []byte {
	grade := string(s.Grade)
	color := scorer.GradeColor(s.Grade)
	return []byte(badgeSVG(grade, color))
}

func badgeSVG(grade, color string) string {
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="90" height="20" role="img" aria-label="MCPwn: %s">
  <title>MCPwn: %s</title>
  <rect width="57" height="20" fill="#555"/>
  <rect x="57" width="33" height="20" fill="%s"/>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="28" y="15">MCPwn</text>
    <text x="73" y="15">%s</text>
  </g>
</svg>`, grade, grade, color, grade)
}
