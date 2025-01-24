package frontend

import (
	"io"

	"github.com/gomarkdown/markdown/ast"
	"github.com/lkarlslund/adalanche/modules/ui"
)

type MarkDownIndexRenderer struct {
	level int
}

// RenderHeader
func (mdir *MarkDownIndexRenderer) RenderHeader(w io.Writer, ast ast.Node) {

}

// RenderFooter
func (mdir *MarkDownIndexRenderer) RenderFooter(w io.Writer, ast ast.Node) {
}

// RenderNode
func (mdir *MarkDownIndexRenderer) RenderNode(w io.Writer, node ast.Node, entering bool) ast.WalkStatus {
	if heading, ok := node.(*ast.Heading); ok { // Check if the node is a Heading
		if entering {
			mdir.level++
			ui.Debug().Msgf("Node %s", string(heading.Content))
		} else {
			mdir.level--
		}
	}
	return ast.GoToNext
}
