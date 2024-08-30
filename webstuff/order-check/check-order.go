package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
)

func after0(r0 int, c0 int, r1 int, c1 int) bool {
	if r1 < r0 {
		return false
	}
	if r1 > r0 {
		return true
	}
	if c1 > c0 {
		return true
	}
	return false
}

func after(s0 token.Position, s1 token.Position) bool {
	return after0(s0.Line, s0.Column, s1.Line, s1.Column)
}

func main() {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, os.Args[1], nil, parser.AllErrors)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Define a map to track function declarations
	funcDecls := make(map[string]token.Pos)

	// Traverse the AST
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			{
				// Record the position of each function declaration
				pos := x.Pos()
				funcDecls[x.Name.Name] = pos
				fpos := fset.Position(pos)
				fmt.Printf("Function %s defined at position %d:%d\n", x.Name.Name, fpos.Line, fpos.Column)
			}
		}
		return true
	})

	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			{
				// Check if the function is called before it's declared
				if ident, ok := x.Fun.(*ast.Ident); ok {
					pos := x.Pos()
					fpos := fset.Position(pos)
					dPos, exists := funcDecls[ident.Name]
					if exists {
						fmt.Printf("Function %s called at position %d:%d\n", ident.Name, fpos.Line, fpos.Column)
						dpos := fset.Position(dPos)
						if after(fpos, dpos) {
							fmt.Printf("Function %s is used before it is defined at position %d:%d\n", ident.Name, dpos.Line, dpos.Column)
						}
					}

				}
			}
		}
		return true
	})
}
