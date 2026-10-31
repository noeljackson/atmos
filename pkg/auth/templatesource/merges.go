package templatesource

import "gopkg.in/yaml.v3"

type mergeVisitState uint8

const (
	mergeVisiting mergeVisitState = iota + 1
	mergeVisited
)

// visitMergedAuth follows only auth entries promoted by a configuration merge.
// Other children remain application data even when the anchor lives under vars/settings.
// Per-input states bound shared merge graphs and reject cycles before rendering.
func visitMergedAuth(source *sourceIndex, node *yaml.Node, visit func(*yaml.Node) error) error {
	if source.mergeVisits == nil {
		source.mergeVisits = make(map[*yaml.Node]mergeVisitState)
	}
	switch source.mergeVisits[node] {
	case mergeVisiting:
		return inlineTemplateError()
	case mergeVisited:
		return nil
	}
	source.mergeVisits[node] = mergeVisiting
	if err := visitMergeNode(source, node, visit); err != nil {
		return err
	}
	source.mergeVisits[node] = mergeVisited
	return nil
}

func visitMergeNode(source *sourceIndex, node *yaml.Node, visit func(*yaml.Node) error) error {
	switch node.Kind {
	case yaml.AliasNode:
		return visitMergedAuth(source, node.Alias, visit)
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := visitMergedAuth(source, child, visit); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		return visitMergedAuthEntries(source, node, visit)
	}
	return nil
}

func visitMergedAuthEntries(source *sourceIndex, node *yaml.Node, visit func(*yaml.Node) error) error {
	for index := 0; index < len(node.Content); index += 2 {
		key, value := node.Content[index], node.Content[index+1]
		if key.Tag == "!!merge" {
			if err := visitMergedAuth(source, value, visit); err != nil {
				return err
			}
			continue
		}
		if key.Value != authKey && !templatedYAMLKey(source, key) {
			continue
		}
		if err := visitAuthEntry(source, key, value, visit); err != nil {
			return err
		}
	}
	return nil
}

// A physical credential scalar can be owned by direct and repeated merged auth paths.
// Visiting its auth declaration once prevents overlapping source replacements.
func visitAuthOnce(source *sourceIndex, auth *yaml.Node, visit func(*yaml.Node) error) error {
	if source.authVisited == nil {
		source.authVisited = make(map[*yaml.Node]bool)
	}
	if source.authVisited[auth] {
		return nil
	}
	source.authVisited[auth] = true
	return visit(auth)
}
