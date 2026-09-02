package artifactpattern

import (
	"path"
	"strings"
)

// Match applies portable slash-separated artifact glob semantics. A segment
// equal to ** matches zero or more complete path segments; other segments use
// path.Match and therefore never cross a slash.
func Match(pattern string, candidate string) (bool, error) {
	patternSegments := strings.Split(pattern, "/")
	candidateSegments := strings.Split(candidate, "/")
	type state struct {
		pattern   int
		candidate int
	}
	memo := make(map[state]bool)
	seen := make(map[state]bool)
	var match func(int, int) (bool, error)
	match = func(patternIndex int, candidateIndex int) (bool, error) {
		current := state{pattern: patternIndex, candidate: candidateIndex}
		if seen[current] {
			return memo[current], nil
		}
		seen[current] = true
		if patternIndex == len(patternSegments) {
			memo[current] = candidateIndex == len(candidateSegments)
			return memo[current], nil
		}
		segment := patternSegments[patternIndex]
		if segment == "**" {
			matched, err := match(patternIndex+1, candidateIndex)
			if err != nil || matched {
				memo[current] = matched
				return matched, err
			}
			if candidateIndex < len(candidateSegments) {
				matched, err = match(patternIndex, candidateIndex+1)
				memo[current] = matched
				return matched, err
			}
			return false, nil
		}
		if candidateIndex == len(candidateSegments) {
			return false, nil
		}
		segmentMatch, err := path.Match(segment, candidateSegments[candidateIndex])
		if err != nil || !segmentMatch {
			return false, err
		}
		matched, err := match(patternIndex+1, candidateIndex+1)
		memo[current] = matched
		return matched, err
	}
	return match(0, 0)
}
