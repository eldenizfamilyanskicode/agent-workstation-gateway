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

// CouldMatchDescendant reports whether at least one path strictly beneath the
// slash-separated prefix can match pattern. Collectors use it to attribute a
// skipped directory boundary to only the patterns that could have traversed it.
func CouldMatchDescendant(pattern string, prefix string) (bool, error) {
	patternSegments := strings.Split(pattern, "/")
	prefixSegments := strings.Split(prefix, "/")
	type state struct {
		pattern int
		prefix  int
	}
	memo := make(map[state]bool)
	seen := make(map[state]bool)
	var possible func(int, int) (bool, error)
	possible = func(patternIndex int, prefixIndex int) (bool, error) {
		current := state{pattern: patternIndex, prefix: prefixIndex}
		if seen[current] {
			return memo[current], nil
		}
		seen[current] = true
		if prefixIndex == len(prefixSegments) {
			memo[current] = patternIndex < len(patternSegments)
			return memo[current], nil
		}
		if patternIndex == len(patternSegments) {
			return false, nil
		}
		segment := patternSegments[patternIndex]
		if segment == "**" {
			matched, err := possible(patternIndex+1, prefixIndex)
			if err != nil || matched {
				memo[current] = matched
				return matched, err
			}
			matched, err = possible(patternIndex, prefixIndex+1)
			memo[current] = matched
			return matched, err
		}
		segmentMatch, err := path.Match(segment, prefixSegments[prefixIndex])
		if err != nil || !segmentMatch {
			return false, err
		}
		matched, err := possible(patternIndex+1, prefixIndex+1)
		memo[current] = matched
		return matched, err
	}
	return possible(0, 0)
}
