package httpsec

// SignalFilterWants is signalFilter.wants of name, for a filter over the chain's set chain,
// narrowed to names when narrowed is true.
func SignalFilterWants(chain []Signal, narrowed bool, names []string, name string) bool {
	f := signalFilter{narrowed: narrowed, names: map[string]bool{}}

	if chain != nil {
		f.chain = make(map[Signal]bool, len(chain))
		for _, s := range chain {
			f.chain[s] = true
		}
	}

	for _, n := range names {
		f.names[n] = true
	}

	return f.wants(name)
}
