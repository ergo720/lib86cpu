/*
 * address space class
 *
 * ergo720                Copyright (c) 2022
 */

#include <map>


template<typename key>
class address_space {
public:
	static std::unique_ptr<address_space<key>> create();
	void insert(std::unique_ptr<memory_region_t<key>> region_to_add);
	void erase(key start, key end);
	const memory_region_t<key> *search(key addr);

private:
	using region_it = std::map<key, std::unique_ptr<memory_region_t<key>>>::iterator;
	address_space();
	region_it get_it(key addr);
	void split(region_it it, key split_at);

	std::map<key, std::unique_ptr<memory_region_t<key>>> m_region_map;
};

template<typename key>
address_space<key>::address_space()
{
	std::unique_ptr<memory_region_t<key>> region(new memory_region_t<key>);
	region->start = 0;
	region->end = std::numeric_limits<key>::max();
	m_region_map.emplace(region->start, std::move(region));
}

template<typename key>
std::unique_ptr<address_space<key>> address_space<key>::create()
{
	return std::unique_ptr<address_space<key>>(new address_space<key>);
}

template<typename key>
void address_space<key>::insert(std::unique_ptr<memory_region_t<key>> region_to_add)
{
	key start = region_to_add->start;
	key end = region_to_add->end;
	region_it it = get_it(start);
	memory_region_t<key> *region = it->second.get();
	key start_in_region = start - region->start;

	if (end <= region->end) {
		// new region fits inside the existing one

		if (end != region->end) {
			split(it, end);
		}

		if (start_in_region) {
			split(it, start - 1);
			it = std::next(it);
		}

		std::swap(*it->second, *region_to_add.get());
	}
	else {
		// new region doesn't fit inside the existing one

		auto next_it = std::next(it);
		while (next_it->second->end < end) {
			next_it = std::next(next_it);
		}

		if (next_it->second->start != end) {
			split(next_it, end);
		}

		if (start_in_region) {
			split(it, start - 1);
			it = std::next(it);
		}

		m_region_map.erase(it, std::next(next_it));
		m_region_map.emplace(start, std::move(region_to_add));
	}
}

template<typename key>
void address_space<key>::erase(key start, key end)
{
	region_it it = get_it(start);
	key start_in_region = start - it->second.get()->start;

	if (end <= it->second->end) {
		// region to delete fits inside the existing one

		if (end != it->second->end) {
			split(it, end);
		}

		if (start_in_region) {
			split(it, start - 1);
			it = std::next(it);
		}

		m_region_map.erase(it);
	}
	else {
		// region to delete doesn't fit inside the existing one

		auto next_it = std::next(it);
		while (next_it->second->end < end) {
			next_it = std::next(next_it);
		}

		if (next_it->second->start != end) {
			split(next_it, end);
		}

		if (start_in_region) {
			split(it, start - 1);
			it = std::next(it);
		}

		m_region_map.erase(it, std::next(next_it));
	}

	std::unique_ptr<memory_region_t<key>> region(new memory_region_t<key>);
	region->start = start;
	region->end = end;
	m_region_map.emplace(start, std::move(region));

	// check if the new unmapped region can be merged with its adjacent neighbors
	it = get_it(start);

	if (auto next_it = std::next(it); (next_it != m_region_map.end()) && (next_it->second->type == mem_type::unmapped)) {
		it->second->end = next_it->second->end;
		m_region_map.erase(next_it);
	}

	if (it != m_region_map.begin()) {
		auto prev_it = std::prev(it);
		if (prev_it->second->type == mem_type::unmapped) {
			prev_it->second->end = it->second->end;
			m_region_map.erase(it);
		}
	}
}

template<typename key>
const memory_region_t<key> *address_space<key>::search(key addr)
{
	return get_it(addr)->second.get();
}

template<typename key>
address_space<key>::region_it address_space<key>::get_it(key addr)
{
	return std::prev(m_region_map.upper_bound(addr));
}

template<typename key>
void address_space<key>::split(region_it it, key split_at)
{
	memory_region_t<key> new_region = *it->second;
	new_region.start = split_at + 1;
	it->second->end = split_at;
	m_region_map.emplace_hint(std::next(it), new_region.start, std::make_unique<memory_region_t<key>>(new_region));
}
