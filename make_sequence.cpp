#include <utility>
#include <iostream>
#include <algorithm>
#include <iterator>
#include <array>
template<int...val> struct Val {};
template<int...val> void print(struct Val<val...>) {
  std::array<int, sizeof...(val)> arr{val...};
  std::copy(arr.begin(), arr.end(), std::ostream_iterator<int>(std::cout, " "));
  std::endl(std::cout);
}
template<typename L, typename R> struct merge;
template<int...lval, int...rval> struct merge<Val<lval...>, Val<rval...>> {
  using type = Val<lval..., sizeof...(lval) + rval...>;
};
template<unsigned N> struct make_sequence;
template<>
struct make_sequence<0>{
  using type = Val<>;
};
template<>
struct make_sequence<1>{
  using type = Val<0>;
};
template<unsigned N>
struct make_sequence {
  using type = typename merge<typename make_sequence<N/2>::type,
	                      typename make_sequence<N - N/2>::type>::type;
};
int main() {
  print(typename merge<Val<1,2,3,4>, Val<4,5,6,7>>::type());
  print(typename make_sequence<10>::type());
  return 0;
}
