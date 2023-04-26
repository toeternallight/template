#include <utility>
#include <iostream>
#include <algorithm>
#include <iterator>
#include <array>
#include <type_traits>
template<typename...types> struct Types{
  typedef Types type;
};
template<int N, typename F> struct Val;
template<int N, typename F, typename...types> struct Val<N, Types<F, types...>>
    : Val<N+1, Types<types...>> {
  using Val<N+1, Types<types...>>::getType;
  static int getType(F) {
    return N;
  }
};
template<int N, typename...types> struct Val<N, Types<void, types...>>
    : Val<N+1, Types<types...>> {
  using Val<N+1, Types<types...>>::getType;
  static int getType() {
    return N;
  }
};

template<int N> struct Val<N, Types<>>{
   static int getType() {
     return N;
   }
};
template<int N> struct Val<N, Types<void>>{
   static int getType() {
     return N;
   }
};
int main() {
  using TypeVal = Val<0, Types<int, char, int, void, long>>;
  int a;
  char b;
  std::cout << TypeVal::getType(a) << ", " << TypeVal::getType(b) << "," << TypeVal::getType() << std::endl;
  return 0;
}
