#include <iostream>
template<char ...C> struct cstring { };

template<template<char...> class P, typename S, typename R, int N>
struct Expand;

template<template<char...> class P, char S1, char ...S, char ...R, int N>
struct Expand<P, cstring<S1, S...>, cstring<R...>, N> :
  Expand<P, cstring<S...>, cstring<R..., S1>, N-1>{ };

template<template<char...> class P, char S1, char ...S, char ...R>
struct Expand<P, cstring<S1, S...>, cstring<R...>, 0> {
  typedef P<R...> type;
};

template<char ...S>
struct Test {
  static void print() {
    char x[] = { S... };
    std::cout << sizeof...(S) << std::endl;
    std::cout << x << std::endl;
  }
};

template<char ...C>
void process(cstring<C...>) {
  std::cout << "start" << std::endl;
}


#define E(L,I)  (I < sizeof(L)) ? L[I] : 0

#define STR(X, L)                                                       \
  typename Expand<X,                                                    \
                  cstring<E(L,0),E(L,1),E(L,2),E(L,3),E(L,4), E(L,5),   \
                          E(L,6),E(L,7),E(L,8),E(L,9),E(L,10), E(L,11), \
                          E(L,12),E(L,13),E(L,14),E(L,15),E(L,16), E(L,17)>, \
                  cstring<>, sizeof L-1>::type

#define CSTR(L) STR(cstring, L)
int main() {
  typedef STR(Test, "Hello folks") type;
  type::print();

  process(CSTR("Hi guys")());
}
//方法二
template <unsigned int N>
constexpr char getch (char const (&s) [N], unsigned int i)
{
    return i >= N ? '\0' : s[i];
}

template<char ... Cs>
struct split_helper;

template<char C, char ... Cs>
struct split_helper<C, Cs...>
{
    typedef push_front_t<typename split_helper<Cs...>::type, char_<C>> type;
};

template<char ... Cs>
struct split_helper<'\0', Cs...>
{
    typedef std::integer_sequence<char> type;
};

template<char ... Cs>
using split_helper_t = typename split_helper<Cs...>::type;
#define SPLIT_CHARS_EXTRACT(z, n, data) \
    BOOST_PP_COMMA_IF(n) getch(data, n)
#define STRING_N(n, str)   \
    split_helper_t<BOOST_PP_REPEAT(n, SPLIT_CHARS_EXTRACT, str)>
#define STRING(str) STRING_N(BOOST_PP_LIMIT_REPEAT, str)

//方法三
template <char... Chars> class CharTuple {};
template <typename Tuple, char ch> class Cons;
template <char... Chars, char ch> class Cons<CharTuple<Chars... ch>> {
    typedef CharTuple<ch, Chars...> type;
}
template <bool Condition, typename TrueType, typename FalseType> class If {
    typedef typename TrueType::type type;
};
template <typename TrueType, typename FalseType> class If<False> {
    typedef typename FalseType::type type;
};
template <typename T> class Identity {
    typedef T type;
};

template <char* str> class StringToChars {
    typedef typename If<*str == '\0', Identity<CharTuple<>>,
                        Cons<*str, typename StringToChars<str + 1>::type>>::type type;
};
//方法四
//In C++14, this can be done by using an immediately invoked lambda and a static member function, similar to BOOST_HANA_STRING:
#include <utility>

template <char... Cs>
struct my_string {};

template <typename T, std::size_t... Is>
constexpr auto as_chars_impl(std::index_sequence<Is...>) {
    return my_string<T::str()[Is]...>{};
}

template <typename T>
constexpr auto as_chars() {
    return as_chars_impl<T>(
        std::make_index_sequence<sizeof(T::str())-1>{});
}

#define STR(literal)                                        \
    []{                                                     \
        struct literal_to_chars {                           \
            static constexpr decltype(auto) str() {         \
                return literal;                             \
            }                                               \
        };                                                  \
        return as_chars<literal_to_chars>();                \
    }()
