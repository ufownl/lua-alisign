#ifndef ALISIGN_SCOPE_GUARD_HPP
#define ALISIGN_SCOPE_GUARD_HPP

#include <utility>

namespace alisign {

template <class Fun>
class scope_guard {
public:
  scope_guard(Fun f)
    : fun_(std::move(f))
    , enabled_(true) {
    // nop
  }

  scope_guard(scope_guard&& x)
    : fun_(std::move(x.fun_))
    , enabled_(x.enabled_) {
    x.enabled_ = false;
  }

  ~scope_guard() {
    if (enabled_) {
      fun_();
    }
  }

private:
  Fun fun_;
  bool enabled_;
};

template <class Fun>
scope_guard<Fun> make_scope_guard(Fun f) {
  return {std::move(f)};
}

}

#endif  // ALISIGN_SCOPE_GUARD_HPP
