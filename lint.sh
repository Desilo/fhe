find src test -name '*.h' -o -name '*.cpp' -o -name '*.cuh' -o -name '*.cu' | xargs clang-format-18 -i --Werror
find examples -name '*.cpp' | xargs clang-format-18 -i --Werror
