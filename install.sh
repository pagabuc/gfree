echo "[+] Downloading llvm, clang and compiler-rt..."
wget http://llvm.org/releases/3.8.0/llvm-3.8.0.src.tar.xz; tar xvf llvm-3.8.0.src.tar.xz
(cd llvm-3.8.0.src &&
    (cd tools && wget http://llvm.org/releases/3.8.0/cfe-3.8.0.src.tar.xz && tar xvf cfe-3.8.0.src.tar.xz && mv cfe-3.8.0.src clang) &&
    (cd projects && wget http://llvm.org/releases/3.8.0/compiler-rt-3.8.0.src.tar.xz && tar xvf compiler-rt-3.8.0.src.tar.xz && mv compiler-rt-3.8.0.src compiler-rt)
)


echo "[+] Installing GFree"
patch -p0 < patches/llvm.patch
cp ./X86GFree/* ./llvm-3.8.0.src/lib/Target/X86/
cp ./llvm-3.8.0.src/lib/CodeGen/AllocationOrder.h ./llvm-3.8.0.src/include/llvm/CodeGen/

echo "[~] Building..."
mkdir llvm-build;
(cd llvm-build &&
    CC=clang CXX=clang++ cmake -G "Ninja" -DCMAKE_BUILD_TYPE="RelWithDebInfo"  \
      -DLLVM_TARGETS_TO_BUILD=X86        \
      -DLLVM_OPTIMIZED_TABLEGEN=ON       \
      -DLLVM_INCLUDE_EXAMPLES=OFF        \
      -DLLVM_INCLUDE_TESTS=OFF           \
      -DLLVM_INCLUDE_DOCS=OFF            \
      -DLLVM_ENABLE_SPHINX=OFF           \
      -DLLVM_PARALLEL_LINK_JOBS=2        \
      -DLLVM_ENABLE_ASSERTIONS=ON        \
      -DCOMPILER_RT_BUILD_SANITIZERS=OFF \
      -DCMAKE_C_FLAGS:STRING="-gsplit-dwarf"  \
      -DCMAKE_CXX_FLAGS:STRING="-gsplit-dwarf" \
      ../llvm-3.8.0.src                 &&      
    ninja -j2;
)

echo -e "\n[+] Done!"
echo "$PWD/llvm-build/bin/clang -mno-red-zone -fno-optimize-sibling-calls \"\$@\"" > clang-gfree
echo "$PWD/llvm-build/bin/clang++ -mno-red-zone -fno-optimize-sibling-calls \"\$@\"" > clang++-gfree
chmod +x $PWD/clang-gfree $PWD/clang++-gfree
echo "You can now install clang-gfree and clang++-gfree with: 
      ln -s $PWD/clang-gfree /usr/bin/clang-gfree
      ln -s $PWD/clang++-gfree /usr/bin/clang++-gfree"
