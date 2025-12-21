/**
 * DEPRECATED: This file is superseded by src/cpp/main.cpp
 *
 * The key generation functionality has been moved to the main entry point.
 * Use the 'keygen' executable instead:
 *
 *   ./build/keygen <algorithm> <output_dir> [options]
 *
 * See src/cpp/main.cpp for the current implementation.
 */

#include <iostream>

int main() {
    std::cerr << "This example is deprecated." << std::endl;
    std::cerr << "Use ./build/keygen instead." << std::endl;
    std::cerr << "See src/cpp/main.cpp for the implementation." << std::endl;
    return 1;
}
