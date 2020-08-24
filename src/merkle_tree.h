
#ifndef CRYPTO_MERKLE_TREE
#define CRYPTO_MERKLE_TREE

#include <vector>
#include <iostream>
using namespace std;

namespace crypto
{

    /**
     * "hash tree or Merkle tree is a tree in which every leaf node is labelled with the cryptographic 
     * hash of a data block, and every non-leaf node is labelled with the cryptographic hash of the 
     * labels of its child nodes. Hash trees allow efficient and secure verification of the contents of 
     * large data structures. Hash trees are a generalization of hash lists and hash chains." (quats wikipadia, for more see https://en.wikipedia.org/wiki/Merkle_tree)
     * on this implementation if the array size is odd in a given recursion it will be supplemented
     * with the last element in the array, also the method of conjunction of two child nodes hashs is 
     * a string concationation.
     * @param leafs array of tree leafs hashs
     * @param hash function to hash each set of leafs after conjunction
     * @returns tree root hash
     */
    string merkle_tree(vector<string> leafs, string (*hash)(const string &));
} 

#endif