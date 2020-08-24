
#include "merkle_tree.h"

namespace crypto
{

    string merkle_tree(vector<string> leafs, string (*hash)(const string &))
    {
        if (leafs.size() == 1)
        {
            return leafs[0];
        }
        vector<string> next;
        // hash every two consecutive elements, ignores last on odd length
        for (unsigned int i = 0; i < leafs.size(); i += 2)
        {
            next.push_back(hash(leafs[i] + leafs[i + 1]));
        }
        // hash twice the last element on odd length
        if (leafs.size() % 2 == 1)
        {
            next.push_back(hash(leafs.back() + leafs.back()));
        }
        return merkle_tree(next, hash);
    }
} 