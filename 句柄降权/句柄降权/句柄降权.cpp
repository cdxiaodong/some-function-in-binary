#include <iostream>
#include <vector>
using namespace std;

struct ListNode {
    int val;
    ListNode* next;
    ListNode(int x) : val(x), next(NULL) {}
};

class Solution {
public:
    ListNode* swapPairs(ListNode* head) {
        if (head == nullptr || head->next == nullptr) {
            return head;
        }
        ListNode* dummy = new ListNode(0);
        dummy->next = head;
        ListNode* pre = dummy, * cur = head;
        while (cur != nullptr && cur->next != nullptr) {
            ListNode* nextGroup = cur->next->next;
            pre->next = cur->next;
            cur->next->next = cur;
            cur->next = nextGroup;
            pre = cur;
            cur = nextGroup;
        }
        return dummy->next;
    }
};

void printList(ListNode* head) {
    while (head != nullptr) {
        cout << head->val << " ";
        head = head->next;
    }
    cout << endl;
}

int main() {
    // Test Case 1
    vector<int> nums1 = { 1, 2, 3, 4, 5 };
    ListNode* head1 = new ListNode(0);
    ListNode* p1 = head1;
    for (int i = 0; i < nums1.size(); i++) {
        p1->next = new ListNode(nums1[i]);
        p1 = p1->next;
    }
    cout << "Before swap: ";
    printList(head1->next);
    Solution sol1;
    ListNode* newHead1 = sol1.swapPairs(head1->next);
    cout << "After swap: ";
    printList(newHead1);

    // Test Case 2
    vector<int> nums2 = { 1, 1, 2, 2, 3, 3, 4 };
    ListNode* head2 = new ListNode(0);
    ListNode* p2 = head2;
    for (int i = 0; i < nums2.size(); i++) {
        p2->next = new ListNode(nums2[i]);
        p2 = p2->next;
    }
    cout << "Before swap: ";
    printList(head2->next);
    Solution sol2;
    ListNode* newHead2 = sol2.swapPairs(head2->next);
    cout << "After swap: ";
    printList(newHead2);

    return 0;
}
