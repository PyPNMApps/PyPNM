## Agent Review Bundle Summary
- Goal:
- Changes:
- Files:
- Tests:
- Notes:
# FILE: .pylintrc
[MASTER]
load-plugins=pylint.extensions.magic_value

[MESSAGES CONTROL]
disable=all
enable=magic-value-comparison

[MAGIC_VALUE]
valid-magic-values=0,1,-1,__main__
