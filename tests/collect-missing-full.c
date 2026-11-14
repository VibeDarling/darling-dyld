// The library the fixture is LINKED against: it exports the four symbols the program imports. See collect-missing-guest.c.
int collectMissingPresent(void) { return 7; }
int collectMissingFunctionA(void) { return 1; }
int collectMissingFunctionB(void) { return 2; }
int collectMissingFunctionC(void) { return 3; }
long kCollectMissingData = 42;
